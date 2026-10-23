// ZeroByte SDK for .NET (Windows, and anywhere .NET runs ChaCha20-Poly1305):
// Relay Protocol v1, https://docs.zerobyte.cloud/protocol/

using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;

namespace ZeroByte;

/// <summary>Which side of a link wrote an envelope.</summary>
public enum Direction : byte
{
    P2C = 1,
    C2P = 2,
}

public static class DirectionExtensions
{
    public static Direction Reversed(this Direction d) => d == Direction.P2C ? Direction.C2P : Direction.P2C;

    internal static string Path(this Direction d) => d == Direction.P2C ? "p2c" : "c2p";
}

/// <summary>Envelope errors. <see cref="Code"/> is the same string in every ZeroByte SDK.</summary>
public sealed class ZeroByteException(string code) : Exception(code)
{
    public string Code { get; } = code;
}

/// <summary>Relay errors. <see cref="Last"/> is the relay's highest sequence on a 409.</summary>
public sealed class RelayException(string code, int status, ulong? last = null) : Exception($"{code} ({status})")
{
    public string Code { get; } = code;
    public int Status { get; } = status;
    public ulong? Last { get; } = last;
}

/// <summary>
/// Everything one paired link needs, derived from the 32-byte link key both
/// devices agreed when they paired, salted with 16 bytes naming the link.
/// </summary>
public sealed class Credentials
{
    // The labels keep the name of the protocol's first application. They are
    // part of the wire format: changing one is a new protocol version.
    private const string MailboxLabel = "derived-relay-mailbox-v1";
    private const string TokenLabel = "derived-relay-token-v1";
    private const string P2CLabel = "derived-relay-p2c-v1";
    private const string C2PLabel = "derived-relay-c2p-v1";

    private readonly byte[] _p2c;
    private readonly byte[] _c2p;

    public byte[] MailboxID { get; }
    public byte[] AccessToken { get; }

    public Credentials(ReadOnlySpan<byte> linkKey, ReadOnlySpan<byte> linkID)
    {
        if (linkKey.Length != 32 || linkID.Length != 16) throw new ZeroByteException("invalid_key");
        MailboxID = Derive(linkKey, linkID, MailboxLabel, 16);
        AccessToken = Derive(linkKey, linkID, TokenLabel, 32);
        _p2c = Derive(linkKey, linkID, P2CLabel, 32);
        _c2p = Derive(linkKey, linkID, C2PLabel, 32);
    }

    /// <summary>A UUID link id, in RFC 4122 byte order (not <see cref="Guid.ToByteArray()"/>'s).</summary>
    public Credentials(ReadOnlySpan<byte> linkKey, Guid linkID) : this(linkKey, linkID.ToByteArray(bigEndian: true)) { }

    private static byte[] Derive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        var output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, Encoding.UTF8.GetBytes(info));
        return output;
    }

    /// <summary>The mailbox's name in URLs: 32 lowercase hex characters.</summary>
    public string MailboxName => Convert.ToHexStringLower(MailboxID);

    /// <summary>The bearer token: base64url without padding.</summary>
    public string BearerToken =>
        Convert.ToBase64String(AccessToken).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>What the relay stores instead of the token: SHA-256, lowercase hex.</summary>
    public string TokenDigest => Convert.ToHexStringLower(SHA256.HashData(AccessToken));

    internal byte[] Key(Direction d) => d == Direction.P2C ? _p2c : _c2p;
}

/// <summary>An opened message.</summary>
public readonly record struct Opened(ulong Sequence, byte[] Plaintext);

/// <summary>
/// <c>version(1) ‖ direction(1) ‖ sequence(UInt64 BE) ‖ nonce(12) ‖ ciphertext ‖ tag(16)</c>,
/// sealed with ChaCha20-Poly1305 over AAD = header ‖ mailboxID.
/// </summary>
public static class Envelope
{
    public const byte Version = 1;
    public const int HeaderLength = 10;
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int Overhead = HeaderLength + NonceLength + TagLength;
    public const int MaxPlaintextBytes = 1_048_576;
    public const int MaxEnvelopeBytes = MaxPlaintextBytes + Overhead;

    /// <summary>
    /// False where the platform has no ChaCha20-Poly1305 (Windows before 10
    /// 20H2, some Linux builds). Every call below throws there.
    /// </summary>
    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    /// <summary>The clear header, without opening.</summary>
    public static (Direction Direction, ulong Sequence) ReadHeader(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < Overhead) throw new ZeroByteException("malformed");
        if (envelope[0] != Version) throw new ZeroByteException("unsupported_version");
        if (envelope[1] is not (1 or 2)) throw new ZeroByteException("malformed");
        return ((Direction)envelope[1], BinaryPrimitives.ReadUInt64BigEndian(envelope[2..]));
    }

    /// <summary>Seals a message. <paramref name="nonce"/> is for known-answer tests only.</summary>
    public static byte[] Seal(
        ReadOnlySpan<byte> plaintext, Direction direction, ulong sequence, Credentials credentials,
        byte[]? nonce = null)
    {
        if (plaintext.Length > MaxPlaintextBytes) throw new ZeroByteException("too_large");
        var output = new byte[Overhead + plaintext.Length];
        var span = output.AsSpan();
        span[0] = Version;
        span[1] = (byte)direction;
        BinaryPrimitives.WriteUInt64BigEndian(span[2..], sequence);
        var n = span.Slice(HeaderLength, NonceLength);
        if (nonce is null) RandomNumberGenerator.Fill(n);
        else nonce.CopyTo(n);
        using var aead = new ChaCha20Poly1305(credentials.Key(direction));
        aead.Encrypt(
            n, plaintext,
            span.Slice(HeaderLength + NonceLength, plaintext.Length),
            span[^TagLength..],
            Aad(span[..HeaderLength], credentials));
        return output;
    }

    /// <summary>
    /// Opens an envelope the other side wrote. <paramref name="after"/> is the
    /// highest sequence already accepted, or null.
    /// </summary>
    public static Opened Open(ReadOnlySpan<byte> envelope, Direction direction, ulong? after, Credentials credentials)
    {
        if (envelope.Length > MaxEnvelopeBytes) throw new ZeroByteException("too_large");
        var (written, sequence) = ReadHeader(envelope);
        if (written != direction) throw new ZeroByteException("wrong_direction");
        if (after is { } a && sequence <= a) throw new ZeroByteException("replayed");
        var body = envelope[(HeaderLength + NonceLength)..^TagLength];
        var plaintext = new byte[body.Length];
        try
        {
            using var aead = new ChaCha20Poly1305(credentials.Key(direction));
            aead.Decrypt(
                envelope.Slice(HeaderLength, NonceLength), body, envelope[^TagLength..], plaintext,
                Aad(envelope[..HeaderLength], credentials));
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new ZeroByteException("authentication_failed");
        }
        return new Opened(sequence, plaintext);
    }

    private static byte[] Aad(ReadOnlySpan<byte> header, Credentials credentials) =>
        [.. header, .. credentials.MailboxID];
}

/// <summary>A fetch body: <c>count(UInt32 BE)</c>, then <c>length(UInt32 BE) ‖ bytes</c> per envelope.</summary>
public static class Wire
{
    public const int MaximumCount = 64;

    public static byte[] Join(IReadOnlyList<byte[]> envelopes)
    {
        var output = new byte[4 + envelopes.Sum(e => 4 + e.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)envelopes.Count);
        var offset = 4;
        foreach (var e in envelopes)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), (uint)e.Length);
            e.CopyTo(output, offset + 4);
            offset += 4 + e.Length;
        }
        return output;
    }

    public static List<byte[]> Split(ReadOnlySpan<byte> body)
    {
        static RelayException Bad() => new("malformed_response", 200);
        if (body.Length < 4) throw Bad();
        var count = BinaryPrimitives.ReadUInt32BigEndian(body);
        if (count > MaximumCount) throw Bad();
        var output = new List<byte[]>((int)count);
        var offset = 4;
        for (var i = 0; i < count; i++)
        {
            if (body.Length - offset < 4) throw Bad();
            var length = BinaryPrimitives.ReadUInt32BigEndian(body[offset..]);
            offset += 4;
            if (length > Envelope.MaxEnvelopeBytes || length > body.Length - offset) throw Bad();
            output.Add(body.Slice(offset, (int)length).ToArray());
            offset += (int)length;
        }
        if (offset != body.Length) throw Bad();
        return output;
    }
}

/// <summary>One page of a fetch.</summary>
public sealed record Page(IReadOnlyList<byte[]> Envelopes, bool More);

/// <summary>What a <see cref="Link"/> needs from a relay.</summary>
public interface IRelayTransport
{
    Task ClaimAsync(CancellationToken ct = default);
    Task PutAsync(byte[] envelope, Direction direction, ulong sequence, CancellationToken ct = default);
    Task<Page> FetchAsync(Direction direction, ulong? after, CancellationToken ct = default);
    Task<ulong?> LastSequenceAsync(Direction direction, CancellationToken ct = default);
    Task PruneAsync(Direction direction, ulong through, CancellationToken ct = default);
    Task EraseAsync(CancellationToken ct = default);
}

/// <summary>The HTTPS side of the protocol.</summary>
public sealed class Relay : IRelayTransport
{
    private readonly Credentials _credentials;
    private readonly HttpClient _http;

    public Uri Mailbox { get; }

    public Relay(string appID, Credentials credentials, Uri @base, HttpClient? http = null)
    {
        ArgumentNullException.ThrowIfNull(@base);
        _credentials = credentials;
        _http = http ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });
        Mailbox = new Uri(@base, $"{appID}/mailbox/{credentials.MailboxName}");
    }

    public async Task ClaimAsync(CancellationToken ct = default)
    {
        var json = $$"""{"tokenDigest":"{{_credentials.TokenDigest}}"}""";
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        (await SendAsync(HttpMethod.Put, "", content, ct)).Dispose();
    }

    public async Task PutAsync(byte[] envelope, Direction direction, ulong sequence, CancellationToken ct = default)
    {
        using var content = new ByteArrayContent(envelope);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        (await SendAsync(HttpMethod.Put, $"/{direction.Path()}/{sequence}", content, ct)).Dispose();
    }

    public async Task<Page> FetchAsync(Direction direction, ulong? after, CancellationToken ct = default)
    {
        using var response = await SendAsync(HttpMethod.Get, $"/{direction.Path()}?after={after ?? 0}&limit=16", null, ct);
        var body = await response.Content.ReadAsByteArrayAsync(ct);
        return new Page(Wire.Split(body), Header(response, "X-Relay-More") == "1");
    }

    public async Task<ulong?> LastSequenceAsync(Direction direction, CancellationToken ct = default)
    {
        using var response = await SendAsync(HttpMethod.Head, $"/{direction.Path()}", null, ct);
        return ulong.TryParse(Header(response, "X-Relay-Last"), out var last) ? last : null;
    }

    public async Task PruneAsync(Direction direction, ulong through, CancellationToken ct = default) =>
        (await SendAsync(HttpMethod.Delete, $"/{direction.Path()}?through={through}", null, ct)).Dispose();

    public async Task EraseAsync(CancellationToken ct = default) =>
        (await SendAsync(HttpMethod.Delete, "", null, ct)).Dispose();

    /// <summary>
    /// A WebSocket that announces each sequence the other side writes. Calls
    /// <paramref name="onSequence"/> until the socket closes or <paramref name="ct"/> fires.
    /// Only writes after <paramref name="onOpen"/> are announced: fetch once after it.
    /// </summary>
    public async Task WatchAsync(
        Direction direction, Action<ulong> onSequence, Action? onOpen = null, CancellationToken ct = default)
    {
        var builder = new UriBuilder(new Uri($"{Mailbox}/{direction.Path()}/watch"));
        builder.Scheme = builder.Scheme == "http" ? "ws" : "wss";
        using var socket = new ClientWebSocket();
        socket.Options.AddSubProtocol("zerobyte.v1");
        socket.Options.SetRequestHeader("Authorization", $"Bearer {_credentials.BearerToken}");
        await socket.ConnectAsync(builder.Uri, ct);
        onOpen?.Invoke();
        var buffer = new byte[32];
        while (socket.State == WebSocketState.Open)
        {
            var result = await socket.ReceiveAsync(buffer, ct);
            if (result.MessageType == WebSocketMessageType.Close) break;
            if (result.EndOfMessage && ulong.TryParse(Encoding.ASCII.GetString(buffer, 0, result.Count), out var s))
                onSequence(s);
        }
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, HttpContent? content, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, Mailbox + path) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _credentials.BearerToken);
        var response = await _http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            var code = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "unauthorized",
                HttpStatusCode.Conflict => "sequence_conflict",
                HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.InsufficientStorage => "quota_exceeded",
                _ => "unavailable",
            };
            ulong? last = ulong.TryParse(Header(response, "X-Relay-Last"), out var l) ? l : null;
            throw new RelayException(code, (int)response.StatusCode, last);
        }
    }

    private static string? Header(HttpResponseMessage r, string name) =>
        r.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null;
}

/// <summary>
/// One side of a paired link: sends in its own direction, receives, opens and
/// prunes in the other. Operations run one at a time. Persist <see cref="LastReceived"/>.
/// </summary>
public sealed class Link(Credentials credentials, Direction sends, IRelayTransport relay, ulong? lastReceived = null)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _claimed;
    private ulong? _next;

    public Direction Sends { get; } = sends;
    public Direction Receives { get; } = sends.Reversed();
    public ulong? LastReceived { get; private set; } = lastReceived;

    private async Task EnsureClaimedAsync(CancellationToken ct)
    {
        if (_claimed) return;
        await relay.ClaimAsync(ct);
        _claimed = true;
    }

    /// <summary>Seals and stores one message; returns its sequence.</summary>
    public async Task<ulong> SendAsync(byte[] plaintext, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await EnsureClaimedAsync(ct);
            var sequence = _next ?? (await relay.LastSequenceAsync(Sends, ct) ?? 0) + 1;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var envelope = Envelope.Seal(plaintext, Sends, sequence, credentials);
                try
                {
                    await relay.PutAsync(envelope, Sends, sequence, ct);
                    _next = sequence + 1;
                    return sequence;
                }
                catch (RelayException e) when (e.Code == "sequence_conflict")
                {
                    sequence = (e.Last ?? sequence) + 1;
                }
            }
            throw new RelayException("sequence_conflict", 409, sequence - 1);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Fetches, opens and prunes everything the other side wrote since
    /// <see cref="LastReceived"/>. Envelopes that do not open are skipped and pruned.
    /// </summary>
    public async Task<List<Opened>> ReceiveAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await EnsureClaimedAsync(ct);
            var received = new List<Opened>();
            var cursor = LastReceived;
            ulong? seen = null;
            while (true)
            {
                var page = await relay.FetchAsync(Receives, cursor, ct);
                var before = cursor;
                foreach (var envelope in page.Envelopes)
                {
                    ulong sequence;
                    try { sequence = Envelope.ReadHeader(envelope).Sequence; }
                    catch (ZeroByteException) { continue; }
                    if (cursor is null || sequence > cursor) cursor = sequence;
                    if (seen is null || sequence > seen) seen = sequence;
                    try
                    {
                        var opened = Envelope.Open(envelope, Receives, LastReceived, credentials);
                        received.Add(opened);
                        LastReceived = opened.Sequence;
                    }
                    catch (ZeroByteException)
                    {
                        // Forged, replayed or damaged: it can never open later.
                    }
                }
                if (!page.More || cursor == before) break;
            }
            if (seen is { } through) await relay.PruneAsync(Receives, through, ct);
            return received;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Deletes the mailbox for both sides. Use when the devices unpair.</summary>
    public async Task EraseAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await relay.EraseAsync(ct);
            _claimed = false;
            _next = null;
        }
        finally
        {
            _gate.Release();
        }
    }
}
