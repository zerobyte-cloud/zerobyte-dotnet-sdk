// Known answers from the independent reference (zerobyte-protocol, spec/vectors.py),
// copied as relay-v1.json. Never regenerate them from this library.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace ZeroByte.Tests;

public class VectorTests
{
    private static readonly JsonElement V =
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "relay-v1.json"))).RootElement;

    private static byte[] Hex(string s) => Convert.FromHexString(s);
    private static string Hex(byte[] b) => Convert.ToHexStringLower(b);

    private static Credentials Creds(int i)
    {
        var c = V.GetProperty("credentials")[i];
        return new Credentials(Hex(c.GetProperty("linkKey").GetString()!), Hex(c.GetProperty("linkId").GetString()!));
    }

    private static Direction Dir(JsonElement o) => (Direction)o.GetProperty("direction").GetInt32();

    // ChaCha20-Poly1305 needs OS support (Windows 10 20H2+, Linux with OpenSSL;
    // not macOS). Envelope tests skip where the platform lacks it.
    private static void RequireAead() =>
        Assert.SkipUnless(Envelope.IsSupported, "ChaCha20-Poly1305 is not supported on this OS");

    [Fact]
    public void CredentialsMatchEveryVectorSet()
    {
        var i = 0;
        foreach (var set in V.GetProperty("credentials").EnumerateArray())
        {
            var c = Creds(i++);
            Assert.Equal(set.GetProperty("mailbox").GetString(), c.MailboxName);
            Assert.Equal(set.GetProperty("bearer").GetString(), c.BearerToken);
            Assert.Equal(set.GetProperty("tokenDigest").GetString(), c.TokenDigest);
        }
        var first = V.GetProperty("credentials")[0];
        var fromGuid = new Credentials(
            Hex(first.GetProperty("linkKey").GetString()!), Guid.Parse("6F1C2A3B-4D5E-4F60-8172-93A4B5C6D7E8"));
        Assert.Equal(first.GetProperty("mailbox").GetString(), fromGuid.MailboxName);
    }

    [Fact]
    public void SealingWithTheVectorNonceGivesTheVectorEnvelope()
    {
        RequireAead();
        foreach (var e in V.GetProperty("envelopes").EnumerateArray())
        {
            var c = Creds(e.GetProperty("credentials").GetInt32());
            var sequence = ulong.Parse(e.GetProperty("sequence").GetString()!);
            var sealedBytes = Envelope.Seal(
                Hex(e.GetProperty("plaintext").GetString()!), Dir(e), sequence, c, Hex(e.GetProperty("nonce").GetString()!));
            Assert.Equal(e.GetProperty("envelope").GetString(), Hex(sealedBytes));
            var opened = Envelope.Open(Hex(e.GetProperty("envelope").GetString()!), Dir(e), null, c);
            Assert.Equal(sequence, opened.Sequence);
            Assert.Equal(e.GetProperty("plaintext").GetString(), Hex(opened.Plaintext));
        }
    }

    [Fact]
    public void EveryRejectionVectorIsRefusedWithItsError()
    {
        RequireAead();
        foreach (var r in V.GetProperty("rejections").EnumerateArray())
        {
            ulong? after = r.GetProperty("after").ValueKind == JsonValueKind.Null
                ? null : ulong.Parse(r.GetProperty("after").GetString()!);
            var error = Assert.Throws<ZeroByteException>(() =>
                Envelope.Open(Hex(r.GetProperty("envelope").GetString()!), Dir(r), after, Creds(r.GetProperty("credentials").GetInt32())));
            Assert.Equal(r.GetProperty("error").GetString(), error.Code);
        }
    }

    [Fact]
    public void FetchBodiesJoinAndSplitAsTheVectorsSay()
    {
        foreach (var w in V.GetProperty("wire").EnumerateArray())
        {
            var envelopes = w.GetProperty("envelopes").EnumerateArray().Select(x => Hex(x.GetString()!)).ToList();
            Assert.Equal(w.GetProperty("body").GetString(), Hex(Wire.Join(envelopes)));
            Assert.Equal(envelopes, Wire.Split(Hex(w.GetProperty("body").GetString()!)));
        }
        foreach (var w in V.GetProperty("wireRejections").EnumerateArray())
            Assert.Throws<RelayException>(() => Wire.Split(Hex(w.GetProperty("body").GetString()!)));
    }

    [Fact]
    public void WrongKeySizesAndOversizedPlaintextAreRefused()
    {
        Assert.Equal("invalid_key", Assert.Throws<ZeroByteException>(() => new Credentials(new byte[31], new byte[16])).Code);
        Assert.Equal("too_large", Assert.Throws<ZeroByteException>(() =>
            Envelope.Seal(new byte[Envelope.MaxPlaintextBytes + 1], Direction.P2C, 1, Creds(0))).Code);
    }

    /// <summary>A relay in memory with the server's rules: the last sequence survives a prune.</summary>
    private sealed class MemoryRelay : IRelayTransport
    {
        public readonly Dictionary<Direction, SortedDictionary<ulong, byte[]>> Boxes = new()
        {
            [Direction.P2C] = [], [Direction.C2P] = [],
        };
        public readonly Dictionary<Direction, ulong> Last = [];
        public readonly List<ulong> Prunes = [];

        public Task ClaimAsync(CancellationToken ct = default) => Task.CompletedTask;

        public Task PutAsync(byte[] envelope, Direction d, ulong sequence, CancellationToken ct = default)
        {
            if (Last.TryGetValue(d, out var last) && sequence <= last) throw new RelayException("sequence_conflict", 409, last);
            Boxes[d][sequence] = envelope;
            Last[d] = sequence;
            return Task.CompletedTask;
        }

        public Task<Page> FetchAsync(Direction d, ulong? after, CancellationToken ct = default)
        {
            var waiting = Boxes[d].Where(kv => kv.Key > (after ?? 0)).Select(kv => kv.Value).ToList();
            return Task.FromResult(new Page(waiting.Take(16).ToList(), waiting.Count > 16));
        }

        public Task<ulong?> LastSequenceAsync(Direction d, CancellationToken ct = default) =>
            Task.FromResult(Last.TryGetValue(d, out var l) ? l : (ulong?)null);

        public Task PruneAsync(Direction d, ulong through, CancellationToken ct = default)
        {
            Prunes.Add(through);
            foreach (var k in Boxes[d].Keys.Where(k => k <= through).ToList()) Boxes[d].Remove(k);
            return Task.CompletedTask;
        }

        public Task EraseAsync(CancellationToken ct = default)
        {
            foreach (var b in Boxes.Values) b.Clear();
            Last.Clear();
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task ALinkDeliversInOrderOncePrunesAndDropsForgeries()
    {
        RequireAead();
        var c = Creds(1);
        var relay = new MemoryRelay();
        var phone = new Link(c, Direction.P2C, relay);
        var laptop = new Link(c, Direction.C2P, relay);
        await Task.WhenAll(Enumerable.Range(1, 20).Select(i => phone.SendAsync(Encoding.UTF8.GetBytes($"m{i}"))));
        relay.Boxes[Direction.P2C][21] = Envelope.Seal([1], Direction.P2C, 21, Creds(0));
        relay.Last[Direction.P2C] = 21;

        var got = await laptop.ReceiveAsync();
        Assert.Equal(Enumerable.Range(1, 20).Select(i => (ulong)i), got.Select(m => m.Sequence));
        Assert.Equal(20, got.Select(m => Encoding.UTF8.GetString(m.Plaintext)).Distinct().Count());
        Assert.Equal(20UL, laptop.LastReceived);
        Assert.Equal([21UL], relay.Prunes);
        Assert.Empty(await laptop.ReceiveAsync());
        Assert.Equal([21UL], relay.Prunes);

        Assert.Equal(22UL, await new Link(c, Direction.P2C, relay).SendAsync([9]));
    }

    [Fact]
    public void TheEndpointIsBuiltFromTheBaseUrl()
    {
        var c = Creds(0);
        var relay = new Relay(
            "01a1601b-fa85-7d58-b2a2-1416e0a6b054", c, new Uri("https://relay.example.com/v1/"));
        Assert.Equal(
            $"https://relay.example.com/v1/01a1601b-fa85-7d58-b2a2-1416e0a6b054/mailbox/{c.MailboxName}",
            relay.Mailbox.ToString());
    }

    /// <summary>Against a running relay: RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=&lt;id&gt; dotnet test</summary>
    [Fact]
    public async Task EndToEndAgainstARealRelay()
    {
        var @base = Environment.GetEnvironmentVariable("RELAY_BASE");
        var app = Environment.GetEnvironmentVariable("RELAY_APP");
        Assert.SkipWhen(string.IsNullOrEmpty(@base) || string.IsNullOrEmpty(app), "RELAY_BASE and RELAY_APP not set");
        RequireAead();
        var c = new Credentials(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(16));
        var phone = new Link(c, Direction.P2C, new Relay(app!, c, new Uri(@base!)));
        var laptop = new Link(c, Direction.C2P, new Relay(app!, c, new Uri(@base!)));

        // The relay accepts a watcher only on a claimed mailbox; sending claims it.
        Assert.Equal(1UL, await phone.SendAsync(Encoding.UTF8.GetBytes("hello")));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var heard = new TaskCompletionSource<ulong>();
        var open = new TaskCompletionSource();
        var watch = new Relay(app!, c, new Uri(@base!))
            .WatchAsync(Direction.P2C, s => heard.TrySetResult(s), () => open.TrySetResult(), cts.Token);
        await Task.WhenAny(open.Task, watch).WaitAsync(cts.Token);
        Assert.True(open.Task.IsCompleted, watch.Exception?.ToString());
        await phone.SendAsync(Encoding.UTF8.GetBytes("again"));
        Assert.Equal(2UL, await heard.Task.WaitAsync(cts.Token));
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => watch);

        Assert.Equal(["hello", "again"], (await laptop.ReceiveAsync()).Select(m => Encoding.UTF8.GetString(m.Plaintext)));
        await laptop.SendAsync(Encoding.UTF8.GetBytes("ack"));
        Assert.Equal(["ack"], (await phone.ReceiveAsync()).Select(m => Encoding.UTF8.GetString(m.Plaintext)));
        await phone.EraseAsync();
    }
}
