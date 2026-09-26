using Watchtower.Core.Alerts;
using Watchtower.Core.History;
using Watchtower.Core.Trust;

namespace Watchtower.Core.Tests;

public class AlertTests
{
    private static readonly HashSet<string> KnownKeys = typeof(SubjectKeys)
        .GetFields()
        .Select(f => (string)f.GetValue(null)!)
        .ToHashSet();

    [Fact]
    public void EveryKindHasCompletePlainEnglishText()
    {
        foreach (var (kind, entry) in AlertCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.Title), kind);
            Assert.False(string.IsNullOrWhiteSpace(entry.Detail), kind);
            Assert.False(string.IsNullOrWhiteSpace(entry.Explanation), kind);
            Assert.False(string.IsNullOrWhiteSpace(entry.Advice), kind);
            Assert.Contains(entry.Severity, new[] { Severity.Info, Severity.Warn, Severity.Critical });

            foreach (var text in new[] { entry.Title, entry.Detail, entry.Explanation, entry.Advice })
            {
                foreach (System.Text.RegularExpressions.Match m in AlertCatalog.Placeholder().Matches(text))
                {
                    Assert.True(KnownKeys.Contains(m.Groups[1].Value), $"{kind} uses unknown placeholder {m.Value}");
                }
            }
        }
    }

    [Fact]
    public void EveryKindConstantIsInCatalog()
    {
        foreach (var field in typeof(AlertKinds).GetFields())
        {
            Assert.True(AlertCatalog.IsKnown((string)field.GetValue(null)!), field.Name);
        }
    }

    [Fact]
    public void RenderFillsMissingValuesWithReadableText()
    {
        var text = AlertCatalog.Render("{processName} from {clientAddress}", new Dictionary<string, string>());
        Assert.Equal("An unknown program from an unknown computer", text);
    }

    [Fact]
    public void PipelineLogsRendersAndRaises()
    {
        using var dir = new TempDir();
        var pipeline = NewPipeline(dir, out var trust, out var history);
        Alert? raised = null;
        pipeline.Published += a => raised = a;

        var alert = pipeline.Publish(AlertDraft.Of(AlertKinds.RemoteToolStarted,
            (SubjectKeys.ProcessName, "anydesk.exe"), (SubjectKeys.ProcessPath, @"C:\Users\a\Downloads\anydesk.exe")))!;

        Assert.Same(alert, raised);
        Assert.Equal("Remote-control program started: anydesk.exe", alert.Title);
        Assert.Contains("scammers", alert.Explanation);
        Assert.Contains(AlertActions.Kill, alert.Actions);
        Assert.Contains(alert.TrustOptions, o => o.Type == TrustTypes.Program);
        Assert.Single(history.Read(new HistoryQuery()));
    }

    [Fact]
    public void TrustedAlertsAreLoggedButMarkedSuppressed()
    {
        using var dir = new TempDir();
        var pipeline = NewPipeline(dir, out var trust, out var history);
        trust.Add(new TrustRule { Type = TrustTypes.Program, Value = @"C:\Tools\anydesk.exe" });

        var alert = pipeline.Publish(AlertDraft.Of(AlertKinds.RemoteToolStarted,
            (SubjectKeys.ProcessName, "anydesk.exe"), (SubjectKeys.ProcessPath, @"c:\tools\ANYDESK.exe")))!;

        Assert.StartsWith("trust:", alert.SuppressedBy);
        Assert.Empty(alert.TrustOptions);
        Assert.Single(history.Read(new HistoryQuery()));
    }

    [Fact]
    public void LearningDropsRoutineAlertsButNotSeriousOnes()
    {
        using var dir = new TempDir();
        var pipeline = NewPipeline(dir, out _, out var history, learning: true);

        Assert.Null(pipeline.Publish(AlertDraft.Of(AlertKinds.FirstConnection, (SubjectKeys.ProcessName, "x"))));
        Assert.NotNull(pipeline.Publish(AlertDraft.Of(AlertKinds.ProgramNewListener, (SubjectKeys.ProcessName, "x"))));
        Assert.Single(history.Read(new HistoryQuery()));
    }

    [Fact]
    public void PublisherTrustRequiresValidSignature()
    {
        using var dir = new TempDir();
        var trust = new TrustStore(dir.File("trust.json"));
        trust.Add(new TrustRule { Type = TrustTypes.Publisher, Value = "Contoso Ltd" });

        var forged = new Dictionary<string, string> { [SubjectKeys.Signer] = "Contoso Ltd", [SubjectKeys.SignatureStatus] = "HashMismatch" };
        var genuine = new Dictionary<string, string> { [SubjectKeys.Signer] = "contoso ltd", [SubjectKeys.SignatureStatus] = "Valid" };

        Assert.Null(trust.Match(AlertKinds.ProgramFirstSeen, forged));
        Assert.NotNull(trust.Match(AlertKinds.ProgramFirstSeen, genuine));
    }

    [Fact]
    public void TrustOnlyAppliesToKindsThatAllowIt()
    {
        using var dir = new TempDir();
        var trust = new TrustStore(dir.File("trust.json"));
        trust.Add(new TrustRule { Type = TrustTypes.Address, Value = "203.0.113.5" });
        var subject = new Dictionary<string, string> { [SubjectKeys.ClientAddress] = "203.0.113.5", [SubjectKeys.RemoteAddress] = "203.0.113.5" };

        Assert.NotNull(trust.Match(AlertKinds.RemoteLogonFailed, subject));
        Assert.Null(trust.Match(AlertKinds.PasswordGuessing, subject));
    }

    [Fact]
    public void TamperAlertsCannotBeMuted()
    {
        using var dir = new TempDir();
        var trust = new TrustStore(dir.File("trust.json"));
        Assert.Throws<ArgumentException>(() => trust.Add(new TrustRule { Type = TrustTypes.Kind, Value = AlertKinds.HistoryTampered }));
        Assert.DoesNotContain(TrustStore.OptionsFor(AlertKinds.MonitoringKilled, new Dictionary<string, string>()), o => o.Type == TrustTypes.Kind);
    }

    [Theory]
    [InlineData("alice", @"DESKTOP\alice", true)]
    [InlineData("alice", "alice@contoso.com", true)]
    [InlineData(@"DESKTOP\alice", @"OTHER\alice", false)]
    [InlineData("alice", "alicia", false)]
    public void AccountMatching(string rule, string account, bool expected) =>
        Assert.Equal(expected, TrustStore.AccountMatches(rule, account));

    [Fact]
    public void TrustRulesPersist()
    {
        using var dir = new TempDir();
        var rule = new TrustStore(dir.File("trust.json")).Add(new TrustRule { Type = TrustTypes.Account, Value = "bob" });
        var reloaded = new TrustStore(dir.File("trust.json"));
        Assert.True(reloaded.IsAccountTrusted(@"PC\bob"));
        Assert.NotNull(reloaded.Remove(rule.Id));
        Assert.False(new TrustStore(dir.File("trust.json")).IsAccountTrusted("bob"));
    }

    private static AlertPipeline NewPipeline(TempDir dir, out TrustStore trust, out HistoryLog history, bool learning = false)
    {
        trust = new TrustStore(dir.File("trust.json"));
        history = new HistoryLog(dir.File("history"));
        return new AlertPipeline(history, trust, () => DateTimeOffset.Parse("2026-05-01T12:00:00Z"), _ => learning);
    }
}
