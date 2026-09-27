using Watchtower.Core.Safety;

namespace Watchtower.Core.Tests;

public class SafetyTests
{
    private const string Root = @"C:\Windows";

    private static ProcessFacts Proc(string name, string? path, bool microsoft = true, bool critical = false, int pid = 1234) =>
        new() { Pid = pid, Name = name, Path = path, SignedByMicrosoft = microsoft, IsOsCritical = critical };

    [Fact]
    public void RealLsassCannotBeKilled() =>
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanKill(Proc("lsass.exe", @"C:\Windows\System32\lsass.exe"), Root).Verdict);

    [Fact]
    public void FakeLsassInDownloadsCanBeKilledAndIsCalledOut()
    {
        var d = ActionGuard.CanKill(Proc("lsass.exe", @"C:\Users\a\Downloads\lsass.exe", microsoft: false), Root);
        Assert.Equal(GuardVerdict.Confirm, d.Verdict);
        Assert.Contains("isn't the real one", d.Reason);
    }

    [Fact]
    public void UnsignedCopyInSystem32IsNotProtected() =>
        Assert.Equal(GuardVerdict.Confirm, ActionGuard.CanKill(Proc("csrss.exe", @"C:\Windows\System32\csrss.exe", microsoft: false), Root).Verdict);

    [Fact]
    public void OsCriticalFlagAlwaysWins() =>
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanKill(Proc("weird.exe", @"C:\x\weird.exe", microsoft: false, critical: true), Root).Verdict);

    [Fact]
    public void DefenderIsProtected() =>
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanKill(Proc("MsMpEng.exe", @"C:\Windows\System32\MsMpEng.exe"), Root).Verdict);

    [Fact]
    public void ExplorerNeedsConfirmationWithConsequence()
    {
        var d = ActionGuard.CanKill(Proc("explorer.exe", @"C:\Windows\explorer.exe"), Root);
        Assert.Equal(GuardVerdict.Confirm, d.Verdict);
        Assert.Contains("taskbar", d.Reason);
    }

    [Fact]
    public void KernelAndSelfAreProtected()
    {
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanKill(Proc("System", null, pid: 4), Root).Verdict);
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanKill(Proc("Watchtower.Service.exe", @"C:\Program Files\Watchtower\x.exe", microsoft: false) with { IsWatchtower = true }, Root).Verdict);
    }

    [Fact]
    public void MasqueradeDetection()
    {
        Assert.Equal(@"C:\Windows\System32", SystemProcesses.Masquerade("svchost.exe", @"C:\ProgramData\svchost.exe", Root));
        Assert.Null(SystemProcesses.Masquerade("svchost.exe", @"C:\Windows\SysWOW64\svchost.exe", Root));
        Assert.Null(SystemProcesses.Masquerade("SVCHOST.EXE", @"c:\windows\system32\SVCHOST.exe", Root));
        Assert.Null(SystemProcesses.Masquerade("notepad.exe", @"C:\anywhere\notepad.exe", Root));
        Assert.Null(SystemProcesses.Masquerade("explorer.exe", @"C:\Windows\explorer.exe", Root));
        // Kernel-style prefixes (conhost's command line starts with \??\) are the same file.
        Assert.Null(SystemProcesses.Masquerade("conhost.exe", @"\??\C:\Windows\system32\conhost.exe", Root));
        Assert.Null(SystemProcesses.Masquerade("svchost.exe", @"\\?\C:\Windows\System32\svchost.exe", Root));
    }

    private static readonly NetworkFacts Net = new()
    {
        LocalAddresses = ["192.168.1.20"],
        Gateways = ["192.168.1.1"],
        DnsServers = ["1.1.1.1"],
    };

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.251")]
    [InlineData("192.168.1.20")]
    [InlineData("192.168.1.1")]
    [InlineData("1.1.1.1")]
    [InlineData("not-an-ip")]
    public void CannotBlockAddressesThatWouldBreakNetworking(string addr) =>
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanBlock(addr, Net).Verdict);

    [Fact]
    public void LanAddressBlockWarnsAboutLocalDevice() =>
        Assert.Contains("local network", ActionGuard.CanBlock("192.168.1.50", Net).Reason);

    [Fact]
    public void PublicAddressCanBeBlocked() =>
        Assert.Equal(GuardVerdict.Confirm, ActionGuard.CanBlock("203.0.113.7", Net).Verdict);

    [Fact]
    public void StartupGuard()
    {
        Assert.Equal(GuardVerdict.Deny, ActionGuard.CanRemoveStartup(new StartupFacts { Name = "SecurityHealth", Command = @"%windir%\system32\SecurityHealthSystray.exe" }).Verdict);
        Assert.Equal(GuardVerdict.Confirm, ActionGuard.CanRemoveStartup(new StartupFacts { Name = "Updater", Command = @"C:\Users\a\AppData\x.exe" }).Verdict);
    }
}
