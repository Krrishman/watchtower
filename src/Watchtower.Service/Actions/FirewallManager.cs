using System.Runtime.InteropServices;

namespace Watchtower.Service.Actions;

/// <summary>Windows Firewall rules via its COM API (HNetCfg), grouped so Watchtower only ever touches its own rules.</summary>
public static class FirewallManager
{
    public const string Group = "Watchtower";
    private const string Prefix = "Watchtower Block ";
    private const int Inbound = 1;
    private const int Outbound = 2;
    private const int ActionBlock = 0;
    private const int AllProfiles = 0x7FFFFFFF;

    public static void Block(string address)
    {
        dynamic policy = Policy();
        try
        {
            foreach (var (direction, suffix) in new[] { (Outbound, ""), (Inbound, " (in)") })
            {
                dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
                rule.Name = Prefix + address + suffix;
                rule.Description = "Added by Watchtower. Remove it from Watchtower's Network tab.";
                rule.Grouping = Group;
                rule.Direction = direction;
                rule.Action = ActionBlock;
                rule.RemoteAddresses = address;
                rule.Profiles = AllProfiles;
                rule.Enabled = true;
                policy.Rules.Add(rule);
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }
    }

    public static void Unblock(string address)
    {
        dynamic policy = Policy();
        try
        {
            foreach (var name in OurRules((object)policy).Where(n => n == Prefix + address || n == Prefix + address + " (in)"))
            {
                policy.Rules.Remove(name);
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }
    }

    public static IReadOnlyList<string> Blocked()
    {
        dynamic policy = Policy();
        try
        {
            return OurRules((object)policy)
                .Select(n => n[Prefix.Length..].Replace(" (in)", ""))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }
    }

    private static List<string> OurRules(object policyObject)
    {
        dynamic policy = policyObject;
        var names = new List<string>();
        foreach (dynamic rule in policy.Rules)
        {
            string? grouping = rule.Grouping;
            string name = rule.Name;
            if (grouping == Group && name.StartsWith(Prefix, StringComparison.Ordinal)) names.Add(name);
        }
        return names;
    }

    private static dynamic Policy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
}
