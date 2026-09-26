using System.Globalization;
using System.Text;

namespace Watchtower.Core.History;

/// <summary>
/// Deterministic JSON used as hash input. Hand-rolled on purpose: a serializer
/// upgrade that changes escaping rules would otherwise make every old history
/// entry fail verification. Keys are sorted ordinally, nulls are omitted, and
/// only the minimal JSON escapes are used.
/// </summary>
public static class CanonicalJson
{
    public static string Serialize(IReadOnlyDictionary<string, object?> obj)
    {
        var sb = new StringBuilder(256);
        WriteObject(sb, obj);
        return sb.ToString();
    }

    private static void WriteObject(StringBuilder sb, IReadOnlyDictionary<string, object?> obj)
    {
        sb.Append('{');
        var first = true;
        foreach (var key in obj.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var value = obj[key];
            if (value is null) continue;
            if (!first) sb.Append(',');
            first = false;
            WriteString(sb, key);
            sb.Append(':');
            WriteValue(sb, value);
        }
        sb.Append('}');
    }

    private static void WriteValue(StringBuilder sb, object value)
    {
        switch (value)
        {
            case string s:
                WriteString(sb, s);
                break;
            case long or int:
                sb.Append(Convert.ToInt64(value, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));
                break;
            case bool b:
                sb.Append(b ? "true" : "false");
                break;
            case IReadOnlyDictionary<string, string> strings:
                WriteObject(sb, strings.ToDictionary(kv => kv.Key, kv => (object?)kv.Value, StringComparer.Ordinal));
                break;
            case IReadOnlyDictionary<string, object?> nested:
                WriteObject(sb, nested);
                break;
            default:
                throw new NotSupportedException($"Canonical JSON does not support {value.GetType().Name}.");
        }
    }

    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20 || IsLoneSurrogate(s, i))
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                        if (char.IsHighSurrogate(c)) sb.Append(s[++i]);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    private static bool IsLoneSurrogate(string s, int i)
    {
        var c = s[i];
        if (char.IsHighSurrogate(c)) return i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1]);
        return char.IsLowSurrogate(c);
    }
}
