using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace Keelie;

/// <summary>
/// The rules the Python SDK gets from its standard library, so that every SDK accepts and refuses
/// the same values: whitespace, UUIDs, integers and JSON text.
/// </summary>
internal static class Compat
{
    /// <summary>Python's <c>str.isspace()</c>: .NET's whitespace and the four separators 0x1C to 0x1F.</summary>
    internal static bool IsSpace(char c) => char.IsWhiteSpace(c) || (c >= '\u001c' && c <= '\u001f');

    /// <summary>Python's <c>str.strip()</c>.</summary>
    internal static string Strip(string value)
    {
        var start = 0;
        var end = value.Length;
        while (start < end && IsSpace(value[start]))
        {
            start++;
        }
        while (end > start && IsSpace(value[end - 1]))
        {
            end--;
        }
        return value.Substring(start, end - start);
    }

    /// <summary>
    /// One scope, by the rule that splits the token's scope claim: Python's
    /// <c>value.split() == [value]</c>.
    /// </summary>
    internal static bool IsOneScope(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }
        foreach (var c in value)
        {
            if (IsSpace(c))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Python's <c>value.split()</c>: split on whitespace, with no empty parts.</summary>
    internal static IEnumerable<string> SplitSpace(string value)
    {
        var start = -1;
        for (var i = 0; i < value.Length; i++)
        {
            if (IsSpace(value[i]))
            {
                if (start >= 0)
                {
                    yield return value.Substring(start, i - start);
                    start = -1;
                }
            }
            else if (start < 0)
            {
                start = i;
            }
        }
        if (start >= 0)
        {
            yield return value.Substring(start);
        }
    }

    /// <summary>
    /// A UUID read as Python's <c>uuid.UUID(str)</c> reads it: "urn:" and "uuid:" dropped, the
    /// braces at either end stripped, every hyphen dropped, then 32 hex digits. Any case.
    /// </summary>
    internal static Guid? ParseUuid(string? value)
    {
        if (value is null)
        {
            return null;
        }
        var hex = value.Replace("urn:", string.Empty, StringComparison.Ordinal)
            .Replace("uuid:", string.Empty, StringComparison.Ordinal)
            .Trim('{', '}')
            .Replace("-", string.Empty, StringComparison.Ordinal);
        if (hex.Length != 32)
        {
            return null;
        }
        foreach (var c in hex)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return null;
            }
        }
        return Guid.ParseExact(hex, "N");
    }

    /// <summary>
    /// Python's <c>int(value)</c> on a JSON value, as the JWT library applies it to <c>exp</c>,
    /// <c>nbf</c> and <c>iat</c>. A whole number stays itself, a decimal is truncated, true is 1,
    /// false is 0, and a string must hold a whole number. Anything else fails. The result is a
    /// double: a whole number too large for it becomes an infinity, which compares as the large
    /// number would.
    /// </summary>
    internal static bool TryPythonInt(JsonElement value, out double result)
    {
        result = 0;
        switch (value.ValueKind)
        {
            case JsonValueKind.True:
                result = 1;
                return true;
            case JsonValueKind.False:
                return true;
            case JsonValueKind.Number:
                var raw = value.GetRawText();
                var number = double.Parse(raw, NumberStyles.Float, CultureInfo.InvariantCulture);
                if (IsDecimalLiteral(raw))
                {
                    // Python reads a decimal as a float. int() of an infinite float fails.
                    if (!double.IsFinite(number))
                    {
                        return false;
                    }
                    result = Math.Truncate(number);
                    return true;
                }
                result = number;
                return true;
            case JsonValueKind.String:
                return TryParsePythonIntString(value.GetString()!, out result);
            default:
                return false;
        }
    }

    /// <summary>True for a JSON number written with a point or an exponent: a float in Python.</summary>
    internal static bool IsDecimalLiteral(string raw) =>
        raw.IndexOfAny(['.', 'e', 'E']) >= 0;

    /// <summary>Python's <c>int(str)</c> in base 10: whitespace, a sign, digits with single underscores.</summary>
    private static bool TryParsePythonIntString(string text, out double result)
    {
        result = 0;
        var s = Strip(text);
        var i = 0;
        var negative = false;
        if (i < s.Length && (s[i] == '+' || s[i] == '-'))
        {
            negative = s[i] == '-';
            i++;
        }
        if (i >= s.Length)
        {
            return false;
        }
        var digits = new StringBuilder();
        var lastWasDigit = false;
        for (; i < s.Length; i++)
        {
            var c = s[i];
            if (char.IsAsciiDigit(c))
            {
                digits.Append(c);
                lastWasDigit = true;
            }
            else if (c == '_' && lastWasDigit && i + 1 < s.Length && char.IsAsciiDigit(s[i + 1]))
            {
                lastWasDigit = false;
            }
            else
            {
                return false;
            }
        }
        var big = BigInteger.Parse(digits.ToString(), CultureInfo.InvariantCulture);
        result = (double)(negative ? -big : big);
        return true;
    }

    /// <summary>
    /// A JSON string as Python's <c>json.dumps</c> writes it: every character outside ASCII, and
    /// every control character, escaped.
    /// </summary>
    internal static void WriteJsonString(StringBuilder output, string value)
    {
        output.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"':
                    output.Append("\\\"");
                    break;
                case '\\':
                    output.Append("\\\\");
                    break;
                case '\n':
                    output.Append("\\n");
                    break;
                case '\r':
                    output.Append("\\r");
                    break;
                case '\t':
                    output.Append("\\t");
                    break;
                case '\b':
                    output.Append("\\b");
                    break;
                case '\f':
                    output.Append("\\f");
                    break;
                default:
                    if (c < ' ' || c > '~')
                    {
                        output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        output.Append(c);
                    }
                    break;
            }
        }
        output.Append('"');
    }

    /// <summary>The number of characters in <paramref name="value"/>, as Python counts them: code points.</summary>
    internal static int CodePoints(string value)
    {
        var count = 0;
        for (var i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                i++;
            }
            count++;
        }
        return count;
    }
}
