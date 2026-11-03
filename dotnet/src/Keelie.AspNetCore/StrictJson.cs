using System.Text.Json;
using System.Text.Unicode;

namespace Keelie.AspNetCore;

/// <summary>
/// JSON that two parsers read the same way.
/// </summary>
/// <remarks>
/// A parser can keep the first or the last value of a key given twice. A guard that read one tool
/// name while your server read another would check the wrong scope. So a key given twice in one
/// object is refused, as the Python SDK refuses it, when that object closes. Keys compare after
/// their escapes are read: <c>"name"</c> and <c>"name"</c> are the same key.
/// </remarks>
internal static class StrictJson
{
    /// <summary>Deeper than this is refused, as Python's parser refuses it at its recursion limit.</summary>
    internal const int MaxDepth = 1000;

    internal enum Outcome
    {
        Ok,
        ParseError,
        DuplicateKey,
    }

    /// <summary>Checks <paramref name="body"/>: UTF-8, no byte order mark, one JSON value, no key given twice.</summary>
    internal static Outcome Check(ReadOnlySpan<byte> body)
    {
        // Python decodes the body as UTF-8 first, and its parser refuses a byte order mark.
        if (!Utf8.IsValid(body) || body.StartsWith("﻿"u8))
        {
            return Outcome.ParseError;
        }
        var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = MaxDepth });
        var frames = new Stack<Frame>();
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        frames.Push(new Frame());
                        break;
                    case JsonTokenType.PropertyName:
                        var frame = frames.Peek();
                        if (!frame.Keys.Add(reader.GetString()!))
                        {
                            frame.Duplicate = true;
                        }
                        break;
                    case JsonTokenType.EndObject:
                        if (frames.Pop().Duplicate)
                        {
                            return Outcome.DuplicateKey;
                        }
                        break;
                }
            }
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            return Outcome.ParseError;
        }
        return Outcome.Ok;
    }

    private sealed class Frame
    {
        internal HashSet<string> Keys { get; } = new(StringComparer.Ordinal);

        internal bool Duplicate { get; set; }
    }
}
