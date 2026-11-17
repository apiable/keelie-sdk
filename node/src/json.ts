/**
 * JSON that two parsers read the same way.
 *
 * `JSON.parse` keeps the last value of a key given twice, and another parser may
 * keep the first. A guard that read one tool name while your server read another
 * would check the wrong scope. So a key given twice in one object is refused, as
 * the Python SDK refuses it. Keys compare after their escapes are read: `"a"`
 * and `"a"` are the same key.
 *
 * @internal
 */

/** Deeper than this is refused, as Python's parser refuses it at its recursion limit. */
export const MAX_DEPTH = 1000;

export class DuplicateKey extends Error {
  override name = "DuplicateKey";
}

export class TooDeep extends Error {
  override name = "TooDeep";
}

/** The value of `text`. Throws `SyntaxError`, {@link DuplicateKey} or {@link TooDeep}. */
export function parseStrictJson(text: string): unknown {
  const value: unknown = JSON.parse(text);
  // `text` is valid JSON from here, so the scan only has to track the objects.
  type Frame = { keys: Set<string> | null; expectKey: boolean };
  const stack: Frame[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack.at(-1);
      if (top?.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) throw new DuplicateKey();
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (c === "{" || c === "[") {
      stack.push({ keys: c === "{" ? new Set() : null, expectKey: c === "{" });
      if (stack.length > MAX_DEPTH) throw new TooDeep();
    } else if (c === "}" || c === "]") {
      stack.pop();
    } else if (c === ",") {
      const top = stack.at(-1);
      if (top?.keys) top.expectKey = true;
    }
  }
  return value;
}
