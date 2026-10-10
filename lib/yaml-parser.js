// lib/yaml-parser.js
// Compact zero-dependency YAML subset parser for dsh-approval-gate (#38).
// Supports scalar values, lists, mappings, nested blocks, and comments.

/**
 * Parses scalar string into JS primitive (string, number, boolean, null).
 *
 * @param {string} val
 * @returns {any}
 */
export function parseScalar(val) {
  if (val === undefined || val === null) return null;
  const trimmed = val.trim();
  if (trimmed === "" || trimmed === "~" || trimmed === "null") return null;
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;

  // Single or double quoted strings
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    const quote = trimmed[0];
    const inner = trimmed.slice(1, -1);
    if (quote === '"') {
      return inner
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, "\\")
        .replace(/\\n/g, "\n")
        .replace(/\\t/g, "\t");
    }
    return inner.replace(/''/g, "'");
  }

  // Numbers
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return Number(trimmed);
  }

  return trimmed;
}

/**
 * Strips comments from a line, preserving comments inside quotes.
 *
 * @param {string} line
 * @returns {string}
 */
export function stripComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === "#" && !inSingle && !inDouble) {
      return line.slice(0, i);
    }
  }
  return line;
}

/**
 * Parses a simple YAML string into JavaScript objects and arrays.
 *
 * @param {string} yamlText
 * @returns {any}
 */
export function parseYaml(yamlText) {
  if (typeof yamlText !== "string" || !yamlText.trim()) return {};

  const trimmedText = yamlText.trim();
  // Fast path for JSON-compatible YAML
  if (trimmedText.startsWith("{") || trimmedText.startsWith("[")) {
    try {
      return JSON.parse(trimmedText);
    } catch {
      // Fallback to YAML line parser
    }
  }

  const rawLines = yamlText.split(/\r?\n/);
  const lines = [];

  for (let i = 0; i < rawLines.length; i += 1) {
    const clean = stripComment(rawLines[i]);
    if (!clean.trim()) continue; // skip blank / comment-only lines
    const indent = clean.match(/^(\s*)/)[0].length;
    lines.push({ indent, text: clean.trim(), lineNum: i + 1 });
  }

  if (lines.length === 0) return {};

  let index = 0;

  function parseBlock(currentIndent) {
    if (index >= lines.length) return null;

    const firstLine = lines[index];
    if (firstLine.text.startsWith("- ") || firstLine.text === "-") {
      // It's a sequence (array)
      const list = [];
      while (index < lines.length) {
        const line = lines[index];
        if (line.indent < currentIndent) break;
        if (line.indent > currentIndent) {
          // Handled within child elements
          break;
        }

        if (line.text.startsWith("- ") || line.text === "-") {
          const itemPayload = line.text.slice(2).trim();
          index += 1;

          if (!itemPayload) {
            // Nested block under list item
            if (index < lines.length && lines[index].indent > line.indent) {
              list.push(parseBlock(lines[index].indent));
            } else {
              list.push(null);
            }
          } else if (itemPayload.includes(":") && !itemPayload.startsWith("{")) {
            // Key-value on the same line as list dash: e.g. "- id: my-rule"
            const colonIdx = itemPayload.indexOf(":");
            const k = itemPayload.slice(0, colonIdx).trim();
            const v = itemPayload.slice(colonIdx + 1).trim();
            const obj = {};
            if (v) {
              obj[k] = parseScalar(v);
            } else {
              // Nested under this key
              if (index < lines.length && lines[index].indent > line.indent) {
                obj[k] = parseBlock(lines[index].indent);
              } else {
                obj[k] = null;
              }
            }

            // Read subsequent keys belonging to this list item
            const itemIndent = line.indent + 2;
            while (index < lines.length) {
              const nextLine = lines[index];
              if (nextLine.indent < itemIndent) break;
              if (nextLine.text.startsWith("- ") && nextLine.indent <= line.indent) break;

              if (nextLine.text.includes(":")) {
                const cIdx = nextLine.text.indexOf(":");
                const subK = nextLine.text.slice(0, cIdx).trim();
                const subV = nextLine.text.slice(cIdx + 1).trim();
                index += 1;
                if (subV) {
                  obj[subK] = parseScalar(subV);
                } else {
                  if (index < lines.length && lines[index].indent > nextLine.indent) {
                    obj[subK] = parseBlock(lines[index].indent);
                  } else {
                    obj[subK] = null;
                  }
                }
              } else {
                index += 1;
              }
            }
            list.push(obj);
          } else {
            // Scalar list item: e.g. "- item1"
            list.push(parseScalar(itemPayload));
          }
        } else {
          break;
        }
      }
      return list;
    } else {
      // It's a mapping (object)
      const obj = {};
      while (index < lines.length) {
        const line = lines[index];
        if (line.indent < currentIndent) break;
        if (line.indent > currentIndent) {
          break;
        }

        if (line.text.includes(":")) {
          const colonIdx = line.text.indexOf(":");
          const key = line.text.slice(0, colonIdx).trim();
          const rest = line.text.slice(colonIdx + 1).trim();
          index += 1;

          if (rest) {
            obj[key] = parseScalar(rest);
          } else {
            // Value is a nested block
            if (index < lines.length && lines[index].indent > line.indent) {
              obj[key] = parseBlock(lines[index].indent);
            } else {
              obj[key] = null;
            }
          }
        } else {
          index += 1;
        }
      }
      return obj;
    }
  }

  const result = parseBlock(lines[0].indent);
  return result || {};
}
