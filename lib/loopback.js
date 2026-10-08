// lib/loopback.js
// Safe loopback bypass helper for 127.0.0.1 and localhost dev servers.
// Resolves: #40

/**
 * Checks whether a hostname or IP string represents a local loopback interface.
 *
 * @param {string} host
 * @returns {boolean}
 */
export function isLoopbackHost(host) {
  if (typeof host !== "string" || !host.trim()) return false;
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");

  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "127.0.0.1" || h === "0.0.0.0" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;

  // 127.0.0.0/8 IPv4 loopback range
  if (/^127(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/.test(h)) return true;

  // IPv6 loopback variants (::ffff:127.x.x.x)
  if (/^::ffff:127(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/i.test(h)) return true;

  return false;
}

/**
 * Checks whether a URL points to a loopback address.
 *
 * @param {string} targetUrl
 * @returns {boolean}
 */
export function isLoopbackUrl(targetUrl) {
  if (typeof targetUrl !== "string" || !targetUrl.trim()) return false;
  try {
    const parsed = new URL(targetUrl.includes("://") ? targetUrl : `http://${targetUrl}`);
    return isLoopbackHost(parsed.hostname);
  } catch {
    return false;
  }
}

/**
 * Checks whether an HTTP/network tool execution or command targets a loopback endpoint.
 *
 * @param {string[]} argv - Tokens of curl/wget or similar command
 * @returns {{ isLoopback: boolean, host?: string, port?: string }}
 */
export function isLoopbackCommand(argv) {
  if (!Array.isArray(argv) || argv.length === 0) return { isLoopback: false };
  const cmd = argv[0].replace(/\\/g, "/").split("/").pop();

  if (cmd !== "curl" && cmd !== "wget" && cmd !== "nc" && cmd !== "socat") {
    return { isLoopback: false };
  }

  const urls = [];
  for (let i = 1; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith("-")) {
      // Skip flags and their values if common
      if ((a === "-u" || a === "-H" || a === "-d" || a === "--data" || a === "-o" || a === "-O") && i + 1 < argv.length) {
        i += 1;
      }
      continue;
    }
    if (a.includes("localhost") || a.includes("127.0.0.1") || a.includes("::1") || a.includes("0.0.0.0") || a.startsWith("http://") || a.startsWith("https://")) {
      urls.push(a);
    }
  }

  if (urls.length === 0) return { isLoopback: false };

  const allLoopback = urls.every((u) => isLoopbackUrl(u));
  if (allLoopback) {
    try {
      const parsed = new URL(urls[0].includes("://") ? urls[0] : `http://${urls[0]}`);
      return { isLoopback: true, host: parsed.hostname, port: parsed.port };
    } catch {
      return { isLoopback: true };
    }
  }

  return { isLoopback: false };
}