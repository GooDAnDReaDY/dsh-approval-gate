// lib/redact.js
// Sensitive credential and URL masking for audit logs, approval messages, and traces.

const SENSITIVE_QUERY_PARAMS = /([?&](?:token|key|api_key|apikey|access_token|secret|password|passwd|auth|client_secret)=)[^&#\s]+/gi;
const USER_INFO_CREDENTIALS = /((?:https?|ftp|ssh|git):\/\/[^:@\/\s]+:)[^@\/\s]+(@)/gi;
const AUTH_HEADERS = /((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic|token)\s+)\S+/gi;
const SENSITIVE_ASSIGNMENTS = /((?:^|[\s,;])(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*)[^\s,;]+/gi;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g;
const TOKEN_PREFIX_PATTERNS = /\b(?:ghp_[a-zA-Z0-9]{30,}|gho_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,}|xox[baprs]-[0-9a-zA-Z-]+|AKIA[0-9A-Z]{16})\b/g;

/**
 * Redacts credentials in userinfo and sensitive query params from a URL string.
 *
 * @param {string} urlStr
 * @returns {string}
 */
export function redactUrl(urlStr) {
  if (typeof urlStr !== "string" || urlStr.trim() === "") return "";
  let redacted = urlStr.replace(USER_INFO_CREDENTIALS, "$1***$2");
  redacted = redacted.replace(SENSITIVE_QUERY_PARAMS, "$1***");
  return redacted;
}

/**
 * Sanitizes and masks sensitive credentials, tokens, passwords, and URLs in arbitrary text.
 *
 * @param {string} text - Arbitrary command, snippet, or log text
 * @returns {string} Text with sensitive tokens masked with ***
 */
export function redactCredentials(text) {
  if (typeof text !== "string") return "";
  if (text.trim() === "") return text;

  let out = text;
  // 1. Private key blocks
  out = out.replace(PRIVATE_KEY_BLOCK, "[REDACTED PRIVATE KEY]");
  // 2. URLs with user:pass@host
  out = redactUrl(out);
  // 3. Authorization headers
  out = out.replace(AUTH_HEADERS, "$1***");
  // 4. Secret variable assignments
  out = out.replace(SENSITIVE_ASSIGNMENTS, "$1***");
  // 5. Well-known token prefixes
  out = out.replace(TOKEN_PREFIX_PATTERNS, "***");

  return out;
}
