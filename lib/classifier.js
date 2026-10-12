// lib/classifier.js
// LLM Semantic Classifier resilience, URL normalization, fault tolerance,
// secret sanitization, context truncation, and timeout policies (#127, #129, #118, #115, #117).

import { redactCredentials, redactUrl } from "./redact.js";
import { CircuitBreaker } from "./breaker.js";
import Schema from "@deepseek-ai/schemastery";

// Additional regex patterns for sensitive tokens & API keys (#115)
const OPENAI_KEY_PATTERN = /\bsk-[a-zA-Z0-9_\-]{20,}\b/g;
const ANTHROPIC_KEY_PATTERN = /\bsk-ant-[a-zA-Z0-9_\-]{20,}\b/g;
const NPM_TOKEN_PATTERN = /\bnpm_[a-zA-Z0-9]{36}\b/g;
const BEARER_HEADER_PATTERN = /\bBearer\s+[a-zA-Z0-9_\-\.]{15,}\b/gi;
const INLINE_CREDENTIAL_PATTERN = /(?:-p|--password|--passwd|--token|--api[-_]?key)\s*(?:=|\s+)[^\s'"]+/gi;
const SENSITIVE_KEY_NAMES = /^(?:token|key|api[-_]?key|secret|password|passwd|auth|authorization|private[-_]?key|client[-_]?secret)$/i;

/**
 * Normalizes user-provided LLM endpoint URLs (#127).
 * Handles bare host/port, duplicate slashes, trailing slashes, and appends /chat/completions when missing.
 *
 * @param {string} inputUrl
 * @returns {string}
 */
export function normalizeChatCompletionsUrl(inputUrl) {
  if (typeof inputUrl !== "string" || inputUrl.trim() === "") {
    throw new TypeError("Classifier endpoint URL must be a non-empty string");
  }

  let raw = inputUrl.trim();
  if (!/^https?:\/\//i.test(raw)) {
    raw = "http://" + raw;
  }

  // Remove duplicate slashes after protocol
  raw = raw.replace(/([^:]\/)\/+/g, "$1");

  const parsed = new URL(raw);
  let pathname = parsed.pathname.replace(/\/+$/, ""); // remove trailing slashes
  pathname = pathname.replace(/\/{2,}/g, "/");

  if (pathname.endsWith("/chat/completions")) {
    // Already has standard completions endpoint
    parsed.pathname = pathname;
  } else if (pathname.endsWith("/v1")) {
    parsed.pathname = pathname + "/chat/completions";
  } else if (pathname === "" || pathname === "/") {
    parsed.pathname = "/chat/completions";
  } else {
    parsed.pathname = pathname + "/chat/completions";
  }

  // Ensure clean pathname without trailing slash
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString();
}

/**
 * Sanitizes arguments and command strings to prevent credential leaks to external LLM APIs (#115).
 * Masks tokens, passwords, private keys, auth headers, and sensitive object keys recursively.
 *
 * @param {any} input
 * @returns {any}
 */
export function sanitizeClassifierInput(input) {
  if (typeof input === "string") {
    let sanitized = redactCredentials(input);
    sanitized = redactUrl(sanitized);
    sanitized = sanitized.replace(OPENAI_KEY_PATTERN, "***");
    sanitized = sanitized.replace(ANTHROPIC_KEY_PATTERN, "***");
    sanitized = sanitized.replace(NPM_TOKEN_PATTERN, "***");
    sanitized = sanitized.replace(BEARER_HEADER_PATTERN, "Bearer ***");
    sanitized = sanitized.replace(INLINE_CREDENTIAL_PATTERN, "***");
    return sanitized;
  }

  if (Array.isArray(input)) {
    return input.map((item) => sanitizeClassifierInput(item));
  }

  if (input !== null && typeof input === "object") {
    const sanitizedObj = {};
    for (const [key, val] of Object.entries(input)) {
      if (SENSITIVE_KEY_NAMES.test(key)) {
        sanitizedObj[key] = "***";
      } else {
        sanitizedObj[key] = sanitizeClassifierInput(val);
      }
    }
    return sanitizedObj;
  }

  return input;
}

/**
 * Truncates classifier payload context to minimize token consumption (#117).
 *
 * @param {any} input - String or object payload
 * @param {number} [maxChars=1000] - Character cap
 * @returns {string} Truncated string representation with metadata marker
 */
export function truncateClassifierContext(input, maxChars = 1000) {
  const cap = typeof maxChars === "number" && maxChars > 0 ? maxChars : 1000;

  if (typeof input === "string") {
    if (input.length <= cap) {
      return input;
    }
    return `${input.slice(0, cap)}\n[...truncated, total: ${input.length} chars]`;
  }

  let jsonStr;
  try {
    jsonStr = JSON.stringify(input, null, 2);
  } catch {
    jsonStr = String(input);
  }

  if (jsonStr.length <= cap) {
    return jsonStr;
  }

  // Attempt smart field truncation if object has large fields
  if (input !== null && typeof input === "object" && !Array.isArray(input)) {
    const copy = { ...input };
    const fieldBudget = Math.max(100, Math.floor(cap / 2));
    for (const key of ["command", "content", "diff", "text", "script", "patch", "data"]) {
      if (typeof copy[key] === "string" && copy[key].length > fieldBudget) {
        copy[key] = `${copy[key].slice(0, fieldBudget)}\n[...truncated field, total: ${copy[key].length} chars]`;
      }
    }
    try {
      const reducedJson = JSON.stringify(copy, null, 2);
      if (reducedJson.length <= cap) {
        return reducedJson;
      }
    } catch {
      // fallback to hard truncation below
    }
  }

  return `${jsonStr.slice(0, cap)}\n[...truncated, total: ${jsonStr.length} chars]`;
}

/**
 * Default error inspector for retrying LLM HTTP requests (#129).
 * Retries on network faults, timeouts, 429 rate limits, and 5xx server errors.
 * Never retries on 400, 401, 403, 404, 422 client errors.
 *
 * @param {any} err
 * @returns {boolean}
 */
export function shouldRetryLlmError(err) {
  if (!err) return false;
  if (CircuitBreaker.isFaultOrTimeout(err)) return true;

  const status = err.status || (err.response && err.response.status);
  if (typeof status === "number") {
    if (status === 429) return true;
    if (status >= 500) return true;
    if (status >= 400 && status < 500) return false;
  }

  const code = err.code;
  if (code && ["ETIMEDOUT", "ECONNRESET", "ECONNREFUSED", "ENOTFOUND", "UND_ERR_CONNECT_TIMEOUT"].includes(code)) {
    return true;
  }

  if (err.name === "AbortError" || err.isTimeout) {
    return true;
  }

  return false;
}

/**
 * Executes an async LLM operation with automatic retry and exponential backoff (#129).
 *
 * @template T
 * @param {(attempt: number) => Promise<T>} fn
 * @param {{ maxRetries?: number, retryDelayMs?: number, backoffFactor?: number, retryOn?: (err: any) => boolean }} [options]
 * @returns {Promise<T>}
 */
export async function withLlmRetry(fn, options = {}) {
  const maxRetries = typeof options.maxRetries === "number" ? options.maxRetries : 2;
  const initialDelay = typeof options.retryDelayMs === "number" ? options.retryDelayMs : 200;
  const backoffFactor = typeof options.backoffFactor === "number" ? options.backoffFactor : 2;
  const checkRetry = options.retryOn || shouldRetryLlmError;

  let attempt = 0;
  let delay = initialDelay;

  while (true) {
    try {
      return await fn(attempt);
    } catch (err) {
      attempt++;
      if (attempt > maxRetries || !checkRetry(err)) {
        if (err && typeof err === "object") {
          err.attempts = attempt;
        }
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay *= backoffFactor;
    }
  }
}

/**
 * Checks if an execution represents a low-risk, read-only operation (#118).
 *
 * @param {{ name?: string, arguments?: any }} execution
 * @returns {boolean}
 */
export function isLowRiskExecution(execution) {
  if (!execution) return false;
  const toolName = execution.name || "";
  const command = execution.arguments && execution.arguments.command;

  // File viewing / inspection tools
  if (["read_file", "view_file", "list_dir", "glob", "search_files", "grep"].includes(toolName)) {
    return true;
  }

  if (typeof command === "string") {
    const trimmed = command.trim();
    if (!trimmed) return true;

    // Reject any dangerous or mutating commands
    if (/\b(?:rm|mv|cp|chmod|chown|sudo|dd|mkfs|curl|wget|nc|bash|sh|zsh|kill|pkill)\b/i.test(trimmed)) {
      return false;
    }
    // Reject shell redirections or pipes to execution
    if (/[><|;&]/.test(trimmed)) {
      return false;
    }
    // Safe commands
    if (/^(?:git\s+(?:status|log|diff|branch|show)|ls|pwd|cat|echo|head|tail|wc|whoami|uname)\b/.test(trimmed)) {
      return true;
    }
  }

  return false;
}

/**
 * Checks whether an error is caused by endpoint rejection of JSON-mode / response_format (#59).
 * Common in local LLM runtimes like Ollama, vLLM, and older endpoints.
 *
 * @param {any} err
 * @returns {boolean}
 */
export function isShapeRejectError(err) {
  if (!err) return false;
  const status = err.status || (err.response && err.response.status);
  if (status === 400 || status === 415 || status === 422) return true;
  const msg = String(err.message || "").toLowerCase();
  return (
    msg.includes("response_format") ||
    msg.includes("json_object") ||
    msg.includes("unsupported parameter") ||
    msg.includes("schema")
  );
}

/**
 * Robust JSON extraction from raw strings, handling markdown code blocks and raw JSON (#59).
 *
 * @param {string} content
 * @returns {any | null}
 */
export function extractJsonPayload(content) {
  if (!content || typeof content !== "string") return null;
  const trimmed = content.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // Check markdown code block
    const mdMatch = /```(?:json)?\s*([\s\S]*?)\s*```/i.exec(trimmed);
    if (mdMatch && mdMatch[1]) {
      try {
        return JSON.parse(mdMatch[1].trim());
      } catch {
        // continue
      }
    }
    // Check bracketed JSON
    const braceMatch = /\{[\s\S]*\}/.exec(trimmed);
    if (braceMatch) {
      try {
        return JSON.parse(braceMatch[0]);
      } catch {
        // ignore
      }
    }
  }
  return null;
}

/**
 * Strict Schemastery schema for validating structured classifier decisions (#66).
 */
export const ClassifierVerdictSchema = Schema.object({
  verdict: Schema.union(["allow", "deny", "ask"]).required(),
  reason: Schema.string().default("classifier-evaluated"),
  riskScore: Schema.number().default(0.5),
  tags: Schema.array(Schema.string()).default([]),
});

/**
 * Validates and normalizes structured classifier response (#66).
 *
 * @param {any} parsed
 * @returns {{ valid: boolean, verdict?: "allow" | "deny" | "ask", reason?: string, riskScore?: number, tags?: string[], error?: string }}
 */
export function validateClassifierResponse(parsed) {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { valid: false, error: "Response is not a valid JSON object" };
  }
  const rawVerdict = String(parsed.verdict || "").toLowerCase().trim();
  if (!["allow", "deny", "ask"].includes(rawVerdict)) {
    return { valid: false, error: `Invalid verdict '${parsed.verdict}', expected allow|deny|ask` };
  }
  const reason = typeof parsed.reason === "string" && parsed.reason.trim()
    ? parsed.reason.trim()
    : `classifier-${rawVerdict}`;
  const riskScore = typeof parsed.riskScore === "number" && !isNaN(parsed.riskScore)
    ? Math.max(0, Math.min(1, parsed.riskScore))
    : (rawVerdict === "deny" ? 1.0 : (rawVerdict === "ask" ? 0.6 : 0.1));
  const tags = Array.isArray(parsed.tags)
    ? parsed.tags.filter((t) => typeof t === "string" && t.trim()).map((t) => t.trim())
    : [];

  return {
    valid: true,
    verdict: rawVerdict,
    reason,
    riskScore,
    tags,
  };
}

/**
 * Standalone resilient LLM Classifier client (#127, #129, #118, #115, #117, #59, #66).
 */
export class LlmClassifier {
  /**
   * @param {{
   *   endpoint?: string,
   *   apiKey?: string,
   *   model?: string,
   *   timeoutMs?: number,
   *   timeoutPolicy?: "strict" | "permissive",
   *   maxRetries?: number,
   *   maxContextChars?: number,
   *   supportsJsonMode?: boolean,
   *   fetch?: typeof globalThis.fetch
   * }} [options]
   */
  constructor(options = {}) {
    this.endpoint = options.endpoint ? normalizeChatCompletionsUrl(options.endpoint) : null;
    this.apiKey = options.apiKey || "";
    this.model = options.model || "gpt-4o-mini";
    this.timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 3000;
    this.timeoutPolicy = options.timeoutPolicy === "permissive" ? "permissive" : "strict";
    this.maxRetries = typeof options.maxRetries === "number" ? options.maxRetries : 2;
    this.maxContextChars = typeof options.maxContextChars === "number" ? options.maxContextChars : 1000;
    this.supportsJsonMode = options.supportsJsonMode !== false;
    this.fetch = options.fetch || globalThis.fetch;
  }

  /**
   * Builds prompt messages with sanitized credentials and bounded context size (#115, #117, #66).
   *
   * @param {any} execution
   * @param {any} [context]
   * @returns {Array<{ role: string, content: string }>}
   */
  formatMessages(execution, context) {
    const sanitized = sanitizeClassifierInput(execution);
    const truncatedPayload = truncateClassifierContext(sanitized, this.maxContextChars);

    return [
      {
        role: "system",
        content:
          "You are a security approval gate classifier. Analyze the provided tool execution request. " +
          "Respond strictly in valid JSON format: {\"verdict\": \"allow\"|\"deny\"|\"ask\", \"reason\": \"<short explanation>\", \"riskScore\": <0.0-1.0>, \"tags\": [\"<tag>\"]}.",
      },
      {
        role: "user",
        content: `Evaluate execution:\n${truncatedPayload}`,
      },
    ];
  }

  /**
   * Classifies an execution request using the configured LLM endpoint (#118, #127, #129, #115, #117, #59, #66).
   *
   * @param {any} execution
   * @param {any} [context]
   * @returns {Promise<{ verdict: "allow" | "deny" | "ask", reason: string, riskScore?: number, tags?: string[], timeout?: boolean, error?: any }>}
   */
  async classify(execution, context = {}) {
    if (!this.endpoint || typeof this.fetch !== "function") {
      return { verdict: "ask", reason: "classifier-not-configured" };
    }

    const messages = this.formatMessages(execution, context);

    const callApi = async (useJsonMode) => {
      const payload = {
        model: this.model,
        messages,
        temperature: 0.1,
      };
      if (useJsonMode) {
        payload.response_format = { type: "json_object" };
      }
      const body = JSON.stringify(payload);

      return withLlmRetry(
        async () => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), this.timeoutMs);
          try {
            const res = await this.fetch(this.endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                ...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
              },
              body,
              signal: controller.signal,
            });

            if (!res.ok) {
              const err = new Error(`LLM endpoint HTTP ${res.status}: ${res.statusText}`);
              err.status = res.status;
              throw err;
            }

            return await res.json();
          } catch (err) {
            if (err.name === "AbortError") {
              const timeoutErr = new Error(`LLM classifier request timed out after ${this.timeoutMs}ms`);
              timeoutErr.isTimeout = true;
              throw timeoutErr;
            }
            throw err;
          } finally {
            clearTimeout(timer);
          }
        },
        {
          maxRetries: this.maxRetries,
          retryOn: shouldRetryLlmError,
        }
      );
    };

    try {
      let response;
      if (this.supportsJsonMode) {
        try {
          response = await callApi(true);
        } catch (err) {
          if (isShapeRejectError(err)) {
            this.supportsJsonMode = false;
            response = await callApi(false);
          } else {
            throw err;
          }
        }
      } else {
        response = await callApi(false);
      }

      const content = response?.choices?.[0]?.message?.content;
      if (!content) {
        return { verdict: "ask", reason: "classifier-empty-response" };
      }

      const parsed = extractJsonPayload(content);
      if (!parsed) {
        return { verdict: "ask", reason: "classifier-invalid-json" };
      }

      const validated = validateClassifierResponse(parsed);
      if (!validated.valid) {
        return {
          verdict: "ask",
          reason: "malformed-classifier-response",
          detail: validated.error,
        };
      }

      return {
        verdict: validated.verdict,
        reason: validated.reason,
        riskScore: validated.riskScore,
        tags: validated.tags,
      };
    } catch (err) {
      const isTimeout = CircuitBreaker.isFaultOrTimeout(err) || Boolean(err?.isTimeout);
      if (isTimeout && this.timeoutPolicy === "permissive") {
        const isLow = isLowRiskExecution(execution);
        if (isLow) {
          return { verdict: "allow", reason: "classifier-timeout-fallback-permissive", timeout: true };
        }
        return { verdict: "ask", reason: "classifier-timeout-fallback-strict", timeout: true };
      }

      if (isTimeout) {
        return { verdict: "ask", reason: "classifier-timeout-strict", timeout: true, error: err };
      }

      return { verdict: "ask", reason: "classifier-error", error: err };
    }
  }
}
