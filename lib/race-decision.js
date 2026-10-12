// lib/race-decision.js
// Asynchronous Race Decision & Pre-emption Claim (#50, #51).
// Races human decision against host timeout and enables fast LLM pre-emption claim.

export const DEFAULT_HUMAN_TIMEOUT_MS = 60000;

export const RACE_WINNERS = Object.freeze({
  HUMAN: "human",
  TIMEOUT: "timeout",
  CLAIM: "claim",
});

/**
 * Handle coordinating human decision, host timeout, and pre-emption claims (#50, #51).
 */
export class RaceHumanHandle {
  /**
   * @param {{
   *   timeoutMs?: number,
   *   timeoutAction?: "allow" | "deny" | "ask",
   *   lockedAsk?: boolean,
   *   onClaim?: (verdict: string, reason: string) => void,
   *   onTimeout?: () => void,
   * }} [options]
   */
  constructor(options = {}) {
    this.timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : DEFAULT_HUMAN_TIMEOUT_MS;
    this.timeoutAction = options.timeoutAction || "deny";
    this.lockedAsk = Boolean(options.lockedAsk);
    this.onClaim = options.onClaim || null;
    this.onTimeout = options.onTimeout || null;

    this.settled = false;
    this.winner = null;
    this.startTime = Date.now();
    this.timer = null;

    this._resolve = null;
    this._reject = null;

    this.promise = new Promise((resolve, reject) => {
      this._resolve = resolve;
      this._reject = reject;
    });

    if (this.timeoutMs > 0 && this.timeoutMs < Infinity) {
      this.timer = setTimeout(() => {
        this._handleTimeout();
      }, this.timeoutMs);
    }
  }

  isSettled() {
    return this.settled;
  }

  /**
   * Pre-empts open human confirmation dialog when fast LLM or reviewer arrives at confident verdict (#51).
   *
   * @param {"allow" | "deny" | "ask"} outcome
   * @param {string} [reason="pre-emption-claim"]
   * @returns {{ claimed: boolean, reason?: string, winner?: string }}
   */
  claim(outcome, reason = "pre-emption-claim") {
    if (this.settled) {
      return { claimed: false, reason: "already-settled", winner: this.winner };
    }

    // Critical lockedAsk operations cannot be auto-claimed as allow
    if (this.lockedAsk && outcome === "allow") {
      return { claimed: false, reason: "locked-ask-cannot-be-claimed-as-allow" };
    }

    this._settle(RACE_WINNERS.CLAIM, {
      winner: RACE_WINNERS.CLAIM,
      verdict: outcome,
      reason,
      elapsedMs: Date.now() - this.startTime,
    });

    if (typeof this.onClaim === "function") {
      this.onClaim(outcome, reason);
    }

    return { claimed: true, verdict: outcome, reason };
  }

  /**
   * Resolves decision from human approval input.
   * @param {Record<string, any> | string} decision
   */
  resolveHuman(decision) {
    if (this.settled) return false;
    const verdict = typeof decision === "string" ? decision : (decision?.verdict || "allow");
    this._settle(RACE_WINNERS.HUMAN, {
      winner: RACE_WINNERS.HUMAN,
      verdict,
      decision: typeof decision === "object" ? decision : { verdict },
      elapsedMs: Date.now() - this.startTime,
    });
    return true;
  }

  /**
   * Aborts the race decision handle.
   * @param {string} [reason="aborted"]
   */
  abort(reason = "aborted") {
    if (this.settled) return false;
    this._settle(RACE_WINNERS.TIMEOUT, {
      winner: RACE_WINNERS.TIMEOUT,
      verdict: "deny",
      reason,
      elapsedMs: Date.now() - this.startTime,
    });
    return true;
  }

  /**
   * @private
   */
  _handleTimeout() {
    if (this.settled) return;

    // Locked ask operations must fail closed on timeout
    const resolvedVerdict = this.lockedAsk ? "deny" : this.timeoutAction;

    if (typeof this.onTimeout === "function") {
      this.onTimeout();
    }

    this._settle(RACE_WINNERS.TIMEOUT, {
      winner: RACE_WINNERS.TIMEOUT,
      verdict: resolvedVerdict,
      reason: "host-timeout-expired",
      elapsedMs: Date.now() - this.startTime,
    });
  }

  /**
   * @private
   */
  _settle(winner, result) {
    if (this.settled) return;
    this.settled = true;
    this.winner = winner;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this._resolve) {
      this._resolve(result);
    }
  }
}

/**
 * Races human decision against host timeout and optional fast claims (#50, #51).
 *
 * @param {Promise<any>} humanPromise
 * @param {ConstructorParameters<typeof RaceHumanHandle>[0]} [options]
 * @returns {Promise<{
 *   winner: "human" | "timeout" | "claim",
 *   verdict: string,
 *   elapsedMs: number,
 *   reason?: string,
 *   decision?: any
 * }>}
 */
export async function raceHumanDecision(humanPromise, options = {}) {
  const handle = new RaceHumanHandle(options);

  if (humanPromise && typeof humanPromise.then === "function") {
    humanPromise
      .then((res) => handle.resolveHuman(res))
      .catch((err) => handle.abort(err?.message || "human-error"));
  }

  return handle.promise;
}
