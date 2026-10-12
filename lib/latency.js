// lib/latency.js
// Classifier latency tracking and SLA-based fallback on deterministic rules (#57).

export const DEFAULT_CLASSIFIER_SLA_MS = 2000;
export const DEFAULT_LATENCY_WINDOW_SIZE = 50;
export const DEFAULT_DEGRADE_THRESHOLD_COUNT = 3;
export const DEFAULT_RECOVERY_THRESHOLD_COUNT = 2;

/**
 * Tracks external semantic classifier latency with sliding window statistics and SLA health (#57).
 */
export class ClassifierLatencyTracker {
  /**
   * @param {{
   *   slaMs?: number,
   *   windowSize?: number,
   *   degradeThresholdCount?: number,
   *   recoveryThresholdCount?: number
   * }} [options]
   */
  constructor(options = {}) {
    this.slaMs = typeof options.slaMs === "number" && options.slaMs > 0
      ? options.slaMs
      : DEFAULT_CLASSIFIER_SLA_MS;
    this.windowSize = typeof options.windowSize === "number" && options.windowSize > 0
      ? options.windowSize
      : DEFAULT_LATENCY_WINDOW_SIZE;
    this.degradeThresholdCount = typeof options.degradeThresholdCount === "number" && options.degradeThresholdCount > 0
      ? options.degradeThresholdCount
      : DEFAULT_DEGRADE_THRESHOLD_COUNT;
    this.recoveryThresholdCount = typeof options.recoveryThresholdCount === "number" && options.recoveryThresholdCount > 0
      ? options.recoveryThresholdCount
      : DEFAULT_RECOVERY_THRESHOLD_COUNT;

    this._samples = [];
    this._consecutiveSlow = 0;
    this._consecutiveFast = 0;
    this._degraded = false;
  }

  /**
   * Records a latency observation in milliseconds.
   *
   * @param {number} durationMs
   * @returns {{ degraded: boolean, p95Ms: number, avgMs: number }}
   */
  recordSample(durationMs) {
    const val = Math.max(0, Number(durationMs) || 0);
    this._samples.push(val);
    if (this._samples.length > this.windowSize) {
      this._samples.shift();
    }

    if (val > this.slaMs) {
      this._consecutiveSlow += 1;
      this._consecutiveFast = 0;
      if (this._consecutiveSlow >= this.degradeThresholdCount) {
        this._degraded = true;
      }
    } else {
      this._consecutiveFast += 1;
      this._consecutiveSlow = 0;
      if (this._consecutiveFast >= this.recoveryThresholdCount) {
        this._degraded = false;
      }
    }

    if (!this._degraded && this._samples.length >= 5 && this.getP95() > this.slaMs && this._consecutiveSlow > 0) {
      this._degraded = true;
    }

    return {
      degraded: this.isDegraded(),
      p95Ms: this.getP95(),
      avgMs: this.getAvg(),
    };
  }

  /**
   * Calculates 95th percentile latency from the current sliding window.
   * @returns {number}
   */
  getP95() {
    if (this._samples.length === 0) return 0;
    const sorted = this._samples.slice().sort((a, b) => a - b);
    const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
    return Math.round(sorted[idx] * 10) / 10;
  }

  /**
   * Calculates mean latency from current window.
   * @returns {number}
   */
  getAvg() {
    if (this._samples.length === 0) return 0;
    const sum = this._samples.reduce((acc, v) => acc + v, 0);
    return Math.round((sum / this._samples.length) * 10) / 10;
  }

  /**
   * Checks whether the classifier is currently marked degraded due to SLA violations.
   * @returns {boolean}
   */
  isDegraded() {
    return this._degraded;
  }

  /**
   * Resets all tracked samples and returns to healthy state.
   */
  reset() {
    this._samples = [];
    this._consecutiveSlow = 0;
    this._consecutiveFast = 0;
    this._degraded = false;
  }

  /**
   * Returns a snapshot of current latency metrics.
   * @returns {{ count: number, avgMs: number, p95Ms: number, minMs: number, maxMs: number, degraded: boolean, slaMs: number, consecutiveSlow: number }}
   */
  getMetrics() {
    const count = this._samples.length;
    const minMs = count > 0 ? Math.min(...this._samples) : 0;
    const maxMs = count > 0 ? Math.max(...this._samples) : 0;
    return {
      count,
      avgMs: this.getAvg(),
      p95Ms: this.getP95(),
      minMs,
      maxMs,
      degraded: this.isDegraded(),
      slaMs: this.slaMs,
      consecutiveSlow: this._consecutiveSlow,
    };
  }
}
