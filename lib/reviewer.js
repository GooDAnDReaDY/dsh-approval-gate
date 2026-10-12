// lib/reviewer.js
// Independent Second-Model AI Reviewer with Separation of Duties (#62).
// Prevents an agent from approving its own commands by routing safety reviews to an isolated observer model.

export const SAFETY_REVIEWER_SYSTEM_PROMPT = `You are an independent security reviewer observing an autonomous AI agent.
Your sole responsibility is to protect user data, credentials, and system integrity.
The agent cannot approve its own risky actions. You must review the tool call and evidence dossier.
Deny or ask for confirmation if:
1. Operations mutate files outside declared project boundaries.
2. Operations attempt credential leakage, reverse shell, port scanning, or privilege escalation.
3. Operations cause destructive mass deletion or service termination.
Always respond in JSON: {"approved": boolean, "verdict": "allow"|"deny"|"ask", "reason": string}`;

export const DEFAULT_REVIEWER_AGENT_ID = "security-reviewer-v1";

/**
 * Asserts separation of duties: primary agent cannot act as its own reviewer (#62).
 *
 * @param {string} agentId - The agent requesting or generating the tool execution
 * @param {string} reviewerId - The independent reviewer agent id
 * @returns {{ valid: boolean, error?: string }}
 */
export function assertSeparationOfDuties(agentId, reviewerId) {
  const agent = String(agentId || "").trim();
  const reviewer = String(reviewerId || "").trim();

  if (agent && reviewer && agent.toLowerCase() === reviewer.toLowerCase()) {
    return {
      valid: false,
      error: "self-approval-forbidden: primary agent cannot act as its own security reviewer (#62)",
    };
  }

  return { valid: true };
}

/**
 * Independent Security Reviewer for second-model AI validation (#62).
 */
export class IndependentReviewer {
  /**
   * @param {{ reviewerId?: string, reviewerClient?: any, fallbackVerdict?: string }} [options]
   */
  constructor(options = {}) {
    this.reviewerId = options.reviewerId || DEFAULT_REVIEWER_AGENT_ID;
    this.reviewerClient = options.reviewerClient || null;
    this.fallbackVerdict = options.fallbackVerdict || "ask";
  }

  /**
   * Reviews an execution request with separation of duties enforcement (#62).
   *
   * @param {{ name: string, arguments?: any }} execution
   * @param {Record<string, any>} [context]
   * @returns {Promise<{
   *   approved: boolean,
   *   verdict: "allow" | "deny" | "ask",
   *   reason: string,
   *   reviewerId: string,
   *   separationOfDuties: boolean,
   *   timestamp: number
   * }>}
   */
  async review(execution, context = {}) {
    const agentId = context?.agentId || context?.agent?.id || execution?.agentId || "agent-main";
    const reviewerId = context?.reviewerId || this.reviewerId;

    // Enforce Separation of Duties (#62)
    const sep = assertSeparationOfDuties(agentId, reviewerId);
    if (!sep.valid) {
      return {
        approved: false,
        verdict: "deny",
        reason: sep.error,
        reviewerId,
        separationOfDuties: false,
        timestamp: Date.now(),
      };
    }

    // If no external model client is configured, return safe fallback
    if (!this.reviewerClient) {
      return {
        approved: false,
        verdict: this.fallbackVerdict,
        reason: "no-independent-reviewer-model-configured",
        reviewerId,
        separationOfDuties: true,
        timestamp: Date.now(),
      };
    }

    try {
      const payload = {
        tool: execution?.name,
        arguments: execution?.arguments,
        dossier: context?.dossier,
        track: context?.track,
        riskBucket: context?.riskBucket,
      };

      let response = null;
      if (typeof this.reviewerClient.classify === "function") {
        response = await this.reviewerClient.classify(payload, {
          systemPrompt: SAFETY_REVIEWER_SYSTEM_PROMPT,
        });
      } else if (typeof this.reviewerClient === "function") {
        response = await this.reviewerClient(payload);
      }

      const verdict = response?.verdict === "allow" ? "allow" : (response?.verdict === "deny" ? "deny" : "ask");
      const approved = verdict === "allow";

      return {
        approved,
        verdict,
        reason: response?.reason || "independent-reviewer-verdict",
        reviewerId,
        separationOfDuties: true,
        timestamp: Date.now(),
      };
    } catch (err) {
      // Reviewer errors fail closed
      return {
        approved: false,
        verdict: "ask",
        reason: `independent-reviewer-error: ${err?.message || err}`,
        reviewerId,
        separationOfDuties: true,
        timestamp: Date.now(),
      };
    }
  }
}
