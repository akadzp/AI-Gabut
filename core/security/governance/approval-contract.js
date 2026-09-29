import { issueApproval, consumeApproval, revokeApproval } from "./policy.js";

/**
 * Compatibility facade for V3 callers. Authority remains core/security governance.
 * This module owns no approval state and does not implement a second lifecycle.
 */
export function createApprovalContract() {
  return Object.freeze({
    issue: args => issueApproval(args),
    consume: args => consumeApproval(args),
    revoke: token => revokeApproval(token)
  });
}
