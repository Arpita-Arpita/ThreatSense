/**
 * Client-side password policy — NFR-11.
 *
 * Proposal Section 3, Table 11, NFR-11 — Requirement (verbatim):
 *   "The system must enforce strong password policies: a minimum of 8
 *   characters, with at least one uppercase letter, one lowercase letter, one
 *   digit, and one special character. Passwords must be validated on both the
 *   client side and the server side before acceptance."
 *
 * Proposal Section 3, Table 11, NFR-11 — Measurement / Metric (verbatim):
 *   "Implementation: client-side regex validation on the registration form,
 *   and server-side validation immediately before bcrypt hashing."
 *
 * This file is the "client-side regex validation" half. The server-side half
 * is backend/app/core/password_policy.py, and the two MUST agree — a password
 * this file accepts but the server rejects would strand the administrator on
 * a form that looks valid and keeps failing.
 *
 * That agreement is pinned by an automated test, not by good intentions:
 * backend/tests/test_password_policy.py::test_client_and_server_policies_agree
 * reads THIS FILE and asserts MIN_LENGTH and the four character-class regexes
 * still match the Python module. If you change a rule here, change it there.
 */

// NFR-11: "a minimum of 8 characters"
export const MIN_LENGTH = 8;

// NFR-11: "one special character". Mirrors Python's string.punctuation — the
// 32 ASCII punctuation marks, expressed as the four contiguous ASCII ranges
// they occupy: !-/ (33-47), :-@ (58-64), [-` (91-96), {-~ (123-126).
// Whitespace is deliberately excluded, matching the server.
export const SPECIAL = /[!-/:-@[-`{-~]/;

/**
 * The five checks named in NFR-11, each independently testable so the form
 * can show which ones are still outstanding rather than a single pass/fail.
 */
export const RULES = [
  { id: "length", label: `At least ${MIN_LENGTH} characters`, test: (p) => p.length >= MIN_LENGTH },
  { id: "upper", label: "One uppercase letter", test: (p) => /[A-Z]/.test(p) },
  { id: "lower", label: "One lowercase letter", test: (p) => /[a-z]/.test(p) },
  { id: "digit", label: "One digit", test: (p) => /[0-9]/.test(p) },
  { id: "special", label: "One special character", test: (p) => SPECIAL.test(p) },
];

/** Per-rule pass/fail, for the live checklist under the password field. */
export function evaluate(password) {
  const value = password || "";
  return RULES.map((rule) => ({ ...rule, passed: rule.test(value) }));
}

/** True when all five NFR-11 checks pass. */
export function isCompliant(password) {
  return evaluate(password).every((rule) => rule.passed);
}

/** Labels of the rules not yet satisfied. */
export function failedRules(password) {
  return evaluate(password).filter((rule) => !rule.passed).map((rule) => rule.label);
}
