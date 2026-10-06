# APIdoc eval results

- Cases: 28 (beginner: 12, experienced: 11, hard: 5)
- LLM: gemini-3.5-flash-lite (replay)

**Diagnosed** = right category AND the explanation names the actual cause.
**auto** = the shipped behaviour: the LLM is consulted only when the rules'
confidence is below 0.85.

## Summary

| Cases | Rules only | LLM always | Auto (shipped) |
|---|---|---|---|
| beginner | 12/12 (100%) | 12/12 (100%) | 12/12 (100%) |
| experienced | 11/11 (100%) | 11/11 (100%) | 11/11 (100%) |
| hard | 0/5 (0%) | 5/5 (100%) | 5/5 (100%) |
| **all** | 23/28 (82%) | 28/28 (100%) | 28/28 (100%) |

Machine-applied fixes that made the request succeed: 7/7 (100%)
LLM gave no usable answer (failed call, invalid JSON, ungrounded): 0 (counted as not diagnosed in the LLM column)
  of which discarded for ungrounded evidence: 0
LLM disagreements overruled by a proven rule: 1
Evidence items dropped by the grounding check: 0

## Per case

| id | case | expected | rules | llm | auto |
|---|---|---|---|---|---|
| b01 | no credentials at all | auth_missing | PASS auth_missing (0.85) | PASS auth_missing (0.85) | PASS auth_missing (0.85) |
| b02 | token without 'Bearer ' | auth_scheme | PASS auth_scheme (0.90) | PASS auth_scheme (0.90) | PASS auth_scheme (0.90) |
| b03 | 'Bearer' written twice | auth_scheme | PASS auth_scheme (0.85) | PASS auth_scheme (0.85) | PASS auth_scheme (0.85) |
| b04 | JSON sent with -d (form content type) | content_type | PASS content_type (0.95) | PASS content_type (0.95) | PASS content_type (0.95) |
| b05 | quotes eaten by the shell | malformed_body | PASS malformed_body (0.90) | PASS malformed_body (0.90) | PASS malformed_body (0.90) |
| b06 | trailing comma in JSON | malformed_body | PASS malformed_body (0.90) | PASS malformed_body (0.90) | PASS malformed_body (0.90) |
| b07 | API key in the query string | api_key_location | PASS api_key_location (0.85) | PASS api_key_location (0.85) | PASS api_key_location (0.85) |
| b08 | API key header missing | auth_missing | PASS auth_missing (0.85) | PASS auth_missing (0.85) | PASS auth_missing (0.85) |
| b09 | typo in the path | not_found | PASS not_found (0.50) | PASS not_found (0.85) | PASS not_found (0.85) |
| b10 | GET on a POST-only endpoint | method_not_allowed | PASS method_not_allowed (0.80) | PASS method_not_allowed (0.85) | PASS method_not_allowed (0.85) |
| b11 | required field missing | validation | PASS validation (0.85) | PASS validation (0.85) | PASS validation (0.85) |
| b12 | nothing listening on that port | connection | PASS connection (0.90) | PASS connection (0.90) | PASS connection (0.90) |
| e01 | auth dropped on cross-host redirect | auth_dropped_on_redirect | PASS auth_dropped_on_redirect (0.95) | PASS auth_dropped_on_redirect (0.95) | PASS auth_dropped_on_redirect (0.95) |
| e02 | 301 turns POST into GET | method_changed_on_redirect | PASS method_changed_on_redirect (0.90) | PASS method_changed_on_redirect (0.90) | PASS method_changed_on_redirect (0.90) |
| e03 | expired JWT | auth_expired | PASS auth_expired (0.95) | PASS auth_expired (0.95) | PASS auth_expired (0.95) |
| e04 | JWT not valid yet (clock) | auth_not_yet_valid | PASS auth_not_yet_valid (0.85) | PASS auth_not_yet_valid (0.85) | PASS auth_not_yet_valid (0.85) |
| e05 | valid token, missing scope | auth_scope | PASS auth_scope (0.95) | PASS auth_scope (0.95) | PASS auth_scope (0.95) |
| e06 | JWT with read scope on admin endpoint | auth_scope | PASS auth_scope (0.95) | PASS auth_scope (0.95) | PASS auth_scope (0.95) |
| e07 | tampered JWT signature | auth_invalid | PASS auth_invalid (0.70) | PASS auth_invalid (0.85) | PASS auth_invalid (0.85) |
| e08 | rate limited | rate_limited | PASS rate_limited (0.95) | PASS rate_limited (0.95) | PASS rate_limited (0.95) |
| e09 | 200 with an error body | error_in_success | PASS error_in_success (0.85) | PASS error_in_success (0.85) | PASS error_in_success (0.85) |
| e10 | 406 Not Acceptable | not_acceptable | PASS not_acceptable (0.85) | PASS not_acceptable (0.85) | PASS not_acceptable (0.85) |
| e11 | server error | server_error | PASS server_error (0.75) | PASS server_error (0.85) | PASS server_error (0.85) |
| h01 | vague 400: date in the wrong format | bad_parameter | PARTIAL bad_parameter (0.30) | PASS bad_parameter (0.85) | PASS bad_parameter (0.85) |
| h02 | 400 reason given as a plain string | bad_parameter | PARTIAL bad_parameter (0.30) | PASS bad_parameter (0.85) | PASS bad_parameter (0.85) |
| h03 | 422 in a non-standard error shape | validation | FAIL unknown (0.10) | PASS validation (0.85) | PASS validation (0.85) |
| h04 | opaque token expired (message only) | auth_expired | FAIL auth_invalid (0.55) | PASS auth_expired (0.85) | PASS auth_expired (0.85) |
| h05 | SSO redirect ends on a 200 HTML login page | auth_missing | FAIL ok (0.50) | PASS auth_missing (0.85) | PASS auth_missing (0.85) |

PASS = diagnosed; PARTIAL = right category, cause not named; FAIL = wrong category

## Limitations

- The cases are self-authored against a self-built mock API. The 'hard' cases
  were written so that no rule matches them, which is the only part of this
  eval that can show the LLM adding value; it is still small (5 cases).
- 'Cause named' is a keyword check, not a judgement of explanation quality.
- One LLM sample per case. Recorded responses make reruns reproducible, but
  a fresh recording can score differently.
