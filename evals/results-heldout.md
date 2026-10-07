# APIdoc eval results

- Cases: 10 (heldout: 10)
- LLM: not run (rules only)

**Diagnosed** = right category AND the explanation names the actual cause.
**auto** = the shipped behaviour: the LLM is consulted only when the rules'
confidence is below 0.85.

## Summary

| Cases | Rules only | 
|---|---|
| heldout | 0/10 (0%) |
| **all** | 0/10 (0%) |

Machine-applied fixes that made the request succeed: -

## Per case

| id | case | expected | rules |
|---|---|---|---|
| x01 | enum value in the wrong case | bad_parameter | PARTIAL bad_parameter (0.30) |
| x02 | GraphQL error in a 200 response | error_in_success | PARTIAL error_in_success (0.85) |
| x03 | revoked API key, reason only in a header | auth_invalid | FAIL unknown (0.10) |
| x04 | page number past the last page | not_found | PARTIAL not_found (0.50) |
| x05 | missing API version header | bad_parameter | PARTIAL bad_parameter (0.30) |
| x06 | missing Idempotency-Key on a payment | bad_parameter | FAIL unknown (0.10) |
| x07 | Basic credentials on a Bearer-only API | auth_scheme | FAIL auth_invalid (0.55) |
| x08 | expired pre-signed URL | auth_expired | FAIL unknown (0.10) |
| x09 | rate limit reported as 403 | rate_limited | FAIL auth_scope (0.50) |
| x10 | Authorization header misspelled | auth_missing | PARTIAL auth_missing (0.85) |

PASS = diagnosed; PARTIAL = right category, cause not named; FAIL = wrong category

## Limitations

- Held-out cases: committed before the first LLM run (see the git history)
  and no rule was written for them. Still self-authored, against a mock API.
- 'Cause named' is a keyword check, not a judgement of explanation quality.
- One LLM sample per case. Recorded responses make reruns reproducible, but
  a fresh recording can score differently.
