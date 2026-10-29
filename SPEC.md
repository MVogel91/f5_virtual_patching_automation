# Virtual patching automation — implementation specification

## Goal

Write a Python 3.9+ script (`virtual_patch.py`) and documentation to create and
maintain manual Advanced WAF attack-signature sets, assign them to one or more
BIG-IP WAF policies, enforce the signatures, and apply changed policies.
Support one BIG-IP and one signature set per invocation. Support YAML primarily
and JSON as an alternative. Use `requests` and `PyYAML`; provide pytest tests
with `responses` for mocked HTTP.

## Input

The file contains exactly one `signature_set` mapping:

```yaml
signature_set:
  name: virtual_patch_example       # required, nonempty string
  signatures: [200001475]          # optional, public numeric signatureId values
  cves: [CVE-2024-12345]           # optional; at least one of signatures/cves required
  policies: [my_policy, /Other/policy] # optional; 'all' or [all] also supported
  enforce_signatures: false        # optional, default false
  apply_policy: false              # optional, default false
  alarm: true                      # optional, default true
  block: true                      # optional, default true
  learn: false                     # optional, default false
```

`policies` absent or `[]` means no policy operations. A bare policy name means
`/Common/<name>`; an absolute path is used verbatim. Missing policies are
errors. Unknown keys are errors, including the typo `apply_policiy`: the valid
key is `apply_policy`. Reject non-boolean boolean flags and invalid CVE/ID
types. Preserve explicit policy selection order. Never put credentials in this
input file.

## CLI and authentication

- `-c/--config` (required), `--host` (required), `--user` (default `admin`).
- Read password from `BIGIP_PASSWORD`, else prompt with `getpass`.
- `--tasks create,assign,enforce,apply` selects any unique subset; default all.
  Execute selected steps in that fixed order. An `enforce` step additionally
  requires `enforce_signatures: true`; `apply` additionally requires
  `apply_policy: true`. The YAML flags cannot be overridden by `--tasks`.
- `--dry-run` performs GETs and logs planned writes without changing sets or
  policies. Token authentication/cleanup still makes authentication requests.
- TLS verification is on by default; provide `--insecure` and `--ca-bundle`.
  `--insecure` also suppresses urllib3 `InsecureRequestWarning` output; without
  it, the warnings are left untouched.
- Support configurable login provider (default `tmos`), token timeout, apply
  timeout, `-v/--verbose`, optional `--log-file`, console summary, and nonzero
  exit on failure.
- Login through `POST /mgmt/shared/authn/login` using username, password and
  login provider. Use the returned token as `X-F5-Auth-Token`, extend its
  timeout with `PATCH /mgmt/shared/authz/tokens/<token>`, and DELETE that token
  when finished or on error. Do not log passwords or token values.

## Workflow

All WAF endpoints below have the **full** `/mgmt/tm/asm` prefix:

1. Resolve public signature IDs using filtered `GET /mgmt/tm/asm/signatures`
   (`signatureId eq N`) and the returned internal `id` / `selfLink`.
   Manually specified IDs are eligible regardless of `hasCve`.
2. For CVEs only, fetch paginated signatures filtered **on the device** by
   `hasCve eq true` (with `$select` and `$top`/`$skip`). Match case-insensitive
   `references` entries with `type: cve` and exact CVE value. Do not scan
   `hasCve=false` signatures for CVEs. Deduplicate across IDs and CVEs.
   Warn for unmatched entries; error when *no* signatures resolve.
3. Find the signature set by name via `GET /mgmt/tm/asm/signature-sets` and,
   for an existing set, GET its details by `id`. If absent and the `create`
   task is selected, POST a `type: manual` set with `signatureReferences`
   pointing at the resolved signature selfLinks. If present and manual, PATCH
   with the union of existing and newly requested signature references.
   Never remove existing signatures. A matching filter-based set is an error.
   If absent and `create` is not selected, error. Skip writes on no-op runs.
4. Resolve policy `id`, `selfLink` and `fullPath` from paginated
   `GET /mgmt/tm/asm/policies`. `all` selects every policy; missing/empty
   `policies` selects none.
5. For `assign`, GET each selected policy's
   `/mgmt/tm/asm/policies/<policy-id>/signature-sets` and POST an attachment
   only when absent, passing `signatureSetReference.link` and configured
   `alarm`, `block`, `learn` flags. Do not attach the set twice.
6. For enabled `enforce`, use the **actual membership of the set**, including
   signatures already present before this run. Query the policy-specific
   signatures with `$filter=signature/signatureId eq N` on
   `/mgmt/tm/asm/policies/<policy-id>/signatures`. PATCH each matching
   `/mgmt/tm/asm/policies/<policy-id>/signatures/<policy-signature-id>` to set
   `performStaging: false` and `enabled: true` only when needed. Warn if a
   signature is missing from the policy or the set is not attached.
7. For enabled `apply`, apply only selected policies changed in this invocation
   by assignment, enforcement, **or changes to an already attached set**.
   POST `/mgmt/tm/asm/tasks/apply-policy` with the policy reference; poll GET
   `/mgmt/tm/asm/tasks/apply-policy/<task-id>` until COMPLETED, failure, or
   configured timeout. Apply policies sequentially. An apply-only invocation
   with no changes this run is a no-op.

Do not assume REST collection responses fit in one page. Verify returned
entries match server-side filters before using them. In a dry run when a set
does not exist, log planned attach/enforce/apply actions without attempting
GETs against hypothetical objects. Re-running the same input should avoid
unnecessary changes. Do not implicitly save system configuration.

## Deliverables and verification

Provide the script, `requirements.txt`, `requirements-dev.txt`, a README with
CLI/config examples and behavior, example YAML and JSON files, and unit tests
for validation, auth cleanup, CVE/ID resolution, set creation/merge, policy
selection/assignment, enforcement, application polling, dry-run, and task
gating. Use mocks for automated tests. Live changes to any BIG-IP require
explicit permission and an identified test policy.
