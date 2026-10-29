# Advanced WAF virtual patching

`virtual_patch.py` creates or extends a **manual** BIG-IP Advanced WAF attack
signature set, attaches it to chosen WAF policies, optionally enforces every
signature in that set, and applies policies changed during the run. Runs on
Python 3.9+ against a single device and a single set per invocation.

## Install and run

```sh
python3 -m pip install -r requirements.txt
export BIGIP_PASSWORD='your-password'
python3 virtual_patch.py --host bigip.example.net --user admin -c examples/signatures.yaml --dry-run
python3 virtual_patch.py --host bigip.example.net --user admin -c examples/signatures.yaml
```

If `BIGIP_PASSWORD` is absent, the script prompts securely. Device TLS is
verified by default. Use `--ca-bundle /path/to/ca.pem` for a private CA, or
`--insecure` when TLS verification is intentionally disabled (this also
suppresses urllib3's per-request `InsecureRequestWarning`). Neither the
password nor the token goes in the configuration file or logs.

Use `--tasks create,assign,enforce,apply` to pick steps (any subset); they run
in that fixed order. Defaults to all four. Example:

```sh
python3 virtual_patch.py --host bigip.example.net -c my-patch.yaml --tasks create,assign
```

`enforce` requires `enforce_signatures: true` and `apply` requires
`apply_policy: true` in the file. Either key absent means false. `--tasks
apply` alone has no changes to apply and is therefore a no-op. `--dry-run`
shows intended changes without writing WAF settings; logging in, setting the
token timeout, and deleting the token still occur. Use `-v` for debug logging
and `--log-file PATH` to duplicate messages to a file. `--login-provider tmos`,
`--token-timeout 3600`, and `--apply-timeout 600` may be changed if necessary.
Exit code 0 means success; 1 means validation, API, or apply failure.

## Configuration

YAML (`.yaml`/`.yml`) and JSON (`.json`) share the same schema. See `examples/`.

```yaml
signature_set:
  name: vp_example
  signatures: [200001475] # Public BIG-IP signature IDs, not REST internal IDs
  cves: [CVE-2024-12345]  # Optional; ID and CVE results are combined
  policies: [my_app, /Other/another_app]
  enforce_signatures: true
  apply_policy: true
  alarm: true
  block: true
  learn: false
```

`name` and at least one nonempty `signatures` or `cves` list are required.
`policies: all` or `policies: [all]` selects all policies. A bare policy name
selects `/Common/<name>`; an absolute name uses that path. Omit `policies` or
use `policies: []` to avoid policy operations. `enforce_signatures` and
`apply_policy` default to false. `alarm` and `block` default to true; `learn`
defaults to false. Unknown config keys and missing named policies are errors.
`apply_policiy` is **not** a valid key.

CVEs use only signatures flagged `hasCve=true` by BIG-IP. The script pages
these signatures and matches `references` of type `cve` by exact value,
ignoring case. Manual `signatures` IDs work whether or not `hasCve` is true.
Unmatched IDs/CVEs generate warnings; zero resolved signatures is an error.

If the set is missing, `create` creates it as a manual set. If already manual,
it merges missing signatures without removing old ones. An existing
filter-based set with the same name is an error. If `create` is omitted, the
set must exist. Enforcement covers **all** signatures in the set, including
ones already there, and takes them out of staging (`performStaging=false`) and
enables them. If a signature is unavailable in a policy, a warning is logged.
Attach flags affect newly attached sets; existing attachments are not changed.
BIG-IP enforcement mode still determines whether blocking occurs.

Only selected policies changed through assignment, enforcement, or an update
to an already attached set are applied. A shared set can affect policies
outside those selected; include those policies if you want them applied by
this run. Repeated runs skip already-complete writes. Policy application is
an asynchronous task and is polled to completion or timeout. BIG-IP config
save is not performed automatically; save the running config separately if
you need changes to survive a reboot.

## API endpoints

Authentication: `POST /mgmt/shared/authn/login`, `PATCH`/`DELETE
/mgmt/shared/authz/tokens/<token>`. All WAF endpoints include the complete
prefix shown here:

| Purpose | Endpoint |
|---|---|
| Find signatures / CVE references | `/mgmt/tm/asm/signatures` |
| Find/create/update manual set | `/mgmt/tm/asm/signature-sets[/<id>]` |
| Find policies | `/mgmt/tm/asm/policies` |
| Check/attach set | `/mgmt/tm/asm/policies/<policy-id>/signature-sets` |
| Check/enforce policy signature | `/mgmt/tm/asm/policies/<policy-id>/signatures[/<policy-signature-id>]` |
| Apply policy / poll | `/mgmt/tm/asm/tasks/apply-policy[/<task-id>]` |

Responses are paged using `$top`/`$skip`; filtering is server-side for CVE
availability, signature IDs, and policy signature lookups. Check API errors
and the task status in output if a policy cannot be applied.

## Tests

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

HTTP is mocked; tests do not require a BIG-IP.
