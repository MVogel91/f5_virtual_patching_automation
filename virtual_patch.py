#!/usr/bin/env python3
"""Manage manual Advanced WAF attack-signature sets and policy enforcement."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from getpass import getpass
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Iterator
from urllib.parse import urlparse

import requests
import urllib3
import yaml


ASM = "/mgmt/tm/asm"
TASKS = ("create", "assign", "enforce", "apply")
LOG = logging.getLogger("virtual_patch")


class PatchError(Exception):
    """Invalid input or a failed BIG-IP operation."""


@dataclass(frozen=True)
class Config:
    name: str
    signatures: tuple[int, ...]
    cves: tuple[str, ...]
    policies: tuple[str, ...] | str
    enforce_signatures: bool
    apply_policy: bool
    alarm: bool
    block: bool
    learn: bool


def load_config(path: Path) -> Config:
    try:
        with path.open(encoding="utf-8") as stream:
            if path.suffix.lower() in (".yaml", ".yml"):
                raw = yaml.safe_load(stream)
            elif path.suffix.lower() == ".json":
                raw = json.load(stream)
            else:
                raise PatchError("config extension must be .yaml, .yml, or .json")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise PatchError(f"cannot load {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"signature_set"}:
        raise PatchError("config must contain exactly one key: signature_set")
    data = raw["signature_set"]
    if not isinstance(data, dict):
        raise PatchError("signature_set must be a mapping")
    allowed = {"name", "signatures", "cves", "policies", "enforce_signatures", "apply_policy", "alarm", "block", "learn"}
    if set(data) - allowed:
        raise PatchError(f"unknown signature_set keys: {', '.join(sorted(set(data) - allowed))}")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PatchError("signature_set.name must be a nonempty string")
    for key in ("signatures", "cves"):
        if not isinstance(data.get(key, []), list):
            raise PatchError(f"signature_set.{key} must be a list")
    ids = []
    for value in data.get("signatures", []):
        if isinstance(value, bool) or not (isinstance(value, int) or isinstance(value, str) and value.isdecimal()):
            raise PatchError("signatures must contain positive public numeric signature IDs")
        if int(value) < 1:
            raise PatchError("signatures must contain positive public numeric signature IDs")
        ids.append(int(value))
    cves = []
    for value in data.get("cves", []):
        if not isinstance(value, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", value, flags=re.I):
            raise PatchError(f"invalid CVE: {value!r}")
        cves.append(value.upper())
    if not ids and not cves:
        raise PatchError("at least one signature ID or CVE is required")
    policies = data.get("policies", [])
    if policies == "all" or policies == ["all"]:
        policies = "all"
    elif isinstance(policies, list) and all(isinstance(p, str) and p.strip() and p != "all" for p in policies):
        policies = tuple(dict.fromkeys(policies))
    else:
        raise PatchError("policies must be 'all', ['all'], or a list of nonempty names/paths")
    flags = {}
    for key, default in (("enforce_signatures", False), ("apply_policy", False), ("alarm", True), ("block", True), ("learn", False)):
        value = data.get(key, default)
        if type(value) is not bool:
            raise PatchError(f"signature_set.{key} must be a boolean")
        flags[key] = value
    return Config(name.strip(), tuple(dict.fromkeys(ids)), tuple(dict.fromkeys(cves)), policies, **flags)


def select_tasks(value: str) -> tuple[str, ...]:
    selected = value.split(",")
    if not selected or len(selected) != len(set(selected)) or any(s not in TASKS for s in selected):
        raise argparse.ArgumentTypeError(f"--tasks must be comma-separated unique choices from {','.join(TASKS)}")
    return tuple(t for t in TASKS if t in selected)


class BigIP:
    def __init__(self, host: str, user: str, password: str, verify: bool | str = True, timeout: int = 30, token_timeout: int = 3600, provider: str = "tmos"):
        if not host or "/" in host or "://" in host or "?" in host or "#" in host:
            raise PatchError("--host must be a hostname or IP address (optionally with port)")
        self.base = f"https://{host}"
        self.user = user
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.token_timeout = token_timeout
        self.provider = provider
        self.session = requests.Session()
        self.token: str | None = None

    def __enter__(self) -> BigIP:
        try:
            result = self.request("POST", "/mgmt/shared/authn/login", {
                "username": self.user, "password": self.password, "loginProviderName": self.provider,
            })
            self.token = result["token"]["token"]
            self.session.headers["X-F5-Auth-Token"] = self.token
            self.request("PATCH", f"/mgmt/shared/authz/tokens/{self.token}", {"timeout": self.token_timeout})
            return self
        except (KeyError, TypeError) as exc:
            self.__exit__(None, None, None)
            raise PatchError("login response contains no token") from exc
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_: Any) -> None:
        if self.token:
            try:
                self.request("DELETE", f"/mgmt/shared/authz/tokens/{self.token}")
            except PatchError as exc:
                LOG.warning("could not delete token: %s", exc)
        self.session.close()
        self.token = None

    def request(self, method: str, path: str, body: dict | None = None, params: dict | None = None) -> dict:
        safe_path = re.sub(r"(/mgmt/shared/authz/tokens/)[^/]+", r"\1<token>", path)
        try:
            response = self.session.request(method, self.base + path, json=body, params=params,
                                            verify=self.verify, timeout=self.timeout)
            response.raise_for_status()
            if not response.content:
                return {}
            result = response.json()
            if not isinstance(result, dict):
                raise PatchError(f"{method} {safe_path}: expected JSON object")
            return result
        except requests.HTTPError as exc:
            try:
                details = response.json().get("message", "")
            except (ValueError, AttributeError):
                details = ""
            if self.token:
                details = str(details).replace(self.token, "<token>")
            raise PatchError(f"{method} {safe_path}: HTTP {response.status_code}: {details}") from exc
        except (requests.RequestException, ValueError) as exc:
            raise PatchError(f"{method} {safe_path}: {str(exc).replace(self.token, '<token>') if self.token else exc}") from exc

    def pages(self, path: str, params: dict | None = None, page_size: int = 500) -> Iterator[dict]:
        offset = 0
        while True:
            result = self.request("GET", path, params={**(params or {}), "$top": page_size, "$skip": offset})
            items = result.get("items", [])
            if not isinstance(items, list):
                raise PatchError(f"GET {path}: items is not a list")
            yield from items
            offset += len(items)
            total = result.get("totalItems")
            if total is not None and offset >= total or total is None and len(items) < page_size:
                break
            if len(items) < page_size:
                raise PatchError(f"GET {path}: pagination stopped before totalItems")


def single_match(client: BigIP, path: str, field: str, value: str | int) -> dict | None:
    literal = str(value) if isinstance(value, int) else "'" + value.replace("'", "''") + "'"
    match = None
    for item in client.pages(path, {"$filter": f"{field} eq {literal}"}):
        if item.get(field) != value:
            raise PatchError(f"device did not honor {field} filter on {path}")
        if match is not None:
            raise PatchError(f"more than one {field}={value!r} found at {path}")
        match = item
    return match


def resolve_signatures(client: BigIP, config: Config) -> dict[int, dict]:
    found: dict[int, dict] = {}
    for sid in config.signatures:
        item = single_match(client, f"{ASM}/signatures", "signatureId", sid)
        if item:
            found[sid] = item
        else:
            LOG.warning("signature ID %s not found", sid)
    if config.cves:
        matched = set()
        wanted = set(config.cves)
        params = {"$filter": "hasCve eq true", "$select": "id,signatureId,name,references,hasCve,selfLink"}
        for item in client.pages(f"{ASM}/signatures", params):
            if item.get("hasCve") is not True:
                raise PatchError("device did not honor hasCve eq true filter; refusing unfiltered CVE scan")
            references = item.get("references") or []
            hits = {r.get("value", "").upper() for r in references if r.get("type", "").lower() == "cve"} & wanted
            if hits:
                matched.update(hits)
                found[item["signatureId"]] = item
        for cve in config.cves:
            if cve not in matched:
                LOG.warning("CVE %s matched no signatures with hasCve=true", cve)
    if not found:
        raise PatchError("no signatures resolved")
    for item in found.values():
        if not item.get("id") or not item.get("selfLink"):
            raise PatchError("signature response missing id or selfLink")
    return found


def resolve_policies(client: BigIP, config: Config) -> list[dict]:
    if not config.policies:
        return []
    items = list(client.pages(f"{ASM}/policies", {"$select": "id,name,fullPath"}))
    if config.policies == "all":
        return items
    by_path = {item["fullPath"]: item for item in items}
    selected = []
    for name in config.policies:
        path = name if name.startswith("/") else "/Common/" + name
        if path not in by_path:
            raise PatchError(f"policy not found: {path}")
        if by_path[path] not in selected:
            selected.append(by_path[path])
    return selected


def reference_id(reference: dict) -> str:
    link = reference.get("link", "")
    if not link:
        return ""
    return urlparse(link).path.rstrip("/").rsplit("/", 1)[-1]


def get_set(client: BigIP, name: str) -> dict | None:
    entry = single_match(client, f"{ASM}/signature-sets", "name", name)
    if entry:
        entry = client.request("GET", f"{ASM}/signature-sets/{entry['id']}")
        if entry.get("type") != "manual":
            raise PatchError(f"set {name!r} exists but is not manual")
    return entry


def sync_set(client: BigIP, config: Config, signatures: dict[int, dict], dry_run: bool) -> tuple[dict | None, bool]:
    current = get_set(client, config.name)
    new_refs = [{"link": item["selfLink"]} for item in signatures.values()]
    if current is None:
        LOG.info("%s create manual set %s (%d signatures)", "would" if dry_run else "creating", config.name, len(new_refs))
        if dry_run:
            return None, True
        created = client.request("POST", f"{ASM}/signature-sets", {
            "name": config.name, "type": "manual", "signatureReferences": new_refs,
        })
        if not created.get("id"):
            raise PatchError("created set response missing id")
        return client.request("GET", f"{ASM}/signature-sets/{created['id']}"), True
    old_refs = current.get("signatureReferences") or []
    existing = {ref.get("signatureId") for ref in old_refs}
    missing = [ref for sid, ref in zip(signatures, new_refs) if sid not in existing]
    if missing:
        LOG.info("%s add %d signatures to set %s", "would" if dry_run else "adding", len(missing), config.name)
        if not dry_run:
            client.request("PATCH", f"{ASM}/signature-sets/{current['id']}", {
                "signatureReferences": [{"link": r["link"]} for r in old_refs] + missing,
            })
            current = client.request("GET", f"{ASM}/signature-sets/{current['id']}")
    return current, bool(missing)


def assignment(client: BigIP, policy: dict, set_id: str) -> dict | None:
    path = f"{ASM}/policies/{policy['id']}/signature-sets"
    for item in client.pages(path):
        if reference_id(item.get("signatureSetReference", {})) == set_id:
            return item
    return None


def policy_signature(client: BigIP, policy_id: str, sid: int) -> dict | None:
    path = f"{ASM}/policies/{policy_id}/signatures"
    params = {"$filter": f"signature/signatureId eq {sid}", "$select": "id,signatureReference,performStaging,enabled"}
    match = None
    for item in client.pages(path, params):
        if item.get("signatureReference", {}).get("signatureId") != sid:
            raise PatchError(f"device did not honor policy signature filter for {sid}")
        if match is not None:
            raise PatchError(f"policy {policy_id} contains multiple copies of signature {sid}")
        match = item
    return match


def apply_policy(client: BigIP, policy: dict, timeout: int, dry_run: bool) -> None:
    name = policy["fullPath"]
    if dry_run:
        LOG.info("would apply policy %s", name)
        return
    if not policy.get("selfLink"):
        raise PatchError(f"policy {name} response missing selfLink")
    task = client.request("POST", f"{ASM}/tasks/apply-policy", {
        "policyReference": {"link": policy["selfLink"]},
    })
    if not task.get("id"):
        raise PatchError(f"apply task for {name} has no id")
    deadline = time.monotonic() + timeout
    while True:
        result = client.request("GET", f"{ASM}/tasks/apply-policy/{task['id']}")
        status = result.get("status")
        if status == "COMPLETED":
            LOG.info("applied policy %s", name)
            return
        if status in ("FAILURE", "FAILED", "ERROR"):
            raise PatchError(f"apply policy {name} failed: {result.get('errorMessage', result)}")
        if time.monotonic() >= deadline:
            raise PatchError(f"timed out applying policy {name} (status={status})")
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def run(client: BigIP, config: Config, tasks: tuple[str, ...], dry_run: bool, apply_timeout: int) -> None:
    signatures = resolve_signatures(client, config)
    policies = resolve_policies(client, config) if any(t in tasks for t in ("assign", "enforce", "apply")) else []
    current = get_set(client, config.name) if "create" not in tasks else None
    changed_set = False
    if "create" in tasks:
        current, changed_set = sync_set(client, config, signatures, dry_run)
    elif current is None:
        raise PatchError(f"set {config.name!r} does not exist; include 'create' in --tasks")
    set_signature_ids = set(signatures) if current is None else {
        ref["signatureId"] for ref in current.get("signatureReferences", [])
        if isinstance(ref.get("signatureId"), int)
    }
    # During a dry run the remote set is not modified: include planned additions.
    if dry_run and "create" in tasks:
        set_signature_ids.update(signatures)
    if current and not set_signature_ids:
        raise PatchError("manual set contains no signature IDs; cannot inspect/enforce membership")
    changed_count = 0
    enforced_count = 0
    applied_count = 0
    for policy in policies:
        name = policy["fullPath"]
        attached = assignment(client, policy, current["id"]) if current else None
        previously_attached = bool(attached)
        changed = changed_set and bool(attached)
        if "assign" in tasks and not attached:
            LOG.info("%s attach set %s to %s", "would" if dry_run else "attaching", config.name, name)
            if not dry_run:
                client.request("POST", f"{ASM}/policies/{policy['id']}/signature-sets", {
                    "signatureSetReference": {"link": current["selfLink"]},
                    "alarm": config.alarm, "block": config.block, "learn": config.learn,
                })
            attached = True
            changed = True
        if "enforce" in tasks and config.enforce_signatures:
            if dry_run and not current:
                if attached:
                    LOG.info("would inspect/enforce up to %d signatures after attaching set to %s", len(set_signature_ids), name)
                    changed = True
            elif not attached:
                LOG.warning("set %s not attached to %s; cannot enforce", config.name, name)
            else:
                for sid in sorted(set_signature_ids):
                    entry = policy_signature(client, policy["id"], sid)
                    if entry is None:
                        if dry_run and (not previously_attached or sid in signatures and changed_set):
                            LOG.info("would enforce signature %d on %s after set/attachment change", sid, name)
                            continue
                        LOG.warning("signature %d not found on policy %s", sid, name)
                        continue
                    if entry.get("performStaging") is not False or entry.get("enabled") is not True:
                        LOG.info("%s enforce signature %d on %s", "would" if dry_run else "enforcing", sid, name)
                        if not dry_run:
                            client.request("PATCH", f"{ASM}/policies/{policy['id']}/signatures/{entry['id']}", {
                                "performStaging": False, "enabled": True,
                            })
                        enforced_count += 1
                        changed = True
        if changed:
            changed_count += 1
        if "apply" in tasks and config.apply_policy and changed:
            apply_policy(client, policy, apply_timeout, dry_run)
            applied_count += 1
        LOG.info("policy %s: %s", name, "changed" if changed else "unchanged")
    LOG.info("summary: %d signatures resolved; set %s; %d policies changed; %d signatures enforced; %d policies applied%s",
             len(signatures), "changed" if changed_set else "unchanged", changed_count, enforced_count, applied_count,
             " (dry run)" if dry_run else "")


def suppress_insecure_warnings(insecure: bool) -> None:
    """Silence urllib3's per-request InsecureRequestWarning, only when the user opted into --insecure."""
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", type=Path, required=True, help="YAML or JSON configuration")
    parser.add_argument("--host", required=True, help="BIG-IP management hostname/IP (optionally :port)")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--login-provider", default="tmos")
    parser.add_argument("--token-timeout", type=int, default=3600)
    parser.add_argument("--apply-timeout", type=int, default=600)
    parser.add_argument("--tasks", type=select_tasks, default=TASKS, metavar="create,assign,enforce,apply")
    parser.add_argument("--dry-run", action="store_true")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true", help="disable TLS certificate verification")
    tls.add_argument("--ca-bundle", help="CA PEM file used to verify TLS")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args(argv)
    suppress_insecure_warnings(args.insecure)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s", handlers=handlers)
    try:
        if not 1 <= args.token_timeout <= 36000 or args.apply_timeout < 1:
            raise PatchError("timeouts must be positive; token timeout maximum is 36000")
        config = load_config(args.config)
        password = os.getenv("BIGIP_PASSWORD") or getpass("BIG-IP password: ")
        with BigIP(args.host, args.user, password, verify=False if args.insecure else args.ca_bundle or True,
                   token_timeout=args.token_timeout, provider=args.login_provider) as client:
            run(client, config, args.tasks, args.dry_run, args.apply_timeout)
        return 0
    except (PatchError, KeyboardInterrupt) as exc:
        LOG.error("%s", exc or "interrupted")
        return 1


if __name__ == "__main__":
    sys.exit(main())
