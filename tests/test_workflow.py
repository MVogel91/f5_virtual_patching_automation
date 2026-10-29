import pytest

import virtual_patch as vp
from virtual_patch import Config, PatchError


def cfg(**changes):
    base = dict(name="example", signatures=(100,), cves=(), policies=("test",),
                enforce_signatures=True, apply_policy=True, alarm=True, block=True, learn=False)
    base.update(changes)
    return Config(**base)


def signature(sid):
    return {"id": f"glob-{sid}", "signatureId": sid,
            "selfLink": f"https://localhost/mgmt/tm/asm/signatures/glob-{sid}"}


def reference(sid):
    return {"link": signature(sid)["selfLink"], "signatureId": sid}


def manual_set(*ids):
    return {"id": "set1", "name": "example", "type": "manual",
            "selfLink": "https://localhost/mgmt/tm/asm/signature-sets/set1",
            "signatureReferences": [reference(i) for i in ids]}


POLICY = {"id": "policy1", "fullPath": "/Common/test", "name": "test",
          "selfLink": "https://localhost/mgmt/tm/asm/policies/policy1"}


class FakeClient:
    def __init__(self, existing_set=None, attachment=None, policy_signatures=None):
        self.signature_set = existing_set
        self.attachment = attachment
        self.policy_signatures = policy_signatures or {}
        self.calls = []

    def pages(self, path, params=None, page_size=500):
        self.calls.append(("GET PAGES", path, params))
        if path.endswith("/policies"):
            return iter([POLICY])
        if path.endswith("/signature-sets") and "/policies/" not in path:
            return iter([self.signature_set] if self.signature_set else [])
        if path.endswith("/signature-sets"):
            return iter([self.attachment] if self.attachment else [])
        if path.endswith("/signatures") and "/policies/" in path:
            sid = int(params["$filter"].split()[-1])
            return iter([self.policy_signatures[sid]] if sid in self.policy_signatures else [])
        raise AssertionError(path)

    def request(self, method, path, body=None, params=None):
        self.calls.append((method, path, body))
        if method == "GET" and "/signature-sets/" in path and "/policies/" not in path:
            return self.signature_set
        if method == "POST" and path == f"{vp.ASM}/signature-sets":
            self.signature_set = manual_set(100)
            return self.signature_set
        if method == "PATCH" and path == f"{vp.ASM}/signature-sets/set1":
            old = self.signature_set["signatureReferences"]
            self.signature_set = manual_set(*[r["signatureId"] for r in old], 100)
            return self.signature_set
        if method == "POST" and path.endswith("/signature-sets"):
            self.attachment = {"signatureSetReference": {"link": self.signature_set["selfLink"]}}
            return {"id": "attach1"}
        if method == "PATCH" and "/signatures/" in path:
            entry = next(entry for entry in self.policy_signatures.values() if path.endswith("/" + entry["id"]))
            entry.update(body)
            return entry
        if method == "POST" and path.endswith("/apply-policy"):
            return {"id": "apply1"}
        if method == "GET" and path.endswith("/apply-policy/apply1"):
            return {"status": "COMPLETED"}
        raise AssertionError((method, path, body))


def test_merge_preserves_existing_and_is_idempotent():
    fake = FakeClient(existing_set=manual_set(200))
    _, changed = vp.sync_set(fake, cfg(), {100: signature(100)}, False)
    assert changed
    patch = next(call for call in fake.calls if call[0] == "PATCH")
    assert {ref["link"] for ref in patch[2]["signatureReferences"]} == {
        reference(100)["link"], reference(200)["link"]}
    fake.calls.clear()
    _, changed = vp.sync_set(fake, cfg(), {100: signature(100)}, False)
    assert not changed
    assert all(call[0] != "PATCH" for call in fake.calls)


def test_create_dry_run_does_not_post():
    fake = FakeClient()
    entry, changed = vp.sync_set(fake, cfg(), {100: signature(100)}, True)
    assert entry is None and changed
    assert not any(call[0] == "POST" for call in fake.calls)


def test_filter_based_set_is_error():
    fake = FakeClient(existing_set={**manual_set(100), "type": "filter-based"})
    with pytest.raises(PatchError, match="not manual"):
        vp.get_set(fake, "example")


def test_policy_names_all_and_missing():
    fake = FakeClient()
    assert vp.resolve_policies(fake, cfg())[0]["fullPath"] == "/Common/test"
    assert vp.resolve_policies(fake, cfg(policies="all")) == [POLICY]
    assert vp.resolve_policies(fake, cfg(policies=("/Common/test",))) == [POLICY]
    with pytest.raises(PatchError, match="policy not found"):
        vp.resolve_policies(fake, cfg(policies=("missing",)))


def run_with_fixed_signature(monkeypatch, fake, config, tasks, dry_run=False):
    monkeypatch.setattr(vp, "resolve_signatures", lambda *_: {100: signature(100)})
    vp.run(fake, config, tasks, dry_run, 3)


def test_real_flow_attach_enforce_apply_and_second_run_noop(monkeypatch):
    fake = FakeClient(policy_signatures={100: {"id": "polsig1", "signatureReference": {"signatureId": 100},
                                               "performStaging": True, "enabled": False}})
    run_with_fixed_signature(monkeypatch, fake, cfg(), vp.TASKS)
    methods = [(call[0], call[1]) for call in fake.calls]
    assert ("POST", f"{vp.ASM}/signature-sets") in methods
    assert ("POST", f"{vp.ASM}/policies/policy1/signature-sets") in methods
    assert ("PATCH", f"{vp.ASM}/policies/policy1/signatures/polsig1") in methods
    assert ("POST", f"{vp.ASM}/tasks/apply-policy") in methods
    attached = next(call[2] for call in fake.calls if call[0] == "POST" and call[1].endswith("policies/policy1/signature-sets"))
    assert (attached["alarm"], attached["block"], attached["learn"]) == (True, True, False)
    fake.calls.clear()
    run_with_fixed_signature(monkeypatch, fake, cfg(), vp.TASKS)
    assert all(call[0] not in ("POST", "PATCH") for call in fake.calls)


def test_enforce_uses_existing_set_membership(monkeypatch):
    fake = FakeClient(existing_set=manual_set(100, 200),
                      attachment={"signatureSetReference": {"link": manual_set()["selfLink"]}},
                      policy_signatures={200: {"id": "s200", "signatureReference": {"signatureId": 200},
                                               "performStaging": True, "enabled": True}})
    run_with_fixed_signature(monkeypatch, fake, cfg(apply_policy=False), ("enforce",))
    assert ("PATCH", f"{vp.ASM}/policies/policy1/signatures/s200") in [(c[0], c[1]) for c in fake.calls]


def test_set_change_applies_already_attached_policy(monkeypatch):
    fake = FakeClient(existing_set=manual_set(200), attachment={"signatureSetReference": {"link": manual_set()["selfLink"]}})
    run_with_fixed_signature(monkeypatch, fake, cfg(enforce_signatures=False), ("create", "apply"))
    assert any(call[0] == "POST" and call[1].endswith("/apply-policy") for call in fake.calls)


def test_dry_run_new_set_makes_no_waf_writes(monkeypatch):
    fake = FakeClient()
    run_with_fixed_signature(monkeypatch, fake, cfg(), vp.TASKS, dry_run=True)
    assert all(call[0] not in ("POST", "PATCH", "DELETE") for call in fake.calls)


def test_tasks_and_yaml_both_gate(monkeypatch):
    fake = FakeClient(existing_set=manual_set(100),
                      attachment={"signatureSetReference": {"link": manual_set()["selfLink"]}},
                      policy_signatures={100: {"id": "p", "signatureReference": {"signatureId": 100},
                                               "performStaging": True, "enabled": True}})
    run_with_fixed_signature(monkeypatch, fake, cfg(enforce_signatures=False), vp.TASKS)
    assert all(call[0] not in ("POST", "PATCH") for call in fake.calls)
    fake.calls.clear()
    run_with_fixed_signature(monkeypatch, fake, cfg(), ("apply",))
    assert all(call[0] not in ("POST", "PATCH") for call in fake.calls)
