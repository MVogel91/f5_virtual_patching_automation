import pytest
import responses

from virtual_patch import BigIP, Config, PatchError, apply_policy, resolve_signatures, single_match


BASE = "https://unit.invalid"
LOGIN = BASE + "/mgmt/shared/authn/login"
TOKEN = BASE + "/mgmt/shared/authz/tokens/test-token"


@responses.activate
def test_token_login_header_extend_cleanup():
    responses.add(responses.POST, LOGIN, json={"token": {"token": "test-token"}})
    responses.add(responses.PATCH, TOKEN, json={"timeout": 3600})
    responses.add(responses.GET, BASE + "/mgmt/tm/asm/policies", json={"items": []})
    responses.add(responses.DELETE, TOKEN, status=200)
    with BigIP("unit.invalid", "user", "secret") as client:
        client.request("GET", "/mgmt/tm/asm/policies")
    calls = responses.calls
    assert calls[0].request.body is not None
    assert calls[2].request.headers["X-F5-Auth-Token"] == "test-token"
    assert calls[1].request.headers["X-F5-Auth-Token"] == "test-token"
    assert [call.request.method for call in calls] == ["POST", "PATCH", "GET", "DELETE"]


@responses.activate
def test_login_timeout_failure_still_cleans_token():
    responses.add(responses.POST, LOGIN, json={"token": {"token": "test-token"}})
    responses.add(responses.PATCH, TOKEN, status=500, json={"message": "timeout failed"})
    responses.add(responses.DELETE, TOKEN, status=200)
    with pytest.raises(PatchError, match="timeout failed"):
        with BigIP("unit.invalid", "user", "secret"):
            pass
    assert [call.request.method for call in responses.calls] == ["POST", "PATCH", "DELETE"]


@responses.activate
def test_login_body_exception_cleans_token():
    responses.add(responses.POST, LOGIN, json={"token": {"token": "test-token"}})
    responses.add(responses.PATCH, TOKEN, json={"timeout": 3600})
    responses.add(responses.DELETE, TOKEN, status=200)
    with pytest.raises(RuntimeError):
        with BigIP("unit.invalid", "user", "secret"):
            raise RuntimeError("problem")
    assert responses.calls[-1].request.method == "DELETE"


class ScanClient:
    def __init__(self, rows):
        self.rows = rows
        self.filters = []

    def pages(self, path, params=None):
        self.filters.append(params["$filter"])
        if params["$filter"].startswith("signatureId"):
            return iter([row for row in self.rows if row["signatureId"] == 123])
        return iter([row for row in self.rows if row["hasCve"]])


def sig(sid, has_cve, refs=()):
    return {"id": f"internal-{sid}", "selfLink": BASE + f"/mgmt/tm/asm/signatures/internal-{sid}",
            "signatureId": sid, "hasCve": has_cve, "references": list(refs)}


def config(**changes):
    fields = dict(name="test", signatures=(123,), cves=("CVE-2024-12345",), policies=(),
                  enforce_signatures=False, apply_policy=False, alarm=True, block=True, learn=False)
    fields.update(changes)
    return Config(**fields)


def test_ids_independent_of_has_cve_and_cves_only_use_flag(caplog):
    rows = [sig(123, False), sig(456, True, [{"type": "cve", "value": "cve-2024-12345"}]),
            sig(789, False, [{"type": "cve", "value": "CVE-2024-12345"}])]
    client = ScanClient(rows)
    assert set(resolve_signatures(client, config())) == {123, 456}
    assert client.filters == ["signatureId eq 123", "hasCve eq true"]
    assert not caplog.records


def test_cve_without_has_cve_is_ignored(caplog):
    client = ScanClient([sig(123, False, [{"type": "cve", "value": "CVE-2024-12345"}])])
    with pytest.raises(PatchError, match="no signatures"):
        resolve_signatures(client, config(signatures=()))
    assert "matched no signatures" in caplog.text


def test_cve_filter_ignored_is_error():
    class Unfiltered(ScanClient):
        def pages(self, path, params=None):
            return iter(self.rows)
    with pytest.raises(PatchError, match="did not honor hasCve"):
        resolve_signatures(Unfiltered([sig(123, False)]), config(signatures=()))


@responses.activate
def test_server_filter_and_pagination():
    endpoint = BASE + "/mgmt/tm/asm/signatures"
    responses.add(responses.GET, endpoint, json={"items": [{"signatureId": 123, "id": "a"}], "totalItems": 2})
    responses.add(responses.GET, endpoint, json={"items": [{"signatureId": 999, "id": "b"}], "totalItems": 2})
    client = BigIP("unit.invalid", "u", "p")
    items = list(client.pages("/mgmt/tm/asm/signatures", {"$filter": "hasCve eq true"}, page_size=1))
    assert [item["id"] for item in items] == ["a", "b"]
    assert "%24skip=1" in responses.calls[1].request.url
    assert "%24filter=hasCve+eq+true" in responses.calls[0].request.url


@responses.activate
def test_ignored_filter_is_error():
    endpoint = BASE + "/mgmt/tm/asm/signatures"
    responses.add(responses.GET, endpoint, json={"items": [{"signatureId": 999}], "totalItems": 1})
    client = BigIP("unit.invalid", "u", "p")
    with pytest.raises(PatchError, match="did not honor signatureId"):
        single_match(client, "/mgmt/tm/asm/signatures", "signatureId", 123)


@responses.activate
def test_pagination_does_not_silently_drop_items():
    endpoint = BASE + "/mgmt/tm/asm/signatures"
    responses.add(responses.GET, endpoint, json={"items": [], "totalItems": 2})
    with pytest.raises(PatchError, match="pagination stopped"):
        list(BigIP("unit.invalid", "u", "p").pages("/mgmt/tm/asm/signatures"))


def test_apply_task_poll_and_timeout(monkeypatch):
    class Fake:
        def __init__(self):
            self.calls = []

        def request(self, method, path, body=None):
            self.calls.append((method, path, body))
            return {"id": "task"} if method == "POST" else {"status": "COMPLETED"}

    fake = Fake()
    apply_policy(fake, {"id": "policy", "fullPath": "/Common/p", "selfLink": BASE + "/mgmt/tm/asm/policies/policy"}, 10, False)
    assert fake.calls[0] == ("POST", "/mgmt/tm/asm/tasks/apply-policy", {
        "policyReference": {"link": BASE + "/mgmt/tm/asm/policies/policy"}})
    assert fake.calls[1][:2] == ("GET", "/mgmt/tm/asm/tasks/apply-policy/task")

    def broken(method, path, body=None):
        return {"id": "task"} if method == "POST" else {"status": "FAILURE", "errorMessage": "bad"}
    fake.request = broken
    with pytest.raises(PatchError, match="bad"):
        apply_policy(fake, {"id": "policy", "fullPath": "/Common/p", "selfLink": "link"}, 10, False)

    fake.request = lambda method, path, body=None: {"id": "task"} if method == "POST" else {"status": "RUNNING"}
    monkeypatch.setattr("virtual_patch.time.monotonic", lambda: 100)
    with pytest.raises(PatchError, match="timed out"):
        apply_policy(fake, {"id": "policy", "fullPath": "/Common/p", "selfLink": "link"}, 0, False)
