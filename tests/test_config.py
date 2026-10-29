import json
from pathlib import Path
import warnings

import pytest
import urllib3

from virtual_patch import PatchError, load_config, select_tasks, suppress_insecure_warnings


@pytest.mark.parametrize("filename", ["examples/cves.yaml", "examples/signatures.yaml", "examples/example.json"])
def test_examples_load(filename):
    config = load_config(Path(filename))
    assert config.name.startswith("virtual_patch_")
    assert config.signatures or config.cves


@pytest.mark.parametrize("changes", [
    {"name": ""}, {"signatures": [], "cves": []}, {"signatures": [True]},
    {"signatures": ["abc"]}, {"cves": ["2024-1234"]},
    {"apply_policiy": True}, {"enforce_signatures": "true"},
    {"policies": ["all", "other"]}, {"policies": "unknown"},
])
def test_bad_config(tmp_path, changes):
    data = {"signature_set": {"name": "test", "signatures": [123], **changes}}
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(PatchError):
        load_config(path)


@pytest.mark.parametrize("policies,expected", [("all", "all"), (["all"], "all"), ([], ()), (["foo", "/Other/bar"], ("foo", "/Other/bar"))])
def test_policies_forms(tmp_path, policies, expected):
    path = tmp_path / "config.yaml"
    path.write_text("signature_set:\n  name: x\n  cves: [CVE-2024-12345]\n" + f"  policies: {json.dumps(policies)}\n")
    assert load_config(path).policies == expected


@pytest.mark.parametrize("insecure,expected_warnings", [(True, 0), (False, 1)])
def test_insecure_warning_suppressed_only_with_flag(insecure, expected_warnings):
    # catch_warnings restores the global filter list, so tests stay isolated.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        suppress_insecure_warnings(insecure)
        warnings.warn("unverified HTTPS request", urllib3.exceptions.InsecureRequestWarning)
    assert len(caught) == expected_warnings


def test_task_selection():
    assert select_tasks("apply,create") == ("create", "apply")
    for value in ("", "assign,assign", "assign,bad", " assign"):
        with pytest.raises(Exception):
            select_tasks(value)
