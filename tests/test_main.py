"""Tests for main.py. The Rekor API is replaced by a fake, so no network is used."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

import main
from merkle_proof import RootMismatchError
from tests.helpers import (
    ARTIFACT,
    consistency_proof,
    hexlist,
    leaves,
    real_rekor_entry,
    tree_root,
)

LOG_INDEX = 3078541822  # the Rekor entry for artifact.md
TREE_ID = "1193050959916656506"
OLD_SIZE, NEW_SIZE = 5, 13  # a small fake log used by the consistency tests


class FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    def json(self) -> Any:
        return self.payload


class FakeRekor:
    """Replaces requests.get: answers like Rekor and remembers every call."""

    def __init__(self, entry: Any = None, status_code: int = 200) -> None:
        self.entry = real_rekor_entry() if entry is None else entry
        self.status_code = status_code
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if "/log/proof" in url:
            proof = hexlist(consistency_proof(OLD_SIZE, leaves(NEW_SIZE)))
            return FakeResponse({"hashes": proof}, self.status_code)
        if "/log/entries" in url:
            return FakeResponse({"some-uuid": self.entry}, self.status_code)
        checkpoint = {
            "treeID": TREE_ID,
            "treeSize": NEW_SIZE,
            "rootHash": tree_root(leaves(NEW_SIZE)).hex(),
        }
        return FakeResponse(checkpoint, self.status_code)


@pytest.fixture
def rekor(monkeypatch: pytest.MonkeyPatch) -> FakeRekor:
    """Every test that takes `rekor` talks to the fake instead of the internet."""
    fake = FakeRekor()
    monkeypatch.setattr(main.requests, "get", fake)
    return fake


def run_cli(monkeypatch: pytest.MonkeyPatch, *args: str) -> None:
    """Run main() as if called as `python main.py <args>`."""
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    main.main()


def old_checkpoint(root_size: int = OLD_SIZE) -> dict[str, Any]:
    root = tree_root(leaves(root_size)).hex()
    return {"treeID": TREE_ID, "treeSize": OLD_SIZE, "rootHash": root}


# --- get_log_entry -----------------------------------------------------------


def test_get_log_entry_rejects_negative_index() -> None:
    with pytest.raises(ValueError, match="Invalid log index"):
        main.get_log_entry(-1)


def test_get_log_entry_returns_requested_entry(rekor: FakeRekor) -> None:
    entry = main.get_log_entry(LOG_INDEX)
    assert entry["logIndex"] == LOG_INDEX
    assert rekor.calls[0]["timeout"] == main.REQUEST_TIMEOUT  # bandit B113 fix


def test_get_log_entry_rejects_empty_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.requests, "get", lambda url, **kw: FakeResponse({}))
    with pytest.raises(ValueError, match="Unexpected response"):
        main.get_log_entry(LOG_INDEX)


def test_get_log_entry_rejects_other_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    other = dict(real_rekor_entry(), logIndex=1)
    monkeypatch.setattr(main.requests, "get", FakeRekor(entry=other))
    with pytest.raises(ValueError, match="expected 3078541822"):
        main.get_log_entry(LOG_INDEX)


def test_rekor_http_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.requests, "get", FakeRekor(status_code=500))
    with pytest.raises(Exception, match="Rekor error: 500"):
        main.get_latest_checkpoint()


# --- inclusion ---------------------------------------------------------------


def test_inclusion_real_artifact(
    rekor: FakeRekor, capsys: pytest.CaptureFixture[str]
) -> None:
    main.inclusion(LOG_INDEX, str(ARTIFACT))
    assert "Offline verification successful" in capsys.readouterr().out


def test_inclusion_rejects_tampered_artifact(
    rekor: FakeRekor, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Regression test for the fail-open bug class: another file must NOT pass.
    fake = tmp_path / "fake.md"
    fake.write_text("rev0000\n")
    main.inclusion(LOG_INDEX, str(fake))
    out = capsys.readouterr().out
    assert "Signature verification failed" in out
    assert "successful" not in out


def test_inclusion_missing_artifact(
    rekor: FakeRekor, capsys: pytest.CaptureFixture[str]
) -> None:
    main.inclusion(LOG_INDEX, "does-not-exist.md")
    assert "Artifact file not found" in capsys.readouterr().out
    assert rekor.calls == []  # stops before touching the network


def test_inclusion_tampered_proof_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = real_rekor_entry()
    entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    monkeypatch.setattr(main.requests, "get", FakeRekor(entry=entry))
    with pytest.raises(RootMismatchError):
        main.inclusion(LOG_INDEX, str(ARTIFACT))


# --- checkpoint and consistency ------------------------------------------------


def test_debug_checkpoint_is_saved(
    rekor: FakeRekor, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # checkpoint.json goes to the current directory
    checkpoint = main.get_latest_checkpoint(debug=True)
    assert json.loads((tmp_path / "checkpoint.json").read_text()) == checkpoint


def test_consistency_succeeds(
    rekor: FakeRekor, capsys: pytest.CaptureFixture[str]
) -> None:
    main.consistency(old_checkpoint())
    assert "Consistency verification successful" in capsys.readouterr().out
    expected = {"firstSize": OLD_SIZE, "lastSize": NEW_SIZE, "treeID": TREE_ID}
    assert rekor.calls[-1]["params"] == expected


def test_consistency_wrong_root_raises(rekor: FakeRekor) -> None:
    with pytest.raises(RootMismatchError):
        main.consistency(old_checkpoint(root_size=OLD_SIZE + 1))


def test_consistency_empty_or_other_tree(
    rekor: FakeRekor, capsys: pytest.CaptureFixture[str]
) -> None:
    main.consistency({})
    main.consistency({"treeID": "other-tree", "treeSize": OLD_SIZE, "rootHash": "00"})
    out = capsys.readouterr().out
    assert "Previous checkpoint is empty" in out
    assert "Tree IDs do not match" in out


# --- command line --------------------------------------------------------------


def test_cli_checkpoint_prints_json(
    rekor: FakeRekor,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli(monkeypatch, "-c")
    assert json.loads(capsys.readouterr().out)["treeID"] == TREE_ID


def test_cli_inclusion_with_debug(
    rekor: FakeRekor,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli(
        monkeypatch, "-d", "--inclusion", str(LOG_INDEX), "--artifact", str(ARTIFACT)
    )
    out = capsys.readouterr().out
    assert "enabled debug mode" in out
    assert "Calculated root hash" in out
    assert "Offline verification successful" in out


def test_cli_consistency(
    rekor: FakeRekor,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tree_root(leaves(OLD_SIZE)).hex()
    args = ["--tree-id", TREE_ID, "--tree-size", str(OLD_SIZE), "--root-hash", root]
    run_cli(monkeypatch, "--consistency", *args)
    assert "Consistency verification successful" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--consistency"], "please specify tree id"),
        (["--consistency", "--tree-id", "1"], "please specify tree size"),
        (["--consistency", "--tree-id", "1", "--tree-size", "5"], "root hash"),
    ],
)
def test_cli_consistency_missing_arguments(
    rekor: FakeRekor,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    message: str,
) -> None:
    run_cli(monkeypatch, *args)
    assert message in capsys.readouterr().out
    assert rekor.calls == []  # nothing is sent to Rekor with incomplete input
