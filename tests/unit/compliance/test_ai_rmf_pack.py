"""NIST AI RMF pack: Covered rows carry chain entries; empty windows do not claim (#4915)."""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, date, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bernstein.core.compliance.ai_rmf import (
    COVERED_EVIDENCE_SELECTORS,
    PACK_KIND_AI_RMF,
    build_ai_rmf_pack,
    parse_mapping_rows,
)
from bernstein.core.lineage.entry import LineageEntry, canonicalise, entry_hash
from bernstein.core.lineage.identity import generate_keypair, sign_detached

REPO_ROOT = Path(__file__).resolve().parents[3]
MAPPING = REPO_ROOT / "docs" / "compliance" / "nist-ai-rmf-mapping.md"


def _date_to_ns(day: str) -> int:
    parsed = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1_000_000_000)


def _operator_key(tmp_path: Path) -> Path:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "operator.key"
    key_path.write_bytes(pem)
    return key_path


def _make_entry(*, path: str, content: str, agent_id: str, kid: str, ts_ns: int) -> LineageEntry:
    return LineageEntry(
        v=1,
        artefact_path=path,
        artefact_kind="file",
        content_hash="sha256:" + hashlib.sha256(content.encode()).hexdigest(),
        parent_hashes=[],
        agent_id=agent_id,
        agent_card_kid=kid,
        tool_call_id=f"tc-{ts_ns}",
        span_id=f"{ts_ns:016x}"[:16],
        ts_ns=ts_ns,
        operator_hmac="deadbeef",
    )


def _write_lineage(tmp_path: Path, entries: list[LineageEntry]) -> dict[str, Path]:
    lineage_dir = tmp_path / "lineage"
    signatures_dir = lineage_dir / "signatures"
    agent_cards_dir = tmp_path / "agents"
    lineage_dir.mkdir()
    signatures_dir.mkdir()
    agent_cards_dir.mkdir()
    priv_pem, pub_pem = generate_keypair()
    agent_id = "agent:worker-1"
    kid = f"{agent_id}-kid"
    (agent_cards_dir / f"{agent_id.replace(':', '_')}.json").write_text(
        json.dumps({"agent_id": agent_id, "kid": kid, "public_key_pem": pub_pem}, sort_keys=True),
        encoding="utf-8",
    )
    log_path = lineage_dir / "log.jsonl"
    with log_path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(canonicalise(entry).decode("utf-8") + "\n")
            digest = entry_hash(entry)
            jws = sign_detached(canonicalise(entry), priv_pem, kid=kid)
            (signatures_dir / f"{digest.split(':', 1)[1]}.jws").write_text(jws, encoding="utf-8")
    return {"lineage_dir": lineage_dir, "agent_cards_dir": agent_cards_dir}


def _build(tmp_path: Path, layout: dict[str, Path], name: str) -> Path:
    out = tmp_path / name
    build_ai_rmf_pack(
        since=date(2026, 1, 1),
        until=date(2026, 6, 30),
        org="Acme",
        lineage_dir=layout["lineage_dir"],
        agent_cards_dir=layout["agent_cards_dir"],
        mapping_path=MAPPING,
        output_path=out,
        operator_key_path=_operator_key(tmp_path),
    )
    return out


def _evidence(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("subcategory-evidence.json"))


def test_covered_selectors_match_mapping_verdicts() -> None:
    rows = parse_mapping_rows(MAPPING.read_text(encoding="utf-8"))
    covered = {row["id"] for row in rows if row["verdict"] == "Covered"}
    assert covered == set(COVERED_EVIDENCE_SELECTORS)


def test_covered_rows_resolve_to_chain_entries(tmp_path: Path) -> None:
    agent_id = "agent:worker-1"
    kid = f"{agent_id}-kid"
    base = _date_to_ns("2026-04-02")
    entries = [
        _make_entry(
            path=f".sdd/controls/{tokens[0]}/record.json",
            content=sub_id,
            agent_id=agent_id,
            kid=kid,
            ts_ns=base + index,
        )
        for index, (sub_id, tokens) in enumerate(sorted(COVERED_EVIDENCE_SELECTORS.items()))
    ]
    layout = _write_lineage(tmp_path, entries)
    out = _build(tmp_path, layout, "ai-rmf.zip")
    doc = _evidence(out)
    assert doc["kind"] == PACK_KIND_AI_RMF
    assert doc["window_claim"] == "evidenced"
    by_id = {row["id"]: row for row in doc["rows"]}
    for sub_id in COVERED_EVIDENCE_SELECTORS:
        assert by_id[sub_id]["verdict"] == "Covered"
        assert by_id[sub_id]["evidenced"] is True
        assert by_id[sub_id]["chain_entry_hashes"]
        assert by_id[sub_id]["genai_profile_ref"] == sub_id
    not_covered = [row for row in doc["rows"] if row["verdict"] == "Not-covered"]
    assert not_covered
    assert all(row["chain_entry_hashes"] == [] and row["evidenced"] is False for row in not_covered)


def test_two_builds_share_member_hashes(tmp_path: Path) -> None:
    agent_id = "agent:worker-1"
    kid = f"{agent_id}-kid"
    entries = [
        _make_entry(
            path=".sdd/controls/approval/record.json",
            content="approval",
            agent_id=agent_id,
            kid=kid,
            ts_ns=_date_to_ns("2026-04-02"),
        )
    ]
    layout = _write_lineage(tmp_path, entries)
    key = _operator_key(tmp_path)

    def _hashes(name: str) -> dict[str, str]:
        out = tmp_path / name
        build_ai_rmf_pack(
            since=date(2026, 1, 1),
            until=date(2026, 6, 30),
            org="Acme",
            lineage_dir=layout["lineage_dir"],
            agent_cards_dir=layout["agent_cards_dir"],
            mapping_path=MAPPING,
            output_path=out,
            operator_key_path=key,
        )
        with zipfile.ZipFile(out) as zf:
            manifest = json.loads(zf.read("pack-manifest.json"))
        return manifest["input_hashes"]

    assert _hashes("a.zip") == _hashes("b.zip")


def test_empty_window_is_valid_and_makes_no_claim(tmp_path: Path) -> None:
    lineage = tmp_path / "lineage"
    cards = tmp_path / "agents"
    lineage.mkdir()
    cards.mkdir()
    out = tmp_path / "empty.zip"
    build_ai_rmf_pack(
        since=date(2026, 1, 1),
        until=date(2026, 1, 2),
        org="Acme",
        lineage_dir=lineage,
        agent_cards_dir=cards,
        mapping_path=MAPPING,
        output_path=out,
        operator_key_path=_operator_key(tmp_path),
    )
    doc = _evidence(out)
    assert doc["window_claim"] == "empty"
    assert doc["entry_count"] == 0
    assert all(row["evidenced"] is False and row["chain_entry_hashes"] == [] for row in doc["rows"])


def test_unmatched_entries_do_not_claim_coverage(tmp_path: Path) -> None:
    agent_id = "agent:worker-1"
    kid = f"{agent_id}-kid"
    entries = [
        _make_entry(
            path="src/readme.md",
            content="notes",
            agent_id=agent_id,
            kid=kid,
            ts_ns=_date_to_ns("2026-04-02"),
        )
    ]
    layout = _write_lineage(tmp_path, entries)
    doc = _evidence(_build(tmp_path, layout, "unmatched.zip"))
    assert doc["window_claim"] == "unmatched"
    assert doc["entry_count"] == 1
    assert all(row["evidenced"] is False for row in doc["rows"])
