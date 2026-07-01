"""SOC-TEL-010 - 证据链完整性与脱敏。"""
import hashlib
import json
from pathlib import Path

import pytest

from tests.common.matrix_loader import get_case

CASE_ID = "SOC-TEL-010"
MITRE = "N/A"
pytestmark = [pytest.mark.p0, pytest.mark.tel]


def test_evidence_integrity_and_redaction(evidence_recorder):
    rec = evidence_recorder
    rec.client({
        "case_meta": get_case(CASE_ID),
        "authorization": "Bearer header-secret-value",
        "nested": {"password": "fake-password", "note": "token=inline-secret"},
    })
    rec.assertion("test_secret_is_synthetic", True, "仅写入伪造密钥用于脱敏验证")
    evidence_path = Path(rec.finish("PASS", "证据时间窗、脱敏与哈希均已生成"))
    sidecar_path = Path(f"{evidence_path}.sha256")

    raw = evidence_path.read_bytes()
    payload = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    recorded_digest = sidecar_path.read_text(encoding="ascii").split()[0]

    serialized = raw.decode("utf-8")
    time_window = payload.get("time_window") or {}
    redacted = all(secret not in serialized for secret in (
        "header-secret-value", "fake-password", "inline-secret",
    ))
    window_complete = bool(time_window.get("start") and time_window.get("end"))
    hash_matches = digest == recorded_digest

    rec.assertion("sensitive_values_redacted", redacted, "伪造敏感值不得出现在 JSON")
    rec.assertion("time_window_complete", window_complete, str(time_window))
    rec.assertion("sha256_matches", hash_matches, recorded_digest)
    assert redacted
    assert window_complete
    assert hash_matches
    rec.finish("PASS", "敏感值为 0；时间窗完整；SHA-256 校验通过")
