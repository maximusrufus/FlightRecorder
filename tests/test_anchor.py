
from flightrecorder import anchor as anchor_mod
from flightrecorder import rfc3161_min


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body


def _build_fake_tsa_reply(digest: bytes) -> bytes:
    """Build a minimal well-formed granted TimeStampResp whose messageImprint
    matches `digest`, entirely offline, so tests never touch the network."""
    # PKIStatusInfo ::= SEQUENCE { status INTEGER(0) }
    pki_status_info = rfc3161_min._der_sequence(rfc3161_min._der_integer(0))

    alg_id = rfc3161_min._der_sequence(
        rfc3161_min._der_oid(rfc3161_min.SHA256_OID), rfc3161_min._der_null()
    )
    message_imprint = rfc3161_min._der_sequence(
        alg_id, rfc3161_min._der_octet_string(digest)
    )
    tst_info = rfc3161_min._der_sequence(
        rfc3161_min._der_integer(1),  # version
        rfc3161_min._der_oid("1.2.3"),  # policy (placeholder OID)
        message_imprint,
        rfc3161_min._der_integer(1),  # serial
        rfc3161_min._der_tlv(rfc3161_min._TAG_GENERALIZED_TIME, b"20260913000000Z"),
    )
    econtent = rfc3161_min._der_tlv(0xA0, rfc3161_min._der_octet_string(tst_info))
    encap_content_info = rfc3161_min._der_sequence(
        rfc3161_min._der_oid(rfc3161_min._ID_CT_TSTINFO_OID), econtent
    )
    signed_data = rfc3161_min._der_sequence(
        rfc3161_min._der_integer(3), encap_content_info
    )
    wrapped_signed_data = rfc3161_min._der_tlv(0xA0, signed_data)
    content_info = rfc3161_min._der_sequence(
        rfc3161_min._der_oid(rfc3161_min._ID_SIGNED_DATA_OID), wrapped_signed_data
    )
    return rfc3161_min._der_sequence(pki_status_info, content_info)


def test_anchor_chain_head_uses_injected_opener_never_touches_network(tmp_path):
    hashes = ["aa" * 32, "bb" * 32, "cc" * 32]
    root = anchor_mod.merkle_root(hashes)

    def fake_opener(request, timeout):
        # Confirm we're never given a real urllib.request.Request pointed at
        # the live internet without our own fake standing in for it.
        body = _build_fake_tsa_reply(bytes.fromhex(root))
        return _FakeResponse(body)

    store = anchor_mod.AnchorStore(tmp_path / "anchors.jsonl")
    rec = anchor_mod.anchor_chain_head(hashes, store, opener=fake_opener)

    assert rec.merkle_root == root
    assert rec.tsa_granted is True
    assert rec.tsa_gen_time == "20260913000000Z"

    stored = store.read_all()
    assert len(stored) == 1
    assert stored[0]["merkle_root"] == root


def test_anchor_without_tsa_attempt_still_computes_merkle_root(tmp_path):
    hashes = ["11" * 32, "22" * 32]
    store = anchor_mod.AnchorStore(tmp_path / "anchors.jsonl")
    rec = anchor_mod.anchor_chain_head(hashes, store, attempt_tsa=False)
    assert rec.tsa_granted is False
    assert rec.merkle_root == anchor_mod.merkle_root(hashes)


def test_merkle_proof_roundtrip():
    hashes = [f"{i:064x}" for i in range(1, 6)]
    root = anchor_mod.merkle_root(hashes)
    for idx in range(len(hashes)):
        proof = anchor_mod.merkle_proof(hashes, idx)
        assert anchor_mod.verify_merkle_proof(hashes[idx], proof, root)
