"""RFC 3161 Time-Stamp Protocol (TSP) client -- vendored, not written from
scratch.

Provenance
----------
Vendored near-verbatim (2026-09-13) from
an internal RFC 3161 helper into this
standalone FlightRecorder repo, for `flightrecorder/anchor.py`'s periodic
chain-head anchoring. That file was itself vendored from
an internal stdlib-only RFC 3161 module, from
an internal RFC 3161 client, from
an internal timestamp-anchor module. This file
keeps the already-trimmed, stdlib-only shape:
  * ``build_timestamp_request`` -- DER-encode a TimeStampReq.
  * ``parse_timestamp_response`` -- parse a TimeStampResp far enough to read
    PKIStatusInfo and the embedded TSTInfo (genTime, serial, messageImprint).
  * ``request_timestamp`` / ``request_timestamp_multi`` -- POST a request,
    parse the reply. Injectable opener so tests never touch the network.
  * ``verify_timestamp_token`` -- messageImprint-match-only verification
    (no certificate-chain / signature check).

Chosen over the untrimmed internal module because that one's full
CMS-signature + certificate-chain verification path (``_verify_cms_signature``,
``require_signature=True``) needs the third-party ``asn1crypto`` + ``certifi``
+ ``cryptography`` packages, and this module is stdlib-only by design (see
its README). This vendor drops that block and keeps only the pieces that
build on stdlib (``hashlib``, ``secrets``, ``urllib``) alone.

============================================================================
WHAT AN RFC 3161 TIMESTAMP TOKEN PROVES, AND WHAT IT DOES NOT
============================================================================
A timestamp token from a public TSA is evidence that a particular digest
existed, verbatim, at or before the TSA's stated ``genTime``. That is the
WHOLE claim this module can support without the (unvendored) certificate-
chain verification step:

  * It does NOT prove the digest's content is truthful, complete, or
    unmodified in any semantic sense -- only that these exact bytes existed
    by that time.
  * It does NOT prove nothing was appended AFTER genTime -- a chain can grow
    after an anchor; only a LATER anchor covers the later rows.
  * Because this trimmed vendor never verifies the TSA's signature or
    certificate chain, ``verify_timestamp_token`` here confirms only that
    the token's messageImprint matches the digest that was anchored -- it
    does NOT confirm the token was genuinely issued by the named TSA. Full
    cryptographic authentication requires either the untrimmed
    untrimmed internal module (needs ``asn1crypto``) or an external check
    (``openssl ts -verify``).
  * It does NOT, by itself, carry evidentiary weight in a legal proceeding
    on its own; that requires a qualified certification pointing at this
    artifact, not the cryptography alone.

No network calls happen unless a caller invokes ``request_timestamp``.
This module itself is transport-agnostic and has no import-time side
effects.
============================================================================
"""

from __future__ import annotations

import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

# ---------------------------------------------------------------------------
# ASN.1 DER -- tiny encoder
# ---------------------------------------------------------------------------

_TAG_BOOLEAN = 0x01
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_UTF8_STRING = 0x0C
_TAG_SEQUENCE = 0x30
_TAG_GENERALIZED_TIME = 0x18

SHA256_OID = "2.16.840.1.101.3.4.2.1"
_ID_SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
_ID_CT_TSTINFO_OID = "1.2.840.113549.1.9.16.1.4"

_HASH_OIDS = {
    "sha256": SHA256_OID,
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}

# Public, free, no-account RFC-3161 authorities. Tried in order; the first
# that answers with a well-formed token wins.
DEFAULT_TSA_URLS: tuple[str, ...] = (
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://rfc3161.ai.moda",
)


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_integer(n: int) -> bytes:
    if n == 0:
        return _der_tlv(_TAG_INTEGER, b"\x00")
    length = max(1, (n.bit_length() + 8) // 8)
    b = n.to_bytes(length, "big", signed=True)
    while len(b) > 1 and b[0] == 0x00 and b[1] < 0x80:
        b = b[1:]
    return _der_tlv(_TAG_INTEGER, b)


def _der_boolean(v: bool) -> bytes:
    return _der_tlv(_TAG_BOOLEAN, b"\xff" if v else b"\x00")


def _der_null() -> bytes:
    return _der_tlv(_TAG_NULL, b"")


def _der_octet_string(b: bytes) -> bytes:
    return _der_tlv(_TAG_OCTET_STRING, b)


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise ValueError(f"bad OID: {dotted}")
    first = parts[0] * 40 + parts[1]
    out = bytearray([first])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunk = []
        while p:
            chunk.insert(0, p & 0x7F)
            p >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        out.extend(chunk)
    return _der_tlv(_TAG_OID, bytes(out))


def _der_sequence(*parts: bytes) -> bytes:
    return _der_tlv(_TAG_SEQUENCE, b"".join(parts))


# ---------------------------------------------------------------------------
# ASN.1 DER -- tiny recursive-descent reader
# ---------------------------------------------------------------------------


class _Node:
    __slots__ = ("class_", "constructed", "end", "length", "start", "tag", "value")

    def __init__(self, tag, constructed, class_, length, value, start, end):
        self.tag = tag
        self.constructed = constructed
        self.class_ = class_
        self.length = length
        self.value = value
        self.start = start
        self.end = end

    def children(self) -> list["_Node"]:
        if not self.constructed:
            return []
        return _parse_der_sequence(self.value)

    def __repr__(self):  # pragma: no cover - debug aid only
        return f"_Node(tag=0x{self.tag:02x}, len={self.length})"


def _read_one_tlv(data: bytes, pos: int) -> _Node:
    if pos >= len(data):
        raise ValueError("truncated DER: no tag byte")
    tag_byte = data[pos]
    class_ = tag_byte >> 6
    constructed = bool(tag_byte & 0x20)
    tag_num = tag_byte & 0x1F
    pos += 1
    if tag_num == 0x1F:
        raise ValueError("unsupported high-tag-number form")
    if pos >= len(data):
        raise ValueError("truncated DER: no length byte")
    length_byte = data[pos]
    pos += 1
    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes == 0:
            raise ValueError("indefinite-length DER not supported")
        if pos + num_len_bytes > len(data):
            raise ValueError("truncated DER: length bytes")
        length = int.from_bytes(data[pos : pos + num_len_bytes], "big")
        pos += num_len_bytes
    else:
        length = length_byte
    if pos + length > len(data):
        raise ValueError("truncated DER: value shorter than declared length")
    value = data[pos : pos + length]
    end = pos + length
    return _Node(tag_byte, constructed, class_, length, value, pos, end)


def _parse_der_sequence(data: bytes) -> list[_Node]:
    nodes = []
    pos = 0
    while pos < len(data):
        node = _read_one_tlv(data, pos)
        nodes.append(node)
        pos = node.end
    return nodes


def _der_read_integer(node: _Node) -> int:
    return int.from_bytes(node.value, "big", signed=True)


def _der_read_oid(node: _Node) -> str:
    b = node.value
    if not b:
        return ""
    first = b[0]
    out = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            out.append(str(val))
            val = 0
    return ".".join(out)


# ---------------------------------------------------------------------------
# TimeStampReq builder
# ---------------------------------------------------------------------------


def build_timestamp_request(
    digest: bytes,
    hash_alg: str = "sha256",
    nonce: int | None = None,
    cert_req: bool = True,
) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq.

    TimeStampReq ::= SEQUENCE {
        version         INTEGER { v1(1) },
        messageImprint  MessageImprint,
        reqPolicy       TSAPolicyId OPTIONAL,  -- omitted
        nonce           INTEGER OPTIONAL,
        certReq         BOOLEAN DEFAULT FALSE,
        extensions      [1] IMPLICIT Extensions OPTIONAL }  -- omitted
    """
    if hash_alg not in _HASH_OIDS:
        raise ValueError(f"unsupported hash_alg: {hash_alg}")
    oid = _HASH_OIDS[hash_alg]

    algorithm_identifier = _der_sequence(_der_oid(oid), _der_null())
    message_imprint = _der_sequence(algorithm_identifier, _der_octet_string(digest))

    parts = [_der_integer(1), message_imprint]
    if nonce is None:
        nonce = secrets.randbits(64)
    parts.append(_der_integer(nonce))
    parts.append(_der_boolean(cert_req))

    return _der_sequence(*parts)


# ---------------------------------------------------------------------------
# TimeStampResp / TimeStampToken / TSTInfo parser
# ---------------------------------------------------------------------------

_PKI_STATUS_NAMES = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}


def _find_generalized_time(nodes: list[_Node]) -> str | None:
    for n in nodes:
        if n.tag == _TAG_GENERALIZED_TIME:
            try:
                return n.value.decode("ascii")
            except Exception:
                return None
    return None


def _parse_tst_info(tst_info_der: bytes) -> dict:
    """TSTInfo ::= SEQUENCE {
    version, policy, messageImprint, serialNumber, genTime,
    accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL,
    tsa [0] GeneralName OPTIONAL, extensions [1] OPTIONAL }
    """
    out: dict[str, Any] = {
        "serial": None,
        "gen_time": None,
        "message_imprint_hash_alg": None,
        "message_imprint_hashed": None,
        "tsa_name": None,
    }
    top = _parse_der_sequence(tst_info_der)
    if not top or top[0].tag != _TAG_SEQUENCE:
        return out
    nodes = top[0].children()
    try:
        if len(nodes) > 2 and nodes[2].tag == _TAG_SEQUENCE:
            imprint_children = nodes[2].children()
            if imprint_children:
                alg_children = imprint_children[0].children()
                if alg_children:
                    out["message_imprint_hash_alg"] = _der_read_oid(alg_children[0])
            if len(imprint_children) > 1:
                out["message_imprint_hashed"] = imprint_children[1].value
        if len(nodes) > 3 and nodes[3].tag == _TAG_INTEGER:
            out["serial"] = hex(_der_read_integer(nodes[3]))
        if len(nodes) > 4 and nodes[4].tag == _TAG_GENERALIZED_TIME:
            out["gen_time"] = nodes[4].value.decode("ascii")
        else:
            out["gen_time"] = _find_generalized_time(nodes)
        for n in nodes:
            if n.class_ == 2 and (n.tag & 0x1F) == 0:
                try:
                    inner = n.children()
                    for c in inner:
                        if c.tag in (_TAG_UTF8_STRING, 0x16, 0x1E):
                            out["tsa_name"] = c.value.decode("utf-8", errors="replace")
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _extract_tstinfo_der(signed_data_node: _Node) -> bytes | None:
    """SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    certificates OPTIONAL, crls OPTIONAL, signerInfos }. We only need
    encapContentInfo.eContent's raw OCTET STRING payload, which IS the
    TSTInfo DER."""
    children = signed_data_node.children()
    for n in children:
        if n.tag == _TAG_SEQUENCE:
            inner = n.children()
            if inner and inner[0].tag == _TAG_OID:
                content_type = _der_read_oid(inner[0])
                if content_type != _ID_CT_TSTINFO_OID:
                    continue
                if len(inner) > 1 and inner[1].class_ == 2:
                    econtent_wrapper = inner[1]
                    inner_octets = econtent_wrapper.children()
                    if inner_octets and inner_octets[0].tag == _TAG_OCTET_STRING:
                        return inner_octets[0].value
    return None


def parse_timestamp_response(der: bytes) -> dict:
    """Parse a DER-encoded TimeStampResp far enough to answer: was it
    granted, what status, and (if granted) the TSTInfo's genTime/serial/
    messageImprint/best-effort TSA name. NEVER raises -- any parse failure
    returns {"granted": False, "reason": "..."} instead."""
    result: dict[str, Any] = {
        "granted": False,
        "status": None,
        "status_string": None,
        "gen_time": None,
        "serial": None,
        "tsa_name": None,
        "message_imprint_hash_alg": None,
        "message_imprint_hashed": None,
        "raw_token": None,
        "reason": None,
    }
    try:
        top = _parse_der_sequence(der)
        if not top or top[0].tag != _TAG_SEQUENCE:
            result["reason"] = "not_a_der_sequence"
            return result
        resp_children = top[0].children()
        if not resp_children:
            result["reason"] = "empty_response"
            return result
        pki_status_info = resp_children[0]
        status_children = pki_status_info.children()
        if not status_children or status_children[0].tag != _TAG_INTEGER:
            result["reason"] = "missing_status"
            return result
        status = _der_read_integer(status_children[0])
        result["status"] = status
        result["status_string"] = _PKI_STATUS_NAMES.get(status, f"unknown({status})")

        if status not in (0, 1):
            result["granted"] = False
            result["reason"] = f"tsa_status_{result['status_string']}"
            return result

        if len(resp_children) < 2:
            result["reason"] = "granted_status_but_no_token"
            return result

        token_content_info = resp_children[1]
        token_der = _der_tlv(token_content_info.tag, token_content_info.value)
        result["raw_token"] = token_der

        ci_children = token_content_info.children()
        if len(ci_children) < 2 or ci_children[0].tag != _TAG_OID:
            result["reason"] = "malformed_content_info"
            return result
        content_type = _der_read_oid(ci_children[0])
        if content_type != _ID_SIGNED_DATA_OID:
            result["reason"] = f"unexpected_content_type:{content_type}"
            return result
        explicit_wrapper = ci_children[1]
        wrapped = explicit_wrapper.children()
        if not wrapped or wrapped[0].tag != _TAG_SEQUENCE:
            result["reason"] = "malformed_signed_data_wrapper"
            return result
        signed_data_node = wrapped[0]

        tst_info_der = _extract_tstinfo_der(signed_data_node)
        if tst_info_der is None:
            result["granted"] = status in (0, 1)
            result["reason"] = "granted_but_tstinfo_not_found"
            return result

        info = _parse_tst_info(tst_info_der)
        result["gen_time"] = info.get("gen_time")
        result["serial"] = info.get("serial")
        result["tsa_name"] = info.get("tsa_name")
        result["message_imprint_hash_alg"] = info.get("message_imprint_hash_alg")
        result["message_imprint_hashed"] = info.get("message_imprint_hashed")
        result["granted"] = True
        return result
    except Exception as exc:
        result["granted"] = False
        result["reason"] = f"parse_error:{type(exc).__name__}"
        return result


# ---------------------------------------------------------------------------
# network transport (injectable opener -- tests never hit the network)
# ---------------------------------------------------------------------------


def _default_opener(req, timeout):  # pragma: no cover - thin urllib shim
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310


def request_timestamp(
    digest: bytes,
    tsa_url: str,
    timeout: int = 15,
    opener: Callable[[urllib.request.Request, int], Any] | None = None,
    hash_alg: str = "sha256",
    nonce: int | None = None,
) -> dict:
    """POST a TimeStampReq to `tsa_url` and parse the response.

    `opener(request, timeout) -> response` is injectable so tests never
    touch the network. Never raises -- any transport or parse failure
    returns {"granted": False, "reason": "..."}.
    """
    try:
        req_der = build_timestamp_request(digest, hash_alg=hash_alg, nonce=nonce)
    except Exception as exc:
        return {"granted": False, "reason": f"build_request_error:{type(exc).__name__}"}

    _scheme = urllib.parse.urlparse(tsa_url).scheme.lower()
    if _scheme not in ("http", "https"):
        return {"granted": False, "reason": f"unsupported_scheme:{_scheme or 'none'}"}

    request = urllib.request.Request(
        tsa_url,
        data=req_der,
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        },
        method="POST",
    )
    opener_fn = opener or _default_opener
    try:
        response = opener_fn(request, timeout)
        body = response.read()
    except urllib.error.URLError as exc:
        return {"granted": False, "reason": f"network_error:{exc}"}
    except Exception as exc:
        return {"granted": False, "reason": f"transport_error:{type(exc).__name__}"}

    parsed = parse_timestamp_response(body)
    parsed["tsa_url"] = tsa_url
    return parsed


def request_timestamp_multi(
    digest: bytes,
    tsa_urls: tuple[str, ...] = DEFAULT_TSA_URLS,
    timeout: int = 15,
    opener: Callable[[urllib.request.Request, int], Any] | None = None,
) -> tuple[dict, list[str]]:
    """Try each TSA in `tsa_urls` in order; return the first granted parse
    result plus the list of errors from any TSAs tried before it. Never
    raises -- a total failure returns the last (ungranted) parse result and
    the accumulated errors."""
    errors: list[str] = []
    last: dict = {"granted": False, "reason": "no_tsa_urls"}
    for url in tsa_urls:
        result = request_timestamp(digest, url, timeout=timeout, opener=opener)
        last = result
        if result.get("granted"):
            return result, errors
        errors.append(f"{url}: {result.get('reason')}")
    return last, errors


# ---------------------------------------------------------------------------
# token verification -- messageImprint match only (see module docstring)
# ---------------------------------------------------------------------------


def verify_timestamp_token(token_der: bytes, digest: bytes) -> dict:
    """Verify a TimeStampToken's messageImprint against `digest`.

    THIS IS MESSAGE-IMPRINT-MATCH-ONLY. It does NOT verify the TSA's CMS
    signature or certificate chain (that verification was intentionally
    dropped from this trimmed vendor -- see module docstring). A `True`
    result proves the token's imprint matches the digest that was sent;
    it does NOT prove TSA authorship. For full cryptographic
    authentication, use the untrimmed untrimmed internal module (needs
    `asn1crypto`) or run `openssl ts -verify` against the TSA's published
    certificate.
    """
    result = {
        "ok": False,
        "reason": None,
        "gen_time": None,
        "signature_verified": False,
        "note": "message-imprint match only -- no CMS signature/chain check in this trimmed vendor",
    }
    try:
        top = _parse_der_sequence(token_der)
        if not top or top[0].tag != _TAG_SEQUENCE:
            result["reason"] = "not_a_der_sequence"
            return result
        ci_children = top[0].children()
        if len(ci_children) < 2 or ci_children[0].tag != _TAG_OID:
            result["reason"] = "malformed_content_info"
            return result
        if _der_read_oid(ci_children[0]) != _ID_SIGNED_DATA_OID:
            result["reason"] = "not_signed_data"
            return result
        wrapped = ci_children[1].children()
        if not wrapped or wrapped[0].tag != _TAG_SEQUENCE:
            result["reason"] = "malformed_signed_data_wrapper"
            return result
        tst_info_der = _extract_tstinfo_der(wrapped[0])
        if tst_info_der is None:
            result["reason"] = "tstinfo_not_found"
            return result
        info = _parse_tst_info(tst_info_der)
        result["gen_time"] = info.get("gen_time")
        hashed = info.get("message_imprint_hashed")
        if hashed is None:
            result["reason"] = "no_message_imprint_in_token"
            return result
        if hashed != digest:
            result["reason"] = "imprint_mismatch"
            result["ok"] = False
            return result
        result["ok"] = True
        result["reason"] = "imprint_match"
        return result
    except Exception as exc:
        result["reason"] = f"parse_error:{type(exc).__name__}"
        return result
