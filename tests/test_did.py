"""did:key / did:web / multibase / JCS / Data Integrity (eddsa-jcs-2022) against published vectors."""

from __future__ import annotations

import base64
import copy
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from autheo_agent_environment.data_integrity import (
    ProofError,
    add_proof,
    format_time,
    hash_data,
    parse_time,
    verify_proof,
)
from autheo_agent_environment.did import (
    DidError,
    DidKey,
    Resolver,
    did_key_document,
    did_key_from_pem,
    did_key_from_public,
    did_web_url,
    public_from_did_key,
    v1_kid_for_did_key,
)
from autheo_agent_environment.jcs import canonicalize, jcs_digest
from autheo_agent_environment.multibase import (
    b58decode,
    b58encode,
    multibase_decode,
    varint_decode,
    varint_encode,
)
from autheo_agent_environment.signing import key_fingerprint, public_pem

# W3C Data Integrity EdDSA Cryptosuites v1.0, Appendix B.3 (eddsa-jcs-2022) - verbatim values.
W3C_SECRET = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
W3C_PUBLIC = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
W3C_CREDENTIAL = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
}
W3C_DOC_HASH = "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
W3C_PROOF_HASH = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db"
W3C_SIGNATURE_HEX = ("407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b80351da3f253d725c6f00b07c9e"
                     "5448d50b3ef78012b9ab54255116d069c6dd2808")
W3C_PROOF_VALUE = "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"


# ---------------------------------------------------------------------- base58 / varint
@pytest.mark.parametrize("data, encoded", [
    # draft-msporny-base58-03 section 5 test vectors
    (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
    (b"The quick brown fox jumps over the lazy dog.", "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"),
    (bytes.fromhex("0000287fb4cd"), "11233QC4"),
    (b"", ""),
    (b"\0", "1"),
])
def test_base58_draft_vectors(data, encoded):
    assert b58encode(data) == encoded
    assert b58decode(encoded) == data


@given(st.binary(max_size=80))
def test_base58_round_trip(data):
    assert b58decode(b58encode(data)) == data


@pytest.mark.parametrize("bad", ["0OIl", "abc!", "z" * 8193])  # bound = multibase.MAX_ENCODED
def test_base58_rejects_invalid(bad):
    with pytest.raises(ValueError):
        b58decode(bad)


def test_multibase_requires_base58btc():
    with pytest.raises(ValueError):
        multibase_decode("mAAAA")
    with pytest.raises(ValueError):
        multibase_decode("z")


@pytest.mark.parametrize("value, encoded", [(0, "00"), (1, "01"), (127, "7f"), (128, "8001"), (0xED, "ed01"),
                                            (0xEC, "ec01"), (0x1300, "8026"), (16384, "808001")])
def test_unsigned_varint_vectors(value, encoded):
    assert varint_encode(value).hex() == encoded
    assert varint_decode(bytes.fromhex(encoded)) == (value, len(encoded) // 2)


def test_varint_rejects_overlong_and_truncated():
    with pytest.raises(ValueError):
        varint_decode(bytes.fromhex("8000"))  # non-minimal zero continuation
    with pytest.raises(ValueError):
        varint_decode(bytes.fromhex("80"))
    with pytest.raises(ValueError):
        varint_encode(-1)


# ---------------------------------------------------------------------- did:key
def test_w3c_multikey_pair_maps_to_did_key():
    key = DidKey.from_secret_multibase(W3C_SECRET)
    assert key.did == "did:key:" + W3C_PUBLIC
    assert key.secret_multibase() == W3C_SECRET
    assert key.verification_method == f"did:key:{W3C_PUBLIC}#{W3C_PUBLIC}"


def test_did_key_spec_document_and_x25519_derivation():
    did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    document = did_key_document(did, encryption_key=True)
    method_id = f"{did}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    assert document["verificationMethod"][0] == {
        "id": method_id, "type": "Multikey", "controller": did,
        "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}
    for relationship in ("authentication", "assertionMethod", "capabilityDelegation", "capabilityInvocation"):
        assert document[relationship] == [method_id]
    # did:key specification "Ed25519 with X25519" example.
    assert document["keyAgreement"] == [f"{did}#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"]
    assert "keyAgreement" not in did_key_document(did)


@settings(max_examples=40)
@given(st.binary(min_size=32, max_size=32))
def test_did_key_round_trip_for_any_seed(seed):
    key = DidKey.from_seed(seed)
    assert key.did.startswith("did:key:z6Mk")
    assert public_from_did_key(key.did) == key.public_raw
    assert DidKey.from_secret_multibase(key.secret_multibase()).did == key.did


@pytest.mark.parametrize("bad", [
    "did:key:z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",  # X25519 key, not Ed25519
    "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",  # secp256k1
    "did:key:mAAAA", "did:key:z6Mk", "did:web:example.com", "did:key:1:z6Mk", "nope",
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do",  # truncated
])
def test_did_key_rejects_other_methods_codecs_and_lengths(bad):
    with pytest.raises(DidError):
        public_from_did_key(bad)


def test_v1_key_ids_map_to_the_same_did_key():
    key = DidKey.from_seed(bytes(range(32)))
    pem = public_pem(key.key.public_key())
    assert did_key_from_pem(pem) == key.did
    assert v1_kid_for_did_key(key.did) == key_fingerprint(key.key.public_key())


def test_key_files_round_trip_json_and_pem(tmp_path):
    from autheo_agent_environment.signing import private_pem

    key = DidKey.generate()
    (tmp_path / "k.json").write_text(json.dumps(key.to_file_json()))
    (tmp_path / "k.pem").write_text(private_pem(key.key))
    assert DidKey.load(tmp_path / "k.json").did == key.did
    assert DidKey.load(tmp_path / "k.pem").did == key.did
    data = key.to_file_json()
    data["did"] = DidKey.generate().did
    (tmp_path / "bad.json").write_text(json.dumps(data))
    with pytest.raises(ValueError):
        DidKey.load(tmp_path / "bad.json")
    with pytest.raises(ValueError):
        DidKey.from_secret_multibase("z" + b58encode(b"\xed\x01" + bytes(32)))
    with pytest.raises(ValueError):
        DidKey.from_seed(b"short")


# ---------------------------------------------------------------------- did:web
@pytest.mark.parametrize("did, url", [
    # did:web method specification examples
    ("did:web:w3c-ccg.github.io", "https://w3c-ccg.github.io/.well-known/did.json"),
    ("did:web:w3c-ccg.github.io:user:alice", "https://w3c-ccg.github.io/user/alice/did.json"),
    ("did:web:example.com%3A3000:user:alice", "https://example.com:3000/user/alice/did.json"),
])
def test_did_web_url_mapping(did, url):
    assert did_web_url(did) == url


@pytest.mark.parametrize("bad", ["did:web:", "did:web:exa mple.com", "did:web:example.com:..", "did:key:z6Mk"])
def test_did_web_rejects_bad_identifiers(bad):
    with pytest.raises(DidError):
        did_web_url(bad)


def _web_document(did: str, key: DidKey, *, jwk: bool = False) -> dict:
    method = {"id": f"{did}#key-1", "type": "Multikey", "controller": did,
              "publicKeyMultibase": key.did.split(":")[2]}
    if jwk:
        x = base64.urlsafe_b64encode(key.public_raw).rstrip(b"=").decode()
        method = {"id": "#key-1", "type": "JsonWebKey2020", "controller": did,
                  "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}
    return {"@context": ["https://www.w3.org/ns/did/v1"], "id": did, "verificationMethod": [method],
            "assertionMethod": [method["id"]], "capabilityDelegation": [method["id"]]}


def test_did_web_is_offline_by_default_and_never_fetches():
    calls = []
    resolver = Resolver(fetch=lambda url: calls.append(url))
    with pytest.raises(DidError) as error:
        resolver.resolve("did:web:example.com:alice")
    assert error.value.code == "notFound" and calls == []


def test_did_web_cache_pinning_and_signing(tmp_path):
    did, key = "did:web:example.com:alice", DidKey.generate()
    resolver = Resolver(cache_dir=tmp_path)
    resolver.add_web_document(_web_document(did, key))
    fresh = Resolver(cache_dir=tmp_path)  # reads the cache file, still no network
    assert fresh.resolve(did)["id"] == did
    from autheo_agent_environment.did import DidSigner

    signer = DidSigner(did, f"{did}#key-1", key.key)
    signed = add_proof({"hello": "world"}, signer, "assertionMethod", 1_790_000_000)
    assert verify_proof(signed, fresh, "assertionMethod").controller == did
    with pytest.raises(ProofError) as error:  # not listed under authentication
        verify_proof(add_proof({"a": 1}, signer, "authentication", 1_790_000_000), fresh, "authentication")
    assert error.value.code == "bad_verification_method"


def test_did_web_jwk_methods_relative_ids_and_mock_fetch(tmp_path):
    did, key = "did:web:example.org", DidKey.generate()
    document = _web_document(did, key, jwk=True)
    fetched = []

    def fetch(url):
        fetched.append(url)
        return json.dumps(document).encode()

    resolver = Resolver(cache_dir=tmp_path, allow_network=True, fetch=fetch)
    assert resolver.public_key(f"{did}#key-1", "assertionMethod") == (did, key.public_raw)
    assert fetched == ["https://example.org/.well-known/did.json"]
    assert Resolver(cache_dir=tmp_path).resolve(did)["id"] == did  # cached after the fetch


@pytest.mark.parametrize("mutate, code", [
    (lambda d: d.update(id="did:web:evil.example"), "invalidDidDocument"),
    (lambda d: d["verificationMethod"][0].update(controller="did:web:other.example"), "invalidVerificationMethod"),
    (lambda d: d["verificationMethod"][0].update(type="EcdsaSecp256k1VerificationKey2019"), "unsupportedPublicKeyType"),
    (lambda d: d.update(capabilityDelegation=[]), "invalidVerificationMethod"),
])
def test_did_web_document_problems_are_rejected(mutate, code):
    did, key = "did:web:example.net", DidKey.generate()
    document = _web_document(did, key)
    mutate(document)
    resolver = Resolver(documents={did: document})
    with pytest.raises(DidError) as error:
        resolver.public_key(f"{did}#key-1", "capabilityDelegation")
    assert error.value.code == code


def test_resolver_rejects_unknown_methods_and_bad_urls():
    with pytest.raises(DidError):
        Resolver().resolve("did:example:123")
    with pytest.raises(DidError):
        Resolver().public_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "assertionMethod")
    with pytest.raises(DidError):
        Resolver().public_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#x", "keyAgreement")


# ---------------------------------------------------------------------- JCS (RFC 8785)
def test_rfc8785_sorting_example():
    value = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
             "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control",
             "\u00f6": "Latin Small Letter O With Diaeresis"}
    keys = [k for k in json.loads(canonicalize(value))]
    assert keys == ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]


def test_rfc8785_string_escaping_example():
    value = {"string": "\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\"/", "literals": [None, True, False]}
    assert canonicalize(value) == ('{"literals":[null,true,false],"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
                                   ).encode("utf-8")


@pytest.mark.parametrize("bad", [1.5, float("nan"), 2**53, {"a": {1: 2}}, "\ud800", object()])
def test_jcs_profile_rejections(bad):
    with pytest.raises(ValueError):
        canonicalize(bad)


json_values = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1)
    | st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(
        st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=6), children, max_size=4),
    max_leaves=20,
)


@settings(max_examples=150)
@given(json_values)
def test_jcs_is_valid_json_and_idempotent(value):
    data = canonicalize(value)
    assert json.loads(data) == value
    assert canonicalize(json.loads(data)) == data
    assert jcs_digest(value) == jcs_digest(json.loads(data))


# ---------------------------------------------------------------------- Data Integrity eddsa-jcs-2022
def test_w3c_eddsa_jcs_2022_example_reproduces_byte_for_byte():
    import hashlib

    key = DidKey.from_secret_multibase(W3C_SECRET)
    assert hashlib.sha256(canonicalize(W3C_CREDENTIAL)).hexdigest() == W3C_DOC_HASH
    proof_options = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                     "created": "2023-02-24T23:36:38Z", "verificationMethod": key.verification_method,
                     "proofPurpose": "assertionMethod", "@context": W3C_CREDENTIAL["@context"]}
    assert hash_data(W3C_CREDENTIAL, proof_options).hex() == W3C_PROOF_HASH + W3C_DOC_HASH
    signed = add_proof(W3C_CREDENTIAL, key.signer, "assertionMethod", parse_time("2023-02-24T23:36:38Z"))
    assert key.key.sign(bytes.fromhex(W3C_PROOF_HASH + W3C_DOC_HASH)).hex() == W3C_SIGNATURE_HEX
    assert signed["proof"]["proofValue"] == W3C_PROOF_VALUE
    assert verify_proof(signed, Resolver(), "assertionMethod").controller == key.did


@pytest.mark.parametrize("mutate, code", [
    (lambda d: d.update(name="Forged"), "bad_signature"),
    (lambda d: d["credentialSubject"].update(alumniOf="Elsewhere"), "bad_signature"),
    (lambda d: d["proof"].update(created="2023-02-24T23:36:39Z"), "bad_signature"),
    (lambda d: d["proof"].update(proofPurpose="authentication"), "bad_proof"),
    (lambda d: d["proof"].update(cryptosuite="eddsa-rdfc-2022"), "bad_proof"),
    (lambda d: d["proof"].update(nonce="x"), "bad_proof"),
    (lambda d: d["proof"].update(created="2023-02-24 23:36:38"), "bad_proof"),
    (lambda d: d["proof"].update(proofValue="z" + b58encode(b"\1" * 63)), "bad_proof"),
    (lambda d: d["proof"].update(verificationMethod="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                                 "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), "bad_signature"),
    (lambda d: d.update({"@context": ["https://www.w3.org/ns/credentials/v2"]}), "bad_proof"),
    (lambda d: d.pop("proof"), "bad_proof"),
])
def test_tampered_or_misused_proofs_fail(mutate, code):
    key = DidKey.from_secret_multibase(W3C_SECRET)
    signed = copy.deepcopy(add_proof(W3C_CREDENTIAL, key.signer, "assertionMethod", 1_677_281_798))
    mutate(signed)
    with pytest.raises(ProofError) as error:
        verify_proof(signed, Resolver(), "assertionMethod")
    assert error.value.code == code


def test_add_proof_rejects_already_secured_documents_and_bad_times():
    key = DidKey.generate()
    with pytest.raises(ValueError):
        add_proof({"proof": {}}, key.signer, "assertionMethod", 1)
    with pytest.raises(ValueError):
        format_time(-1)
    with pytest.raises(ValueError):
        parse_time("2026-01-01T00:00:00+00:00")
    assert parse_time(format_time(1_790_000_000)) == 1_790_000_000
    with pytest.raises(ProofError):
        verify_proof("not a dict", Resolver(), "assertionMethod")


def test_documents_without_context_sign_without_proof_context():
    key = DidKey.generate()
    signed = add_proof({"type": "Thing", "n": 1}, key.signer, "capabilityInvocation", 1_790_000_000)
    assert "@context" not in signed["proof"]
    assert verify_proof(signed, Resolver(), "capabilityInvocation").controller == key.did
    assert did_key_from_public(key.public_raw) == key.did
