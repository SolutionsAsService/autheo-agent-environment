"""Decentralized identifiers for agents and principals: did:key (default) and did:web (optional).

* did:key (W3C CCG did:key v0.7 / Multikey): the DID *is* the Ed25519 public key,
  base58btc multibase of multicodec 0xed + 32 key bytes ("did:key:z6Mk..."). Anyone
  can create one offline; there is no registration, registry or issuer. Resolution
  is a pure function, so verification never needs the network.
* did:web (W3C CCG did:web): the DID document is a JSON file served over HTTPS.
  Resolution here is OFFLINE BY DEFAULT: documents come from an in-memory map or a
  local cache directory. Fetching is only attempted when allow_network=True.

A did:key cannot rotate: a new key is a new DID (see docs/SPEC-DID.md section 7 for the
rotation story). v1 key ids ("sha256:" + b64url(sha256(SPKI DER))) are hashes of the
same public key, so both identifiers are derivable from the key; a kid alone cannot
be turned back into a DID.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .multibase import (
    ED25519_PRIV,
    ED25519_PUB,
    X25519_PUB,
    multibase_decode,
    multibase_encode,
    multicodec_unwrap,
    multicodec_wrap,
)

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MULTIKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
JWS2020_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1"
RELATIONSHIPS = ("authentication", "assertionMethod", "capabilityDelegation", "capabilityInvocation")
DID_PATTERN = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._:%-]{1,512}$")
DID_KEY_PATTERN = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
DID_WEB_PATTERN = re.compile(r"^did:web:[A-Za-z0-9.-]+(%3A[0-9]{1,5})?(:[A-Za-z0-9._~%-]+)*$")
MAX_DID_DOCUMENT_BYTES = 65536
_P = 2**255 - 19


class DidError(ValueError):
    """Invalid DID, unresolvable DID or unusable verification method."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# ---------------------------------------------------------------------- did:key
def raw_public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_multibase(raw: bytes) -> str:
    if len(raw) != 32:
        raise DidError("invalidPublicKeyLength", "Ed25519 public keys are 32 bytes")
    return multibase_encode(multicodec_wrap(ED25519_PUB, raw))


def did_key_from_public(raw: bytes) -> str:
    return "did:key:" + public_multibase(raw)


def did_key_from_pem(pem: str) -> str:
    """Map a v1 SPKI PEM public key (passports, agent keys) to its did:key."""
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise DidError("invalidPublicKey", "only Ed25519 keys map to did:key in Autheo")
    return did_key_from_public(raw_public_bytes(key))


def decode_public_multibase(value: str) -> bytes:
    try:
        code, raw = multicodec_unwrap(multibase_decode(value))
    except ValueError as error:
        raise DidError("invalidPublicKey", str(error)) from error
    if code != ED25519_PUB:
        raise DidError("unsupportedPublicKeyType", f"multicodec 0x{code:x} is not ed25519-pub")
    if len(raw) != 32:
        raise DidError("invalidPublicKeyLength", "Ed25519 public keys are 32 bytes")
    return raw


def public_from_did_key(did: str) -> bytes:
    """Decode a did:key (Ed25519 only) to the raw 32-byte public key; raises DidError."""
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise DidError("invalidDid", "not a did:key")
    parts = did.split(":")
    if len(parts) != 3 or not parts[2].startswith("z"):
        raise DidError("invalidDid", "did:key must be did:key:z<base58btc>")
    raw = decode_public_multibase(parts[2])
    if did_key_from_public(raw) != did:
        raise DidError("invalidDid", "non-canonical did:key encoding")
    return raw


def v1_kid_for_did_key(did: str) -> str:
    """The v1 agent kid (Paperclip keyId format) of the key behind a did:key."""
    import base64

    key = Ed25519PublicKey.from_public_bytes(public_from_did_key(did))
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def x25519_from_ed25519(raw: bytes) -> bytes:
    """Birational map Edwards -> Montgomery: u = (1 + y) / (1 - y) mod p (RFC 7748 section 4.1)."""
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    if y >= _P or (1 - y) % _P == 0:
        raise DidError("invalidPublicKey", "Ed25519 point cannot be mapped to X25519")
    u = (1 + y) * pow((1 - y) % _P, _P - 2, _P) % _P
    return u.to_bytes(32, "little")


def did_key_document(did: str, *, encryption_key: bool = False) -> dict:
    """DID document for a did:key per the did:key Document Creation Algorithm (Multikey form)."""
    raw = public_from_did_key(did)
    fingerprint = did.split(":")[2]
    method = {"id": f"{did}#{fingerprint}", "type": "Multikey", "controller": did,
              "publicKeyMultibase": fingerprint}
    document = {
        "@context": [DID_CONTEXT, MULTIKEY_CONTEXT],
        "id": did,
        "verificationMethod": [method],
        **{relationship: [method["id"]] for relationship in RELATIONSHIPS},
    }
    if encryption_key:
        x_key = multibase_encode(multicodec_wrap(X25519_PUB, x25519_from_ed25519(raw)))
        agreement = {"id": f"{did}#{x_key}", "type": "Multikey", "controller": did, "publicKeyMultibase": x_key}
        document["verificationMethod"].append(agreement)
        document["keyAgreement"] = [agreement["id"]]
    return document


# ---------------------------------------------------------------------- did:web
def did_web_url(did: str) -> str:
    """did:web -> HTTPS URL of its DID document (did:web method specification section 3.2)."""
    if not isinstance(did, str) or not DID_WEB_PATTERN.match(did):
        raise DidError("invalidDid", "not a valid did:web")
    parts = did.split(":")[2:]
    host = unquote(parts[0])
    path = "/".join(unquote(p) for p in parts[1:])
    if any(segment in {"", ".", ".."} for segment in parts[1:]):
        raise DidError("invalidDid", "did:web path segments must be non-empty and not dot segments")
    return f"https://{host}/{path}/did.json" if path else f"https://{host}/.well-known/did.json"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # pragma: no cover - network only
        return None


def _fetch_https(url: str, timeout: float = 5.0) -> bytes:  # pragma: no cover - network only
    if not url.startswith("https://"):
        raise DidError("notFound", "did:web resolution requires HTTPS")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/did+json, application/json"})
    with opener.open(request, timeout=timeout) as response:
        data = response.read(MAX_DID_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DID_DOCUMENT_BYTES:
        raise DidError("notFound", "DID document too large")
    return data


def cache_file_name(did: str) -> str:
    return hashlib.sha256(did.encode()).hexdigest()[:40] + ".json"


# ---------------------------------------------------------------------- resolver
class Resolver:
    """Offline-first DID resolver.

    did:key is resolved locally. did:web documents come, in order, from the
    in-memory documents map, the cache directory, and - only if allow_network -
    an HTTPS fetch (no redirects, 64 KiB cap) whose result is written to the cache.
    """

    def __init__(self, *, documents: dict | None = None, cache_dir: Path | None = None,
                 allow_network: bool = False, fetch=None):
        self.documents = dict(documents or {})
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.allow_network = allow_network
        self._fetch = fetch or _fetch_https

    def resolve(self, did: str) -> dict:
        if not isinstance(did, str) or not DID_PATTERN.match(did):
            raise DidError("invalidDid", "malformed DID")
        if did.startswith("did:key:"):
            return did_key_document(did)
        if did.startswith("did:web:"):
            return self._resolve_web(did)
        raise DidError("methodNotSupported", did.split(":")[1])

    def _resolve_web(self, did: str) -> dict:
        url = did_web_url(did)
        if did in self.documents:
            document = self.documents[did]
        else:
            cached = self.cache_dir / cache_file_name(did) if self.cache_dir else None
            if cached is not None and cached.is_file():
                document = self._parse(cached.read_bytes())
            elif self.allow_network:
                data = self._fetch(url)
                document = self._parse(data)
                if cached is not None:
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    cached.write_bytes(data)
            else:
                raise DidError("notFound", f"did:web document not cached and network resolution is disabled ({url})")
        if not isinstance(document, dict) or document.get("id") != did:
            raise DidError("invalidDidDocument", "document id does not match the DID")
        return document

    @staticmethod
    def _parse(data: bytes) -> dict:
        if len(data) > MAX_DID_DOCUMENT_BYTES:
            raise DidError("invalidDidDocument", "DID document too large")
        try:
            return json.loads(data)
        except (ValueError, UnicodeDecodeError) as error:
            raise DidError("invalidDidDocument", "DID document is not JSON") from error

    def add_web_document(self, document: dict) -> str:
        """Validate a did:web document and store it in the cache (offline pinning)."""
        did = document.get("id") if isinstance(document, dict) else None
        if not isinstance(did, str) or not did.startswith("did:web:"):
            raise DidError("invalidDidDocument", "document id must be a did:web")
        did_web_url(did)
        for method in document.get("verificationMethod", []):
            _method_public_key(method)
        self.documents[did] = document
        if self.cache_dir is not None:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            (self.cache_dir / cache_file_name(did)).write_text(json.dumps(document, indent=2), encoding="utf-8")
        return did

    def public_key(self, verification_method: str, relationship: str) -> tuple[str, bytes]:
        """Return (controller DID, raw Ed25519 key) for a verification method authorised for relationship."""
        if relationship not in RELATIONSHIPS:
            raise DidError("invalidProofPurpose", relationship)
        if not isinstance(verification_method, str) or "#" not in verification_method:
            raise DidError("invalidVerificationMethod", "verification method must be a DID URL with a fragment")
        did = verification_method.split("#", 1)[0]
        document = self.resolve(did)
        methods = {}
        for method in document.get("verificationMethod", []) or []:
            if isinstance(method, dict) and isinstance(method.get("id"), str):
                methods[_absolute(did, method["id"])] = method
        authorised = False
        for entry in document.get(relationship, []) or []:
            if isinstance(entry, str) and _absolute(did, entry) == verification_method:
                authorised = True
            elif isinstance(entry, dict) and _absolute(did, entry.get("id", "")) == verification_method:
                authorised = True
                methods[verification_method] = entry
        if not authorised or verification_method not in methods:
            raise DidError("invalidVerificationMethod", f"{verification_method} is not authorised for {relationship}")
        method = methods[verification_method]
        if method.get("controller") != did:
            raise DidError("invalidVerificationMethod", "verification method controller differs from the DID")
        return did, _method_public_key(method)


def _absolute(did: str, reference: str) -> str:
    return did + reference if isinstance(reference, str) and reference.startswith("#") else reference


def _method_public_key(method: dict) -> bytes:
    kind = method.get("type")
    if kind in {"Multikey", "Ed25519VerificationKey2020"} and isinstance(method.get("publicKeyMultibase"), str):
        return decode_public_multibase(method["publicKeyMultibase"])
    if kind in {"JsonWebKey", "JsonWebKey2020"} and isinstance(method.get("publicKeyJwk"), dict):
        jwk = method["publicKeyJwk"]
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" in jwk:
            raise DidError("unsupportedPublicKeyType", "only public OKP Ed25519 JWKs are accepted")
        import base64

        x = jwk.get("x", "")
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)) if isinstance(x, str) else b""
        if len(raw) != 32:
            raise DidError("invalidPublicKeyLength", "Ed25519 public keys are 32 bytes")
        return raw
    raise DidError("unsupportedPublicKeyType", str(kind))


# ---------------------------------------------------------------------- key pairs
@dataclass(frozen=True)
class DidSigner:
    """A private key plus the DID and verification method it signs for."""

    did: str
    verification_method: str
    key: Ed25519PrivateKey

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)


@dataclass(frozen=True)
class DidKey:
    """An Ed25519 key pair and its did:key. Generating one requires nobody's permission."""

    key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> DidKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> DidKey:
        if len(seed) != 32:
            raise ValueError("Ed25519 seeds are 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_secret_multibase(cls, value: str) -> DidKey:
        code, seed = multicodec_unwrap(multibase_decode(value))
        if code != ED25519_PRIV or len(seed) != 32:
            raise ValueError("secretKeyMultibase must be ed25519-priv (0x1300) with a 32-byte seed")
        return cls.from_seed(seed)

    @classmethod
    def from_pem(cls, pem: str) -> DidKey:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Only Ed25519 private keys are accepted")
        return cls(key)

    @classmethod
    def load(cls, path: Path) -> DidKey:
        """Load a key file written by to_file_json() or an Ed25519 PKCS#8 PEM (v1 key files)."""
        text = Path(path).read_text(encoding="utf-8")
        if text.lstrip().startswith("-----BEGIN"):
            return cls.from_pem(text)
        data = json.loads(text)
        key = cls.from_secret_multibase(data["secretKeyMultibase"])
        if data.get("did") not in (None, key.did):
            raise ValueError("Key file DID does not match its secret key")
        return key

    @property
    def public_raw(self) -> bytes:
        return raw_public_bytes(self.key.public_key())

    @property
    def did(self) -> str:
        return did_key_from_public(self.public_raw)

    @property
    def verification_method(self) -> str:
        return f"{self.did}#{self.did.split(':')[2]}"

    @property
    def signer(self) -> DidSigner:
        return DidSigner(self.did, self.verification_method, self.key)

    def seed(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())

    def secret_multibase(self) -> str:
        return multibase_encode(multicodec_wrap(ED25519_PRIV, self.seed()))

    def to_file_json(self) -> dict:
        return {
            "type": "autheo.did-key-file/v2",
            "did": self.did,
            "publicKeyMultibase": self.did.split(":")[2],
            "secretKeyMultibase": self.secret_multibase(),
            "warning": "PRIVATE KEY. Unencrypted local file; protect it like a password.",
        }
