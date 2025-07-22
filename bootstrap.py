#!/usr/bin/env python3
"""
Bootstrap module for generating X3DH keys and DID documents
"""

import base64
import json
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from jwcrypto import jwk
from syft_core import Client

# Import shared utilities
from crypto_utils import did_path, private_key_path


def generate_did_web_id(email: str, domain: str = "syftbox.net") -> str:
    """Generate a did:web identifier from email"""
    encoded_email = urllib.parse.quote(email, safe="")
    return f"did:web:{domain}:{encoded_email}"


def key_to_jwk(public_key, key_id: str):
    """Convert a cryptography public key to JWK format using jwcrypto"""
    jwk_key = jwk.JWK.from_pyca(public_key)
    jwk_dict = jwk_key.export_public(as_dict=True)

    # Add metadata
    jwk_dict["kid"] = key_id
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        jwk_dict["use"] = "sig"
    elif isinstance(public_key, x25519.X25519PublicKey):
        jwk_dict["use"] = "enc"

    return jwk_dict


def create_did_document(
    email: str,
    domain: str,
    identity_public_key,
    signed_prekey_public_key,
    spk_signature: bytes,
):
    """Create a DID document with X3DH keys"""
    did_id = generate_did_web_id(email, domain)

    # Convert keys to JWK format
    identity_jwk = key_to_jwk(identity_public_key, "identity-key")
    spk_jwk = key_to_jwk(signed_prekey_public_key, "signed-prekey")

    # Add signature to the SPK
    spk_jwk["signature"] = base64.urlsafe_b64encode(spk_signature).decode().rstrip("=")

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1",
        ],
        "id": did_id,
        "verificationMethod": [
            {
                "id": f"{did_id}#identity-key",
                "type": "Ed25519VerificationKey2020",
                "controller": did_id,
                "publicKeyJwk": identity_jwk,
            }
        ],
        "keyAgreement": [
            {
                "id": f"{did_id}#signed-prekey",
                "type": "X25519KeyAgreementKey2020",
                "controller": did_id,
                "publicKeyJwk": spk_jwk,
            }
        ],
    }


def bootstrap_user(client: Client):
    """Generate X3DH keypairs and create DID document"""
    print(f"🔧 Bootstrapping user: {client.config.email}")

    # Generate Identity Key (long-term Ed25519 key pair)
    identity_private_key = ed25519.Ed25519PrivateKey.generate()
    identity_public_key = identity_private_key.public_key()

    # Generate Signed Pre Key (X25519 key pair)
    spk_private_key = x25519.X25519PrivateKey.generate()
    spk_public_key = spk_private_key.public_key()

    # Sign the Signed Pre Key with the Identity Key
    spk_public_bytes = spk_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    spk_signature = identity_private_key.sign(spk_public_bytes)

    # Save private keys securely as JWKs
    identity_jwk = jwk.JWK.from_pyca(identity_private_key)
    spk_jwk = jwk.JWK.from_pyca(spk_private_key)

    private_keys = {
        "identity_key": identity_jwk.export(as_dict=True),
        "signed_prekey": spk_jwk.export(as_dict=True),
    }

    pks_path = private_key_path(client)
    pks_path.parent.mkdir(parents=True, exist_ok=True)

    with open(pks_path, "w") as f:
        json.dump(private_keys, f, indent=2)

    # Create and save DID document
    did_doc = create_did_document(
        client.config.email,
        client.config.server_url.host,
        identity_public_key,
        spk_public_key,
        spk_signature,
    )

    did_file = did_path(client)
    did_file.parent.mkdir(parents=True, exist_ok=True)

    with open(did_file, "w") as f:
        json.dump(did_doc, f, indent=2)

    print(f"✅ Generated DID: {did_doc['id']}")
    print(f"📄 DID document saved to: {did_file}")
    print(f"🔐 Private keys saved to: {pks_path}")


if __name__ == "__main__":
    """Allow running bootstrap directly"""
    client = Client.load()
    key_path = private_key_path(client)
    if key_path.exists():
        print(f"✅ Private keys already exist for {client.config.email} at {key_path}")
    else:
        bootstrap_user(client)
