"""Helpers to drive real WebAuthn registration/authentication ceremonies in tests
using a software authenticator (soft_webauthn), mirroring what app/static/webauthn.js
does in the browser: decode base64url options to bytes before handing them to the
authenticator, then re-encode the authenticator's response back to base64url JSON.
"""

import base64

from soft_webauthn import SoftWebauthnDevice


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def decode_creation_options(pk: dict) -> dict:
    pk = dict(pk)
    pk["challenge"] = b64url_decode(pk["challenge"])
    pk["user"] = dict(pk["user"])
    pk["user"]["id"] = b64url_decode(pk["user"]["id"])
    pk["excludeCredentials"] = [
        {**c, "id": b64url_decode(c["id"])} for c in pk.get("excludeCredentials", [])
    ]
    return {"publicKey": pk}


def decode_request_options(pk: dict) -> dict:
    pk = dict(pk)
    pk["challenge"] = b64url_decode(pk["challenge"])
    pk["allowCredentials"] = [
        {**c, "id": b64url_decode(c["id"])} for c in pk.get("allowCredentials", [])
    ]
    return {"publicKey": pk}


def encode_credential(cred: dict) -> dict:
    response = {"clientDataJSON": b64url_encode(cred["response"]["clientDataJSON"])}
    if "attestationObject" in cred["response"]:
        response["attestationObject"] = b64url_encode(cred["response"]["attestationObject"])
    if "authenticatorData" in cred["response"]:
        response["authenticatorData"] = b64url_encode(cred["response"]["authenticatorData"])
        response["signature"] = b64url_encode(cred["response"]["signature"])
        if cred["response"].get("userHandle"):
            response["userHandle"] = b64url_encode(cred["response"]["userHandle"])
    return {
        "id": b64url_encode(cred["rawId"]),
        "rawId": b64url_encode(cred["rawId"]),
        "type": cred["type"],
        "response": response,
    }


def register_via_invite(client, token: str, device: SoftWebauthnDevice, nickname: str = "test-device", origin: str = "http://testserver"):
    r = client.post(f"/register/{token}/begin")
    r.raise_for_status()
    begin = r.json()
    options = decode_creation_options(begin["publicKey"])
    attestation = device.create(options, origin)
    r = client.post(
        f"/register/{token}/complete",
        json={"state": begin["state"], "credential": encode_credential(attestation), "nickname": nickname},
    )
    return r


def login_with_device(client, device: SoftWebauthnDevice, origin: str = "http://testserver"):
    r = client.post("/webauthn/authenticate/begin")
    r.raise_for_status()
    begin = r.json()
    options = decode_request_options(begin["publicKey"])
    assertion = device.get(options, origin)
    r = client.post(
        "/webauthn/authenticate/complete",
        json={"state": begin["state"], "credential": encode_credential(assertion)},
    )
    return r


def add_passkey_authenticated(client, device: SoftWebauthnDevice, nickname: str = "second-device", origin: str = "http://testserver"):
    r = client.post("/profile/passkeys/begin")
    r.raise_for_status()
    begin = r.json()
    options = decode_creation_options(begin["publicKey"])
    attestation = device.create(options, origin)
    r = client.post(
        "/profile/passkeys/complete",
        json={"state": begin["state"], "credential": encode_credential(attestation), "nickname": nickname},
    )
    return r
