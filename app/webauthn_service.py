import os
import secrets
import time
from typing import Any, Optional

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json_dict
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_ID = os.environ.get("RP_ID", "example.com")
RP_NAME = os.environ.get("RP_NAME", "Cerberus")
ORIGIN = os.environ.get("ORIGIN", "https://example.com")

CHALLENGE_TTL_SECONDS = 300

# In-memory store for in-flight ceremony challenges. Fine for a single uvicorn
# process (see Dockerfile CMD); would need a shared store behind >1 worker.
_challenges: dict[str, dict[str, Any]] = {}


def _stash_challenge(challenge: bytes, user_id: Optional[int] = None) -> str:
    state = secrets.token_urlsafe(16)
    _prune_expired()
    _challenges[state] = {
        "challenge": challenge,
        "user_id": user_id,
        "expires": time.time() + CHALLENGE_TTL_SECONDS,
    }
    return state


def _pop_challenge(state: str) -> Optional[dict[str, Any]]:
    entry = _challenges.pop(state, None)
    if entry is None or entry["expires"] < time.time():
        return None
    return entry


def _prune_expired():
    now = time.time()
    expired = [k for k, v in _challenges.items() if v["expires"] < now]
    for k in expired:
        _challenges.pop(k, None)


def build_registration_options(user_row, existing_credential_ids: list[bytes]) -> dict:
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_row["id"]).encode(),
        user_name=user_row["username"],
        user_display_name=user_row["display_name"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cred_id) for cred_id in existing_credential_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    state = _stash_challenge(options.challenge, user_id=user_row["id"])
    return {"publicKey": options_to_json_dict(options), "state": state}


def verify_registration(state: str, expected_user_id: int, credential: dict):
    entry = _pop_challenge(state)
    if entry is None or entry["user_id"] != expected_user_id:
        raise InvalidRegistrationResponse("Registration ceremony expired or invalid")
    return verify_registration_response(
        credential=credential,
        expected_challenge=entry["challenge"],
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
    )


def build_authentication_options() -> dict:
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    state = _stash_challenge(options.challenge)
    return {"publicKey": options_to_json_dict(options), "state": state}


def verify_authentication(state: str, credential: dict, credential_public_key: bytes, current_sign_count: int):
    entry = _pop_challenge(state)
    if entry is None:
        raise InvalidAuthenticationResponse("Authentication ceremony expired or invalid")
    return verify_authentication_response(
        credential=credential,
        expected_challenge=entry["challenge"],
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        credential_public_key=credential_public_key,
        credential_current_sign_count=current_sign_count,
    )


__all__ = [
    "base64url_to_bytes",
    "build_registration_options",
    "verify_registration",
    "build_authentication_options",
    "verify_authentication",
]
