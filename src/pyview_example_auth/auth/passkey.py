import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.parse_registration_credential_json import (
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .storage import StoredCredential, user_store
from .webauthn_config import get_expected_origin, get_rp_id, get_rp_name

passkey_app = FastAPI()


@passkey_app.post("/register/begin")
async def register_begin(request: Request):
    """Begin passkey registration - generate challenge and options."""
    body = await request.json()
    username = body.get("username", "").strip()

    if not username:
        return JSONResponse({"error": "Username is required"}, status_code=400)

    # Get or create user
    user_id = user_store.get_or_create_user(username)

    # Get existing credentials to exclude (prevent re-registration of same device)
    existing_credentials = user_store.get_user_credentials(user_id)
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=cred.credential_id)
        for cred in existing_credentials
    ]

    # Generate registration options
    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=get_rp_name(),
        user_id=user_id.encode(),
        user_name=username,
        user_display_name=username,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    # Store challenge in session for verification
    request.session["webauthn_register_challenge"] = bytes_to_base64url(options.challenge)
    request.session["webauthn_register_username"] = username

    return JSONResponse(json.loads(options_to_json(options)))


@passkey_app.post("/register/complete")
async def register_complete(request: Request):
    """Complete passkey registration - verify and store credential."""
    # Get stored challenge
    expected_challenge = request.session.get("webauthn_register_challenge")
    username = request.session.get("webauthn_register_username")

    if not expected_challenge or not username:
        return JSONResponse({"error": "Registration session expired"}, status_code=400)

    body = await request.json()

    try:
        # Parse the credential from the client
        credential = parse_registration_credential_json(json.dumps(body))

        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=get_rp_id(),
            expected_origin=get_expected_origin(),
        )

        # Store the credential
        user_id = user_store.get_or_create_user(username)
        stored_credential = StoredCredential(
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            user_id=user_id,
            username=username,
        )
        user_store.add_credential(stored_credential)

        # Clear registration session data
        del request.session["webauthn_register_challenge"]
        del request.session["webauthn_register_username"]

        return JSONResponse({"success": True, "message": "Passkey registered successfully"})

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@passkey_app.post("/authenticate/begin")
async def authenticate_begin(request: Request):
    """Begin passkey authentication - generate challenge."""
    body = await request.json()
    username = body.get("username", "").strip()

    # Optional: if username provided, restrict to that user's credentials
    allow_credentials = None
    if username:
        user_id = user_store.get_user_id(username)
        if user_id:
            credentials = user_store.get_user_credentials(user_id)
            allow_credentials = [
                PublicKeyCredentialDescriptor(id=cred.credential_id)
                for cred in credentials
            ]

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    # Store challenge for verification
    request.session["webauthn_auth_challenge"] = bytes_to_base64url(options.challenge)

    return JSONResponse(json.loads(options_to_json(options)))


@passkey_app.post("/authenticate/complete")
async def authenticate_complete(request: Request):
    """Complete passkey authentication - verify and create session."""
    expected_challenge = request.session.get("webauthn_auth_challenge")

    if not expected_challenge:
        return JSONResponse({"error": "Authentication session expired"}, status_code=400)

    body = await request.json()

    try:
        credential = parse_authentication_credential_json(json.dumps(body))

        # Find the stored credential
        stored_credential = user_store.get_credential(credential.raw_id)
        if not stored_credential:
            return JSONResponse({"error": "Unknown credential"}, status_code=400)

        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=get_rp_id(),
            expected_origin=get_expected_origin(),
            credential_public_key=stored_credential.public_key,
            credential_current_sign_count=stored_credential.sign_count,
        )

        # Update sign count
        user_store.update_sign_count(credential.raw_id, verification.new_sign_count)

        # Clear auth session data
        del request.session["webauthn_auth_challenge"]

        # Set user session (matching OAuth flow structure)
        request.session["user"] = {
            "name": stored_credential.username,
            "email": f"{stored_credential.username}@passkey.local",
            "picture": "",  # No picture for passkey users
            "auth_method": "passkey",
        }

        return JSONResponse({"success": True})

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)
