import os

# WebAuthn Relying Party configuration
# These should be set via environment variables in production

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "PyView Example Auth")
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:7100")


def get_rp_id() -> str:
    return RP_ID


def get_rp_name() -> str:
    return RP_NAME


def get_expected_origin() -> str:
    return ORIGIN
