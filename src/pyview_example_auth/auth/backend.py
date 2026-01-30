from starlette.authentication import AuthCredentials, AuthenticationBackend, SimpleUser


class GoogleInfoBackend(AuthenticationBackend):
    """Authentication backend supporting both OAuth and Passkey sessions."""

    async def authenticate(self, conn):
        if "user" in conn.session:
            user = conn.session["user"]
            scopes = ["authenticated"]

            # Add auth method specific scope if available
            auth_method = user.get("auth_method", "oauth")
            scopes.append(f"auth:{auth_method}")

            return AuthCredentials(scopes), SimpleUser(user["name"])
