from starlette.authentication import AuthCredentials, AuthenticationBackend, SimpleUser


class GoogleInfoBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        if "user" in conn.session:
            user = conn.session["user"]
            return AuthCredentials(["authenticated"]), SimpleUser(user["name"])
