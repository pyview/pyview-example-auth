from typing import Optional, TypedDict

from pyview import LiveView, LiveViewSocket
from pyview.auth import requires


class User(TypedDict):
    name: str
    email: str
    picture: str
    auth_method: Optional[str]


class ProfileContext(TypedDict):
    user: User


@requires("authenticated", redirect="login")
class ProfileLiveView(LiveView[ProfileContext]):
    async def mount(self, socket: LiveViewSocket[ProfileContext], session):
        user_data = session["user"]
        # Ensure all expected fields exist with defaults
        user = User(
            name=user_data.get("name", "Unknown"),
            email=user_data.get("email", ""),
            picture=user_data.get("picture", ""),
            auth_method=user_data.get("auth_method"),
        )
        socket.context = ProfileContext(user=user)
