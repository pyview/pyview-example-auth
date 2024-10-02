from pyview import LiveView, LiveViewSocket
from typing import TypedDict
from pyview.auth import requires


class User(TypedDict):
    name: str
    email: str
    picture: str


class ProfileContext(TypedDict):
    user: User


@requires("authenticated", redirect="login")
class ProfileLiveView(LiveView[ProfileContext]):
    async def mount(self, socket: LiveViewSocket[ProfileContext], session):
        socket.context = ProfileContext({"user": session["user"]})
