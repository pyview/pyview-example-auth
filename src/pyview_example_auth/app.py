from fastapi.staticfiles import StaticFiles
from pyview import PyView, defaultRootTemplate
from pyview.secret import get_secret

from markupsafe import Markup
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import RedirectResponse

from .views import ProfileLiveView
from .auth import GoogleInfoBackend, auth_app


css = """
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.11.1/dist/full.min.css" rel="stylesheet" type="text/css" />
<script src="https://cdn.tailwindcss.com"></script>     
"""

app = PyView()
app.rootTemplate = defaultRootTemplate(css=Markup(css))

app.add_middleware(AuthenticationMiddleware, backend=GoogleInfoBackend())
app.add_middleware(SessionMiddleware, secret_key=get_secret())

app.mount("/auth", auth_app)

app.mount("/static", StaticFiles(packages=[("pyview", "static")]), name="static")

app.add_live_view("/profile", ProfileLiveView)


@app.route("/")
async def index(request):
    return RedirectResponse("/profile")
