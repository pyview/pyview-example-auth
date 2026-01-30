import os

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.config import Config
from starlette.responses import RedirectResponse

from .passkey import passkey_app

auth_app = FastAPI()

# Mount passkey routes under /passkey prefix
auth_app.mount("/passkey", passkey_app)

# https://www.starlette.io/authentication/

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID") or None
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET") or None
if GOOGLE_CLIENT_ID is None or GOOGLE_CLIENT_SECRET is None:
    raise BaseException("Missing env variables")

config_data = {
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET,
}
starlette_config = Config(environ=config_data)
oauth = OAuth(starlette_config)

oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@auth_app.route("/login")
async def login(request: Request):
    return HTMLResponse(
        """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="flex items-center justify-center h-screen bg-gray-100">
    <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full">
        <h1 class="text-2xl font-bold text-center mb-6">Sign In</h1>

        <!-- Passkey Authentication Section -->
        <div id="passkey-section" class="mb-6">
            <div class="mb-4">
                <input
                    type="text"
                    id="username"
                    placeholder="Username"
                    class="w-full px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
            </div>

            <button
                id="passkey-login-btn"
                class="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded flex items-center justify-center mb-2"
            >
                <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 8a6 6 0 01-7.743 5.743L10 14l-1 1-1 1H6v2H2v-4l4.257-4.257A6 6 0 1118 8zm-6-4a1 1 0 100 2 2 2 0 012 2 1 1 0 102 0 4 4 0 00-4-4z" clip-rule="evenodd"/>
                </svg>
                Sign in with Passkey
            </button>

            <button
                id="passkey-register-btn"
                class="w-full bg-gray-200 hover:bg-gray-300 text-gray-700 font-bold py-2 px-4 rounded flex items-center justify-center"
            >
                <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/>
                </svg>
                Register New Passkey
            </button>
        </div>

        <div class="relative flex items-center justify-center my-6">
            <div class="border-t border-gray-300 flex-grow"></div>
            <span class="px-4 text-gray-500 text-sm">OR</span>
            <div class="border-t border-gray-300 flex-grow"></div>
        </div>

        <!-- Google OAuth Section -->
        <div class="text-center">
            <a href="/auth/google_login" class="bg-white border border-gray-300 hover:bg-gray-100 text-gray-700 font-bold py-2 px-4 rounded flex items-center justify-center w-full">
                <svg width="24" height="24" viewBox="0 0 48 48">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"></path>
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"></path>
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"></path>
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"></path>
                </svg>
                &nbsp; Sign in with Google
            </a>
        </div>

        <!-- Status/Error messages -->
        <div id="status-message" class="mt-4 text-center hidden"></div>
    </div>

    <script>
    // WebAuthn Helper Functions
    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const byte of bytes) {
            str += String.fromCharCode(byte);
        }
        return btoa(str).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
    }

    function base64urlToBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padLen = (4 - (base64.length % 4)) % 4;
        const padded = base64 + '='.repeat(padLen);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function showStatus(message, isError = false) {
        const statusEl = document.getElementById('status-message');
        statusEl.textContent = message;
        statusEl.className = 'mt-4 text-center p-2 rounded ' +
            (isError ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700');
        statusEl.classList.remove('hidden');
    }

    // Check WebAuthn support
    if (!window.PublicKeyCredential) {
        document.getElementById('passkey-section').innerHTML =
            '<p class="text-gray-500 text-center">Passkeys are not supported in this browser.</p>';
    }

    // Register Passkey
    document.getElementById('passkey-register-btn')?.addEventListener('click', async () => {
        const username = document.getElementById('username').value.trim();
        if (!username) {
            showStatus('Please enter a username', true);
            return;
        }

        try {
            // 1. Get registration options from server
            const optionsRes = await fetch('/auth/passkey/register/begin', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username})
            });
            const options = await optionsRes.json();

            if (options.error) {
                showStatus(options.error, true);
                return;
            }

            // 2. Convert options for browser API
            options.challenge = base64urlToBuffer(options.challenge);
            options.user.id = base64urlToBuffer(options.user.id);
            if (options.excludeCredentials) {
                options.excludeCredentials = options.excludeCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }

            // 3. Create credential via browser
            const credential = await navigator.credentials.create({publicKey: options});

            // 4. Prepare response for server
            const credentialJSON = {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64url(credential.response.attestationObject),
                },
            };

            if (credential.response.getTransports) {
                credentialJSON.response.transports = credential.response.getTransports();
            }

            // 5. Complete registration on server
            const verifyRes = await fetch('/auth/passkey/register/complete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(credentialJSON)
            });
            const result = await verifyRes.json();

            if (result.success) {
                showStatus('Passkey registered! You can now sign in.');
            } else {
                showStatus(result.error || 'Registration failed', true);
            }
        } catch (err) {
            showStatus('Registration error: ' + err.message, true);
        }
    });

    // Authenticate with Passkey
    document.getElementById('passkey-login-btn')?.addEventListener('click', async () => {
        const username = document.getElementById('username').value.trim();

        try {
            // 1. Get authentication options
            const optionsRes = await fetch('/auth/passkey/authenticate/begin', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username})
            });
            const options = await optionsRes.json();

            if (options.error) {
                showStatus(options.error, true);
                return;
            }

            // 2. Convert for browser API
            options.challenge = base64urlToBuffer(options.challenge);
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id)
                }));
            }

            // 3. Get credential from authenticator
            const credential = await navigator.credentials.get({publicKey: options});

            // 4. Prepare response
            const credentialJSON = {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                    signature: bufferToBase64url(credential.response.signature),
                },
            };

            if (credential.response.userHandle) {
                credentialJSON.response.userHandle = bufferToBase64url(credential.response.userHandle);
            }

            // 5. Verify on server
            const verifyRes = await fetch('/auth/passkey/authenticate/complete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(credentialJSON)
            });
            const result = await verifyRes.json();

            if (result.success) {
                window.location.href = '/';
            } else {
                showStatus(result.error || 'Authentication failed', true);
            }
        } catch (err) {
            showStatus('Authentication error: ' + err.message, true);
        }
    });
    </script>
</body>
</html>
    """
    )


@auth_app.route("/google_login")
async def google_login(request: Request):
    redirect_uri = request.url_for("auth")
    assert oauth.google is not None
    return await oauth.google.authorize_redirect(request, redirect_uri)


@auth_app.route("/logout")
async def logout(request: Request):
    request.scope["session"] = None
    return RedirectResponse(url="/")


@auth_app.route("/auth")
async def auth(request: Request):
    try:
        assert oauth.google is not None
        access_token = await oauth.google.authorize_access_token(request)
        request.session["user"] = access_token["userinfo"]
    except OAuthError:
        return RedirectResponse(url="/")

    return RedirectResponse(url="/")
