from dataclasses import dataclass
from typing import Optional


@dataclass
class StoredCredential:
    """Represents a stored passkey credential."""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    user_id: str
    username: str


class UserStore:
    """In-memory storage for users and their passkey credentials."""

    def __init__(self):
        # Map: username -> user_id
        self._users: dict[str, str] = {}
        # Map: credential_id (as hex) -> StoredCredential
        self._credentials: dict[str, StoredCredential] = {}
        # Map: user_id -> list of credential_ids (as hex)
        self._user_credentials: dict[str, list[str]] = {}
        # Counter for generating user IDs
        self._user_counter: int = 0

    def get_or_create_user(self, username: str) -> str:
        """Get existing user_id or create new user."""
        if username not in self._users:
            self._user_counter += 1
            user_id = f"user_{self._user_counter}"
            self._users[username] = user_id
            self._user_credentials[user_id] = []
        return self._users[username]

    def get_user_id(self, username: str) -> Optional[str]:
        """Get user_id for username, or None if not exists."""
        return self._users.get(username)

    def get_username_by_user_id(self, user_id: str) -> Optional[str]:
        """Get username for user_id, or None if not exists."""
        for username, uid in self._users.items():
            if uid == user_id:
                return username
        return None

    def add_credential(self, credential: StoredCredential) -> None:
        """Store a new credential."""
        cred_id_hex = credential.credential_id.hex()
        self._credentials[cred_id_hex] = credential
        if credential.user_id not in self._user_credentials:
            self._user_credentials[credential.user_id] = []
        self._user_credentials[credential.user_id].append(cred_id_hex)

    def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]:
        """Retrieve credential by ID."""
        return self._credentials.get(credential_id.hex())

    def get_user_credentials(self, user_id: str) -> list[StoredCredential]:
        """Get all credentials for a user."""
        cred_ids = self._user_credentials.get(user_id, [])
        return [self._credentials[cid] for cid in cred_ids if cid in self._credentials]

    def update_sign_count(self, credential_id: bytes, new_count: int) -> None:
        """Update the sign count for a credential."""
        cred_id_hex = credential_id.hex()
        if cred_id_hex in self._credentials:
            self._credentials[cred_id_hex].sign_count = new_count


# Global store instance (for this example; use a real database in production)
user_store = UserStore()
