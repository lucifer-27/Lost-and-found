"""
User Model — defines the user document structure for MongoDB.
Since MongoDB is schemaless, this serves as documentation and
provides helper functions for user operations.
"""

# User document structure in MongoDB:
# {
#     "_id": ObjectId,
#     "name": str,
#     "full_name": str,
#     "email": str,              # college email (e.g. 24bcp001@sot.pdpu.ac.in)
#     "role": str,               # "student", "staff", or "admin"
#     "password_hash": str,      # werkzeug hashed password
#     "account_flagged": bool,   # True if flagged by admin
#     "flag_reason": str,        # reason for flagging (optional)
# }


import dataclasses
from typing import Optional

@dataclasses.dataclass
class User:
    name: str
    full_name: str
    email: str
    role: str
    password_hash: str
    account_flagged: bool = False
    flag_reason: Optional[str] = None

def new_user(full_name: str, email: str, role: str, password_hash: str) -> dict:
    """Return a new user document ready for insertion."""
    user = User(
        name=full_name,
        full_name=full_name,
        email=email,
        role=role,
        password_hash=password_hash
    )
    return dataclasses.asdict(user)
