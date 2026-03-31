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


def new_user(full_name, email, role, password_hash):
    """Return a new user document ready for insertion."""
    return {
        "name": full_name,
        "full_name": full_name,
        "email": email,
        "role": role,
        "password_hash": password_hash,
        "account_flagged": False,
    }
