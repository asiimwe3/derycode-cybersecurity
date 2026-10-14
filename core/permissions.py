"""Role-based permissions (Stage 2)."""
import json


def role_permissions(db, role_name):
    row = db.query_one("SELECT permissions_json FROM roles WHERE name = ?", (role_name,))
    return json.loads(row["permissions_json"]) if row else []


def user_can(user, permission):
    """user is the row dict from Database.authenticate(). '*' grants everything."""
    perms = user.get("_permissions") or []
    if "*" in perms:
        return True
    for p in perms:
        if p.endswith(".*"):
            if permission.startswith(p[:-1]):
                return True
        elif p == permission:
            return True
    return False


def load_user(db, username, password):
    """Authenticate and attach effective permissions. Returns dict or None."""
    user = db.authenticate(username, password)
    if user is None:
        return None
    row = db.query_one("SELECT name FROM roles WHERE id = ?", (user["role_id"],))
    user["role"] = row["name"] if row else "student"
    user["_permissions"] = role_permissions(db, user["role"])
    return user
