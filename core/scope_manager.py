"""Scope management (Stage 2) — nothing scans without recorded authorization."""


class UnauthorizedTargetError(Exception):
    """Raised when a scan target is not an approved asset within scope."""


class ScopeManager:
    def __init__(self, db):
        self.db = db

    def register_asset(self, name, asset_type, target, owner="", notes=""):
        self.db.execute(
            "INSERT INTO assets (name, asset_type, target, owner, notes) VALUES (?,?,?,?,?)",
            (name, asset_type, target, owner, notes))
        asset_id = self.db.scalar("SELECT MAX(id) FROM assets")
        self.db.audit("asset.register", target=target,
                      details={"name": name, "type": asset_type})
        return asset_id

    def authorize_asset(self, asset_id, scope, authorized_by, valid_until=None, evidence=""):
        """Record explicit written authorization for an asset."""
        self.db.execute(
            "UPDATE assets SET authorization_status = 'approved' WHERE id = ?", (asset_id,))
        self.db.execute(
            "INSERT INTO authorizations (asset_id, scope, authorized_by, valid_until, evidence) "
            "VALUES (?,?,?,?,?)", (asset_id, scope, authorized_by, valid_until, evidence))
        self.db.audit("asset.authorize", target=str(asset_id),
                      details={"scope": scope, "by": authorized_by, "until": valid_until})

    def revoke(self, asset_id):
        self.db.execute("UPDATE assets SET authorization_status = 'revoked' WHERE id = ?", (asset_id,))
        self.db.audit("asset.revoke", target=str(asset_id))

    def assert_authorized(self, asset_id):
        """Call before any scan. Raises UnauthorizedTargetError otherwise."""
        asset = self.db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
        if asset is None:
            raise UnauthorizedTargetError("Asset not found.")
        if asset["authorization_status"] != "approved":
            raise UnauthorizedTargetError(
                f"Asset '{asset['name']}' is not authorized. Approval is required before scanning.")
        auth = self.db.query_one(
            "SELECT * FROM authorizations WHERE asset_id = ? ORDER BY id DESC LIMIT 1", (asset_id,))
        if auth is None:
            raise UnauthorizedTargetError("No authorization record for this asset.")
        if auth["valid_until"] and auth["valid_until"] < str(auth["created_at"])[:10]:
            raise UnauthorizedTargetError("Authorization has expired.")
        return dict(asset)

    def is_authorized(self, asset_id):
        try:
            self.assert_authorized(asset_id)
            return True
        except UnauthorizedTargetError:
            return False
