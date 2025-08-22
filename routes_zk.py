# routes_zk.py —— 提供 /api/zk/register 与 /api/zk/verify
from flask import Blueprint, request, jsonify, abort
from models_zk import db, ZKIdentity
from zk_schnorr import SchnorrProof, verify_proof

bp = Blueprint("zk", __name__, url_prefix="/api/zk")

@bp.post("/register")
def zk_register():
    data = request.get_json(force=True)
    pub = (data.get("pubkey_hex") or "").strip()
    role = (data.get("role") or "admin").strip()
    if not pub:
        abort(400, "pubkey_hex required")
    rec = ZKIdentity.query.filter_by(pubkey_hex=pub).first()
    if rec:
        return jsonify({"ok": True, "msg": "exists"})
    db.session.add(ZKIdentity(pubkey_hex=pub, role=role))
    db.session.commit()
    return jsonify({"ok": True})

@bp.post("/verify")
def zk_verify():
    data = request.get_json(force=True)
    try:
        proof = SchnorrProof(**data)
    except TypeError as e:
        abort(400, f"bad proof fields: {e}")
    rec = ZKIdentity.query.filter_by(pubkey_hex=proof.pubkey_hex).first()
    if not rec:
        return jsonify({"ok": False, "reason": "pubkey not allowed"}), 403
    ok = verify_proof(proof)
    return (jsonify({"ok": True, "role": rec.role})
            if ok else (jsonify({"ok": False, "reason": "invalid proof"}), 400))

@bp.get("/health")
def health():
    return {"ok": True}
