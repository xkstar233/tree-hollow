# zk_guard.py —— 装饰器：用 ZK 证明保护敏感操作
from __future__ import annotations
import time, hashlib
from functools import wraps
from typing import Callable
from flask import request, jsonify
from models_zk import ZKIdentity
from zk_schnorr import SchnorrProof, verify_proof

# 轻量防重放（单进程内存）。生产建议换成 Redis。
_SEEN_NONCE: dict[str, float] = {}
_NONCE_TTL = 300          # 5 分钟
_MAX_DRIFT = 120          # 允许时间漂移（秒）

def _gc_nonce():
    now = time.time()
    expired = [k for k, t in _SEEN_NONCE.items() if t < now]
    for k in expired:
        _SEEN_NONCE.pop(k, None)

def require_zk_admin(action: str, resource_field: str) -> Callable:
    """
    要求请求体提供 JSON：
    {
      "<resource_field>": 123,
      "pubkey_hex": "...", "R_hex": "...", "s_hex": "...",
      "msg": "delete_post:123:<nonce>:<ts>",    # ts = int(seconds)
      "ctx": "zk-login-v1"
    }
    """
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not request.is_json:
                return jsonify({"ok": False, "reason": "expect application/json"}), 400
            data = request.get_json(force=True)

            # 1) 主体字段
            rid = str(data.get(resource_field) or "")
            if not rid:
                return jsonify({"ok": False, "reason": f"{resource_field} required"}), 400
            try:
                proof = SchnorrProof(
                    pubkey_hex=data["pubkey_hex"],
                    R_hex=data["R_hex"],
                    s_hex=data["s_hex"],
                    msg=data["msg"],
                    ctx=data.get("ctx", "zk-login-v1"),
                )
            except Exception:
                return jsonify({"ok": False, "reason": "missing zk proof fields"}), 400

            # 2) 白名单
            if not ZKIdentity.query.filter_by(pubkey_hex=proof.pubkey_hex, role="admin").first():
                return jsonify({"ok": False, "reason": "pubkey not allowed"}), 403

            # 3) 绑定操作 + 防重放（msg = action:rid:nonce:ts）
            parts = (proof.msg or "").split(":")
            if len(parts) < 2 or parts[0] != action or parts[1] != rid:
                return jsonify({"ok": False, "reason": "msg mismatch"}), 400
            nonce = parts[2] if len(parts) >= 3 else ""
            ts = int(parts[3]) if len(parts) >= 4 and parts[3].isdigit() else 0
            now = int(time.time())
            if not nonce or not ts or abs(now - ts) > _MAX_DRIFT:
                return jsonify({"ok": False, "reason": "stale or bad nonce/ts"}), 400
            key = hashlib.sha256(f"{proof.pubkey_hex}:{nonce}:{ts}".encode()).hexdigest()
            _gc_nonce()
            if key in _SEEN_NONCE:
                return jsonify({"ok": False, "reason": "replay"}), 409
            _SEEN_NONCE[key] = now + _NONCE_TTL

            # 4) ZK 验证
            if not verify_proof(proof):
                return jsonify({"ok": False, "reason": "invalid proof"}), 400

            return func(*args, **kwargs)
        return wrapper
    return deco
