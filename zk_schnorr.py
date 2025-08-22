# zk_schnorr.py —— 兼容 coincurve 多版本的 Schnorr NIZK（Fiat–Shamir）
from __future__ import annotations
import os, hashlib
from dataclasses import dataclass
from typing import Optional
from coincurve import PrivateKey, PublicKey

# secp256k1 曲线阶（常量）
N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def _H(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big") % N

def _pb(pub: PublicKey) -> bytes:
    return pub.format(compressed=True)  # 33B 压缩公钥

@dataclass
class SchnorrProof:
    pubkey_hex: str
    R_hex: str
    s_hex: str
    msg: str
    ctx: str = "zk-login-v1"

def generate_keypair(seed: Optional[bytes] = None) -> tuple[str, str]:
    sk = PrivateKey(hashlib.sha256(seed).digest()) if seed else PrivateKey()
    return sk.to_hex(), _pb(sk.public_key).hex()

def prove_knowledge(sk_hex: str, msg: str, ctx: str = "zk-login-v1") -> SchnorrProof:
    sk = PrivateKey(bytes.fromhex(sk_hex))
    pk = sk.public_key
    k = _H(sk.secret, os.urandom(32), b"nonce") or 1  # 简化版 nonce
    R_priv = PrivateKey(int(k).to_bytes(32, "big"))
    R = R_priv.public_key
    e = _H(ctx.encode(), msg.encode(), _pb(pk), _pb(R))
    x = int.from_bytes(sk.secret, "big")
    s = (k + e * x) % N
    return SchnorrProof(_pb(pk).hex(), _pb(R).hex(), f"{s:064x}", msg, ctx)

def verify_proof(proof: SchnorrProof) -> bool:
    try:
        pk = PublicKey(bytes.fromhex(proof.pubkey_hex))
        R = PublicKey(bytes.fromhex(proof.R_hex))
        s = int(proof.s_hex, 16) % N
    except Exception:
        return False
    e = _H(proof.ctx.encode(), proof.msg.encode(), _pb(pk), _pb(R))
    sG = PrivateKey(int(s).to_bytes(32, "big")).public_key
    if e == 0:
        right = R
    else:
        eP = pk.multiply(int(e).to_bytes(32, "big"))
        right = PublicKey.combine_keys([R, eP])
    return sG.format() == right.format()
