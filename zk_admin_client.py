import os
import time, requests
from zk_schnorr import generate_keypair, prove_knowledge

BASE = "http://127.0.0.1:5000"

# 第一次运行：生成密钥，注册到白名单
sk_hex, pub_hex = generate_keypair()
r = requests.post(f"{BASE}/api/zk/register", json={"pubkey_hex": pub_hex, "role": "admin"})
print("register:", r.json())

# 删除帖子 123
post_id = 123
nonce = os.urandom(8).hex()
ts = int(time.time())
msg = f"delete_post:{post_id}:{nonce}:{ts}"
proof = prove_knowledge(sk_hex, msg)
payload = {
    "post_id": post_id,
    "pubkey_hex": proof.pubkey_hex,
    "R_hex": proof.R_hex,
    "s_hex": proof.s_hex,
    "msg": proof.msg,
    "ctx": proof.ctx
}
r = requests.post(f"{BASE}/api/admin/delete_post", json=payload, timeout=10)
print("delete_post:", r.status_code, r.json())
