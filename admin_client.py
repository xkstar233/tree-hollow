# admin_client.py
import os, time, requests
from zk_schnorr import prove_knowledge

BASE = "http://127.0.0.1:5000"


SK_HEX = "8872f6b8bd392ab88d027818758aa2b34e4e95380e368d684ef0a17e0c8f16cb"
POST_ID = "1c99a248-a2ab-42d6-8d24-f501f2b25a00"


# 绑定操作的消息：action:resourceId:nonce:timestamp
nonce = os.urandom(8).hex()
ts = int(time.time())
msg = f"delete_post:{POST_ID}:{nonce}:{ts}"

# 生成零知识证明
proof = prove_knowledge(SK_HEX, msg)

payload = {
    "post_id": POST_ID,
    "pubkey_hex": proof.pubkey_hex,
    "R_hex": proof.R_hex,
    "s_hex": proof.s_hex,
    "msg": proof.msg,
    "ctx": proof.ctx
}

r = requests.post(f"{BASE}/api/admin/delete_post", json=payload, timeout=15)
print(r.status_code, r.text)
