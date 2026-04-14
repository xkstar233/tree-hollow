# blockchain_logger.py
import json
import requests
from config import Config

# 如果改了端口，这里也一起改
FABRIC_GATEWAY = "http://127.0.0.1:7071"

def log_admin_action(action: str, details: dict):
    """
    先写本地文件，不丢；再异步/网络写链上（失败不阻断业务）
    返回 {"ok": True, "txId": "..."} 或 {"ok": False, "err": "..."}
    """
    # 1) 本地日志文件（已在 Config 里有 ADMIN_ACTION_LOG）
    try:
        with open(Config.ADMIN_ACTION_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps({"action": action, **(details or {})}, ensure_ascii=False) + "\n")
    except Exception:
        pass

    # 2) 上链（失败不阻断）
    try:
        r = requests.post(
            f"{FABRIC_GATEWAY}/log",
            json={"action": action, "details": details},
            timeout=5
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("chain log failed:", e)
        return {"ok": False, "err": str(e)}

def get_chain_log(tx_id: str):
    """按交易ID查询链上日志"""
    r = requests.get(f"{FABRIC_GATEWAY}/log/{tx_id}", timeout=5)
    r.raise_for_status()
    return r.json()
