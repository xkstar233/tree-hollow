# tor_proxy.py
import os
import requests
import httpx

def tor_session(
    host: str | None = None,
    port: int | None = None,
) -> requests.Session:
    """
    返回一个通过 Tor SOCKS 代理发请求的 requests.Session
    * 使用 socks5h 确保 DNS 也走 Tor（避免 DNS 泄露）
    """
    host = host or os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    port = int(port or os.getenv("TOR_SOCKS_PORT", "9050"))
    proxy = f"socks5h://{host}:{port}"

    s = requests.Session()
    s.trust_env = False  # 忽略系统环境代理，避免串联
    s.proxies.update({"http": proxy, "https": proxy})
    s.headers.update({"User-Agent": "Mozilla/5.0 (Tor Egress)"})
    return s

def tor_httpx_client(
    host: str | None = None,
    port: int | None = None,
    timeout: float = 30.0,
) -> httpx.Client:
    host = host or os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    port = int(port or os.getenv("TOR_SOCKS_PORT", "9050"))
    proxy = f"socks5://{host}:{port}"
    return httpx.Client(proxies=proxy, timeout=timeout, trust_env=False)

def tor_httpx_async_client(
    host: str | None = None,
    port: int | None = None,
    timeout: float = 30.0,
):
    host = host or os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
    port = int(port or os.getenv("TOR_SOCKS_PORT", "9050"))
    proxy = f"socks5://{host}:{port}"
    return httpx.AsyncClient(proxies=proxy, timeout=timeout, trust_env=False)
