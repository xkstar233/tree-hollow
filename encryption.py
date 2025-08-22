import base64
import os
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from config import Config
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

def encrypt_data(data):
    if not data:
        return data

    try:
        if isinstance(data, str):
            data = data.encode('utf-8')

        key = Config.derived_sm4_key
        iv = os.urandom(16)  #每次加密时生成随机 IV（16字节）

        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key, SM4_ENCRYPT)

        padded_data = pad(data, BLOCK_SIZE)
        encrypted = crypt_sm4.crypt_cbc(iv, padded_data)
        #SM4 使用 CBC 模式时必须传入 IV
        return base64.b64encode(iv + encrypted).decode('utf-8')
        #IV和密文打包在一起返回，保证解密方能取出IV
    except Exception as e:
        print(f"SM4 加密错误: {e}")
        raise

def decrypt_data(encrypted_data):
    if not encrypted_data:
        return encrypted_data

    try:
        raw = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = raw[:16]   #从 base64 解码后的前16字节提取 IV
        encrypted = raw[16:]  #后面是密文

        key = Config.derived_sm4_key
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key, SM4_DECRYPT)

        decrypted = crypt_sm4.crypt_cbc(iv, encrypted)
        unpadded = unpad(decrypted, BLOCK_SIZE)
        return unpadded.decode('utf-8')
    except Exception as e:
        print(f"SM4 解密错误: {e}")
        return None
