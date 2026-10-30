"""
securedocs_crypto - biblioteca didática de criptografia simétrica
=================================================================

Projeto SecureDocs / TechSecure - PBL, Missão 3.

Implementações em Python puro (sem dependências externas) de:
    * DES e 3DES  (des.py)
    * RC5-w/r/b   (rc5.py)
    * AES-128/192/256 (aes.py)
    * modos ECB, CBC e CTR + padding PKCS#7 (modos.py)
    * cifragem autenticada de arquivos com AES-256 (arquivo.py)

Exemplo:
    >>> from securedocs_crypto import AES, cbc_encrypt, cbc_decrypt
    >>> cifra = AES(bytes(32))
    >>> iv, c = cbc_encrypt(cifra, b"contrato confidencial")
    >>> cbc_decrypt(cifra, iv, c)
    b'contrato confidencial'

AVISO: código para fins de estudo. Em produção, use bibliotecas auditadas
(por exemplo, `cryptography` / OpenSSL), que são resistentes a ataques de
canal lateral (tempo, cache) e muito mais rápidas.
"""

from .aes import AES
from .arquivo import ArquivoCorrompido, cifrar_arquivo, cifrar_bytes, decifrar_arquivo, decifrar_bytes
from .des import DES, TripleDES
from .modos import cbc_decrypt, cbc_encrypt, ctr_crypt, ecb_decrypt, ecb_encrypt, pkcs7_pad, pkcs7_unpad
from .rc5 import RC5

__version__ = "1.0.0"

__all__ = [
    "AES", "DES", "TripleDES", "RC5",
    "ecb_encrypt", "ecb_decrypt", "cbc_encrypt", "cbc_decrypt", "ctr_crypt",
    "pkcs7_pad", "pkcs7_unpad",
    "cifrar_bytes", "decifrar_bytes", "cifrar_arquivo", "decifrar_arquivo",
    "ArquivoCorrompido",
]
