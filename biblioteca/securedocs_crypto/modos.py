"""
Modos de operação e preenchimento (padding)
===========================================

Uma cifra de bloco sozinha só cifra um bloco de tamanho fixo. Para cifrar um
arquivo inteiro é preciso um MODO DE OPERAÇÃO. As funções abaixo funcionam com
qualquer objeto que tenha `block_size`, `encrypt_block` e `decrypt_block`
(ou seja, com DES, TripleDES, RC5 e AES desta biblioteca).

    * ECB - cada bloco é cifrado isoladamente. NÃO usar: blocos iguais geram
            cifrados iguais e revelam padrões do arquivo.
    * CBC - cada bloco é combinado (XOR) com o cifrado anterior; exige IV
            aleatório e padding.
    * CTR - transforma a cifra de bloco em cifra de fluxo cifrando um
            contador; não precisa de padding e é paralelizável.
"""

import os


# ---------------------------------------------------------------------------
# Padding PKCS#7
# ---------------------------------------------------------------------------

def pkcs7_pad(dados: bytes, tamanho_bloco: int) -> bytes:
    n = tamanho_bloco - (len(dados) % tamanho_bloco)
    return dados + bytes([n]) * n


def pkcs7_unpad(dados: bytes, tamanho_bloco: int) -> bytes:
    if not dados or len(dados) % tamanho_bloco:
        raise ValueError("Tamanho de dados inválido para remover o padding.")
    n = dados[-1]
    if n < 1 or n > tamanho_bloco or dados[-n:] != bytes([n]) * n:
        raise ValueError("Padding PKCS#7 inválido.")
    return dados[:-n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _blocos(dados: bytes, tamanho: int):
    for i in range(0, len(dados), tamanho):
        yield dados[i:i + tamanho]


# ---------------------------------------------------------------------------
# ECB (apenas para demonstração do que NÃO fazer)
# ---------------------------------------------------------------------------

def ecb_encrypt(cifra, dados: bytes) -> bytes:
    bs = cifra.block_size
    return b"".join(cifra.encrypt_block(b) for b in _blocos(pkcs7_pad(dados, bs), bs))


def ecb_decrypt(cifra, dados: bytes) -> bytes:
    bs = cifra.block_size
    return pkcs7_unpad(b"".join(cifra.decrypt_block(b) for b in _blocos(dados, bs)), bs)


# ---------------------------------------------------------------------------
# CBC
# ---------------------------------------------------------------------------

def cbc_encrypt(cifra, dados: bytes, iv: bytes = None):
    """Retorna (iv, texto_cifrado). Gera um IV aleatório se não for informado."""
    bs = cifra.block_size
    iv = iv if iv is not None else os.urandom(bs)
    if len(iv) != bs:
        raise ValueError(f"O IV deve ter {bs} bytes.")
    anterior, saida = iv, []
    for bloco in _blocos(pkcs7_pad(dados, bs), bs):
        anterior = cifra.encrypt_block(_xor(bloco, anterior))
        saida.append(anterior)
    return iv, b"".join(saida)


def cbc_decrypt(cifra, iv: bytes, dados: bytes) -> bytes:
    bs = cifra.block_size
    if len(dados) % bs:
        raise ValueError("Texto cifrado com tamanho que não é múltiplo do bloco.")
    anterior, saida = iv, []
    for bloco in _blocos(dados, bs):
        saida.append(_xor(cifra.decrypt_block(bloco), anterior))
        anterior = bloco
    return pkcs7_unpad(b"".join(saida), bs)


# ---------------------------------------------------------------------------
# CTR
# ---------------------------------------------------------------------------

def ctr_crypt(cifra, nonce_contador: bytes, dados: bytes) -> bytes:
    """Cifra ou decifra (a operação é a mesma) no modo contador.

    `nonce_contador` é o bloco inicial do contador (tamanho do bloco); ele é
    incrementado como um inteiro big-endian a cada bloco.
    """
    bs = cifra.block_size
    if len(nonce_contador) != bs:
        raise ValueError(f"O contador inicial deve ter {bs} bytes.")
    contador = int.from_bytes(nonce_contador, "big")
    modulo = 1 << (8 * bs)
    saida = []
    for bloco in _blocos(dados, bs):
        fluxo = cifra.encrypt_block(contador.to_bytes(bs, "big"))
        saida.append(_xor(bloco, fluxo))
        contador = (contador + 1) % modulo
    return b"".join(saida)
