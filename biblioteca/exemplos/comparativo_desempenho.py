"""
COMPARATIVO DE DESEMPENHO: DES x 3DES x RC5 x AES

Mede a vazão (KB/s) de cada implementação em modo CBC, em Python puro.
Os números absolutos são baixos (Python interpretado, sem instruções AES-NI),
mas a comparação RELATIVA entre os algoritmos é instrutiva.

Executar a partir da pasta `biblioteca`:
    python exemplos/comparativo_desempenho.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from securedocs_crypto import AES, DES, RC5, TripleDES, cbc_decrypt, cbc_encrypt  # noqa: E402

TAMANHO = 32 * 1024   # 32 KB


def medir(cifra, dados):
    inicio = time.perf_counter()
    iv, c = cbc_encrypt(cifra, dados)
    t_cifrar = time.perf_counter() - inicio
    inicio = time.perf_counter()
    assert cbc_decrypt(cifra, iv, c) == dados
    t_decifrar = time.perf_counter() - inicio
    kb = len(dados) / 1024
    return kb / t_cifrar, kb / t_decifrar


def main():
    dados = os.urandom(TAMANHO)
    algoritmos = [
        ("DES", DES(os.urandom(8)), 56, 64, 16),
        ("3DES", TripleDES(os.urandom(24)), 112, 64, 48),
        ("RC5-32/12/16", RC5(os.urandom(16)), 128, 64, 12),
        ("AES-128", AES(os.urandom(16)), 128, 128, 10),
        ("AES-256", AES(os.urandom(32)), 256, 128, 14),
    ]
    print("=" * 78)
    print(f" DESEMPENHO EM MODO CBC - {TAMANHO // 1024} KB de dados aleatórios (Python puro)")
    print("=" * 78)
    print(f" {'Algoritmo':<14}{'Chave':>8}{'Bloco':>8}{'Rodadas':>9}{'Cifrar KB/s':>14}{'Decifrar KB/s':>16}")
    print(" " + "-" * 69)
    for nome, cifra, chave, bloco, rodadas in algoritmos:
        enc, dec = medir(cifra, dados)
        print(f" {nome:<14}{chave:>6} b{bloco:>6} b{rodadas:>9}{enc:>14.1f}{dec:>16.1f}")
    print("\n Observação: em hardware moderno com AES-NI, o AES ultrapassa vários GB/s.")


if __name__ == "__main__":
    main()
