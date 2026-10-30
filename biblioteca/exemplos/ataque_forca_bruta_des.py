"""
ATAQUE DE FORÇA BRUTA AO DES (prova de conceito)

O invasor que roubou os arquivos tem um bloco de texto conhecido (por exemplo,
todo contrato começa com "CONTRATO") e o bloco cifrado correspondente.
Ele testa chaves até encontrar a que transforma um no outro.

Para caber em poucos segundos, o ataque é feito com 14 bits desconhecidos
(2^14 = 16.384 chaves). Em seguida, a velocidade medida é usada para estimar
o tempo para o espaço de chaves completo do DES (2^56), do 3DES (2^112 efetivo)
e do AES (2^128 e 2^256).

Executar a partir da pasta `biblioteca`:
    python exemplos/ataque_forca_bruta_des.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from securedocs_crypto import DES  # noqa: E402

BITS_DESCONHECIDOS = 14
SEGUNDOS_POR_ANO = 365.25 * 24 * 3600


def formatar_tempo(segundos):
    if segundos < 120:
        return f"{segundos:,.1f} segundos"
    if segundos < 2 * 3600:
        return f"{segundos / 60:,.1f} minutos"
    if segundos < 2 * 86400:
        return f"{segundos / 3600:,.1f} horas"
    if segundos < 2 * SEGUNDOS_POR_ANO:
        return f"{segundos / 86400:,.1f} dias"
    return f"{segundos / SEGUNDOS_POR_ANO:.2e} anos"


def montar_chave(base, desconhecido):
    """Coloca 14 bits nos 7 bits efetivos dos 2 últimos bytes (o bit 0 é paridade)."""
    alto, baixo = desconhecido >> 7, desconhecido & 0x7F
    return base[:6] + bytes([alto << 1, baixo << 1])


def main():
    base = bytes.fromhex("133457799BBC0000")
    segredo = 0b10111100110111                       # parte "desconhecida" da chave
    chave_real = montar_chave(base, segredo)
    texto_conhecido = b"CONTRATO"
    cifrado = DES(chave_real).encrypt_block(texto_conhecido)

    print("=" * 72)
    print(" ATAQUE DE FORÇA BRUTA AO DES (texto conhecido)")
    print("=" * 72)
    print(f" Texto conhecido : {texto_conhecido!r}")
    print(f" Bloco cifrado   : {cifrado.hex().upper()}")
    print(f" Bits procurados : {BITS_DESCONHECIDOS} ({2 ** BITS_DESCONHECIDOS:,} chaves)\n")

    inicio = time.perf_counter()
    encontrada, testadas = None, 0
    for candidato in range(2 ** BITS_DESCONHECIDOS):
        testadas += 1
        chave = montar_chave(base, candidato)
        if DES(chave).encrypt_block(texto_conhecido) == cifrado:
            encontrada = chave
            break
    duracao = time.perf_counter() - inicio
    velocidade = testadas / duracao

    print(f" Chave encontrada: {encontrada.hex().upper()}  (real: {chave_real.hex().upper()})")
    print(f" Chaves testadas : {testadas:,} em {duracao:.2f} s -> {velocidade:,.0f} chaves/s (Python puro)\n")

    cenarios = [
        ("Este notebook (Python puro)", velocidade),
        ("Deep Crack, EFF - 1998", 9.0e10),
        ("Cluster de GPUs atual (estimativa)", 1.0e12),
    ]
    alvos = [("DES (2^56)", 56), ("3DES (2^112)", 112), ("AES-128 (2^128)", 128), ("AES-256 (2^256)", 256)]

    print(" Tempo MÉDIO estimado para achar a chave (metade do espaço):")
    for nome, v in cenarios:
        print(f"\n  {nome} - {v:,.0f} chaves/s")
        for alvo, bits in alvos:
            print(f"    {alvo:<17}: {formatar_tempo(2 ** (bits - 1) / v)}")
    print("\n Conclusão: o DES cai em horas com hardware dedicado; o AES é inviável.")


if __name__ == "__main__":
    main()
