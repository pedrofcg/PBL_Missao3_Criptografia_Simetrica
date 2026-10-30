"""
POR QUE O MODO DE OPERAÇÃO IMPORTA: ECB x CBC

Mesmo com o AES, cifrar no modo ECB vaza padrões: blocos de texto iguais
geram blocos cifrados iguais. Este script cifra uma "imagem" de 24x12 blocos
(cada célula é um bloco de 16 bytes) com AES-ECB e AES-CBC e gera um SVG em
que cada célula é colorida a partir dos bytes do bloco cifrado.

    * ECB: o desenho original continua visível no cifrado;
    * CBC: o resultado parece ruído aleatório.

Executar a partir da pasta `biblioteca`:
    python exemplos/demo_ecb_vs_cbc.py
"""

import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, ".."))

from securedocs_crypto import AES, cbc_encrypt  # noqa: E402

# Desenho de um cadeado: '#' = corpo, '.' = fundo
DESENHO = [
    "........................",
    "..........####..........",
    ".........#....#.........",
    "........#......#........",
    "........#......#........",
    "......############......",
    "......############......",
    "......#####..#####......",
    "......######.#####......",
    "......############......",
    "......############......",
    "........................",
]
TAM = 14


def blocos_do_desenho():
    blocos = []
    for linha in DESENHO:
        for c in linha:
            blocos.append(b"\xff" * 16 if c == "#" else b"\x00" * 16)
    return blocos


def cor(bloco, original=False):
    if original:
        return "#1f2937" if bloco[0] else "#f3f4f6"
    return f"#{bloco[0]:02x}{bloco[1]:02x}{bloco[2]:02x}"


def grade(blocos, x0, titulo, original=False):
    largura = len(DESENHO[0])
    partes = [f'<text x="{x0 + largura * TAM / 2}" y="18" text-anchor="middle" '
              f'font-family="Segoe UI, Arial" font-size="15" font-weight="600" fill="#111">{titulo}</text>']
    for i, b in enumerate(blocos):
        x, y = x0 + (i % largura) * TAM, 30 + (i // largura) * TAM
        partes.append(f'<rect x="{x}" y="{y}" width="{TAM}" height="{TAM}" fill="{cor(b, original)}"/>')
    return "\n".join(partes)


def main():
    cifra = AES(os.urandom(16))
    claros = blocos_do_desenho()
    dados = b"".join(claros)

    ecb = [cifra.encrypt_block(b) for b in claros]
    _, c = cbc_encrypt(cifra, dados)
    cbc = [c[i:i + 16] for i in range(0, len(dados), 16)]

    print(f"Blocos de texto: {len(claros)} ({len(set(claros))} distintos)")
    print(f"Blocos ECB distintos: {len(set(ecb))}  -> padrão preservado")
    print(f"Blocos CBC distintos: {len(set(cbc))}  -> padrão destruído")

    largura = len(DESENHO[0]) * TAM
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {3 * largura + 80} {30 + len(DESENHO) * TAM + 6}">\n'
           + grade(claros, 0, "Original", original=True) + "\n"
           + grade(ecb, largura + 40, "AES-ECB") + "\n"
           + grade(cbc, 2 * largura + 80, "AES-CBC") + "\n</svg>\n")
    os.makedirs(os.path.join(AQUI, "saida"), exist_ok=True)
    caminho = os.path.join(AQUI, "saida", "ecb_vs_cbc.svg")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"Imagem gerada: {caminho}")


if __name__ == "__main__":
    main()
