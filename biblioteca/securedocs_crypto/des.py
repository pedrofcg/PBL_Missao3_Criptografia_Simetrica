"""
DES - Data Encryption Standard (FIPS PUB 46-3)
==============================================

Implementação didática, em Python puro, da cifra de bloco DES.

Características:
    * bloco de 64 bits (8 bytes);
    * chave de 64 bits, dos quais apenas 56 são efetivos (8 bits de paridade);
    * rede de Feistel com 16 rodadas;
    * 16 subchaves de 48 bits geradas pelo escalonamento de chave (PC-1, PC-2
      e rotações circulares).

ATENÇÃO: o DES é considerado inseguro desde o fim da década de 1990 (chave de
56 bits quebrável por força bruta). Esta implementação existe apenas para fins
de estudo e comparação no projeto SecureDocs.

Também é fornecido o TripleDES (3DES, EDE), variante que ainda aparece em
sistemas legados.
"""

# ---------------------------------------------------------------------------
# Tabelas do padrão. Os valores são posições de bit numeradas de 1 a 64
# (bit 1 = bit mais significativo), exatamente como aparecem no FIPS 46-3.
# ---------------------------------------------------------------------------

# Permutação inicial (IP)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Permutação final (IP^-1)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Expansão E: 32 -> 48 bits
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# Permutação P aplicada à saída das S-boxes
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

# Escolha permutada 1 (PC-1): 64 -> 56 bits (descarta os bits de paridade)
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# Escolha permutada 2 (PC-2): 56 -> 48 bits
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Quantidade de rotações à esquerda de C e D em cada rodada
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# As 8 S-boxes (6 bits de entrada -> 4 bits de saída). Única parte não linear.
SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 0, 9, 3, 11, 5, 6, 12]],
]


def _permutar(valor: int, tabela: list, bits_entrada: int) -> int:
    """Aplica uma tabela de permutação/expansão do padrão a um inteiro.

    A posição i da tabela diz qual bit da entrada (1 = MSB) vai para a
    posição i da saída.
    """
    saida = 0
    for posicao in tabela:
        saida = (saida << 1) | ((valor >> (bits_entrada - posicao)) & 1)
    return saida


def _rotl28(valor: int, n: int) -> int:
    """Rotação circular à esquerda em uma metade de 28 bits."""
    return ((valor << n) | (valor >> (28 - n))) & 0x0FFFFFFF


def gerar_subchaves(chave: bytes) -> list:
    """Escalonamento de chave: gera as 16 subchaves de 48 bits."""
    if len(chave) != 8:
        raise ValueError("A chave DES deve ter exatamente 8 bytes (64 bits).")
    k = int.from_bytes(chave, "big")
    k56 = _permutar(k, PC1, 64)            # remove os 8 bits de paridade
    c, d = k56 >> 28, k56 & 0x0FFFFFFF     # divide em duas metades de 28 bits
    subchaves = []
    for deslocamento in SHIFTS:
        c, d = _rotl28(c, deslocamento), _rotl28(d, deslocamento)
        subchaves.append(_permutar((c << 28) | d, PC2, 56))
    return subchaves


def _funcao_f(r: int, subchave: int) -> int:
    """Função de rodada f(R, K) da rede de Feistel."""
    x = _permutar(r, E, 32) ^ subchave     # expansão 32->48 e XOR com subchave
    saida = 0
    for i in range(8):                     # 8 grupos de 6 bits -> S-boxes
        bloco6 = (x >> (42 - 6 * i)) & 0x3F
        linha = ((bloco6 & 0x20) >> 4) | (bloco6 & 0x01)   # bits externos
        coluna = (bloco6 >> 1) & 0x0F                      # 4 bits internos
        saida = (saida << 4) | SBOX[i][linha][coluna]
    return _permutar(saida, P, 32)


def _processar_bloco(bloco: bytes, subchaves: list) -> bytes:
    """Executa as 16 rodadas de Feistel sobre um bloco de 8 bytes."""
    if len(bloco) != 8:
        raise ValueError("O bloco DES deve ter exatamente 8 bytes.")
    b = _permutar(int.from_bytes(bloco, "big"), IP, 64)
    esquerda, direita = b >> 32, b & 0xFFFFFFFF
    for k in subchaves:
        esquerda, direita = direita, esquerda ^ _funcao_f(direita, k)
    # Após a 16ª rodada as metades NÃO são trocadas (R16 || L16)
    pre_saida = (direita << 32) | esquerda
    return _permutar(pre_saida, FP, 64).to_bytes(8, "big")


class DES:
    """Cifra de bloco DES. Uso: DES(chave).encrypt_block(bloco)."""

    nome = "DES"
    block_size = 8

    def __init__(self, chave: bytes):
        self._subchaves = gerar_subchaves(chave)

    def encrypt_block(self, bloco: bytes) -> bytes:
        return _processar_bloco(bloco, self._subchaves)

    def decrypt_block(self, bloco: bytes) -> bytes:
        # Propriedade da rede de Feistel: decifrar = cifrar com as subchaves
        # em ordem inversa.
        return _processar_bloco(bloco, self._subchaves[::-1])


class TripleDES:
    """3DES no modo EDE: C = E_K3(D_K2(E_K1(P))). Chave de 16 ou 24 bytes."""

    nome = "3DES"
    block_size = 8

    def __init__(self, chave: bytes):
        if len(chave) == 16:
            chave = chave + chave[:8]          # opção 2 (K3 = K1)
        if len(chave) != 24:
            raise ValueError("A chave 3DES deve ter 16 ou 24 bytes.")
        self._k1 = DES(chave[0:8])
        self._k2 = DES(chave[8:16])
        self._k3 = DES(chave[16:24])

    def encrypt_block(self, bloco: bytes) -> bytes:
        return self._k3.encrypt_block(self._k2.decrypt_block(self._k1.encrypt_block(bloco)))

    def decrypt_block(self, bloco: bytes) -> bytes:
        return self._k1.decrypt_block(self._k2.encrypt_block(self._k3.decrypt_block(bloco)))
