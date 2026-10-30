"""
AES - Advanced Encryption Standard (FIPS PUB 197)
=================================================

Implementação didática, em Python puro, da cifra de bloco AES (Rijndael).

Características:
    * bloco de 128 bits (16 bytes), organizado como uma matriz 4x4 de bytes
      ("estado"), preenchida coluna a coluna;
    * chaves de 128, 192 ou 256 bits -> 10, 12 ou 14 rodadas;
    * rede de substituição-permutação (SPN), não Feistel;
    * aritmética no corpo finito GF(2^8) com o polinômio irredutível
      m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).

Cada rodada aplica: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
(a última rodada não tem MixColumns).

A S-box não é copiada de uma tabela: ela é calculada na importação do módulo
(inverso multiplicativo em GF(2^8) seguido da transformação afim), para
mostrar de onde vêm os valores.
"""


# ---------------------------------------------------------------------------
# Aritmética em GF(2^8)
# ---------------------------------------------------------------------------

def xtime(a: int) -> int:
    """Multiplica por x (ou seja, por 0x02) em GF(2^8)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a: int, b: int) -> int:
    """Multiplicação de dois bytes em GF(2^8) (algoritmo 'russian peasant')."""
    resultado = 0
    while b:
        if b & 1:
            resultado ^= a
        a = xtime(a)
        b >>= 1
    return resultado


def _inverso(a: int) -> int:
    """Inverso multiplicativo em GF(2^8): a^254 (com 0 -> 0)."""
    if a == 0:
        return 0
    resultado, base, e = 1, a, 254
    while e:
        if e & 1:
            resultado = gmul(resultado, base)
        base = gmul(base, base)
        e >>= 1
    return resultado


def _gerar_sbox():
    sbox = [0] * 256
    for x in range(256):
        b = _inverso(x)
        # Transformação afim: b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
        s = b
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF
            s ^= b
        sbox[x] = s ^ 0x63
    inversa = [0] * 256
    for i, v in enumerate(sbox):
        inversa[v] = i
    return sbox, inversa


SBOX, INV_SBOX = _gerar_sbox()

# Constantes de rodada usadas na expansão de chave: x^(i-1) em GF(2^8)
RCON = [0x01]
for _ in range(13):
    RCON.append(xtime(RCON[-1]))

# Tabelas de multiplicação pré-calculadas (acelera MixColumns)
_MUL2 = [gmul(i, 2) for i in range(256)]
_MUL3 = [gmul(i, 3) for i in range(256)]
_MUL9 = [gmul(i, 9) for i in range(256)]
_MUL11 = [gmul(i, 11) for i in range(256)]
_MUL13 = [gmul(i, 13) for i in range(256)]
_MUL14 = [gmul(i, 14) for i in range(256)]


# ---------------------------------------------------------------------------
# Expansão de chave
# ---------------------------------------------------------------------------

def expandir_chave(chave: bytes) -> list:
    """Gera as (Nr + 1) chaves de rodada de 16 bytes cada."""
    nk = len(chave) // 4
    if len(chave) not in (16, 24, 32):
        raise ValueError("A chave AES deve ter 16, 24 ou 32 bytes.")
    nr = nk + 6
    palavras = [list(chave[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(palavras[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                   # RotWord
            temp = [SBOX[b] for b in temp]               # SubWord
            temp[0] ^= RCON[i // nk - 1]                 # XOR com Rcon
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]               # passo extra do AES-256
        palavras.append([a ^ b for a, b in zip(palavras[i - nk], temp)])
    return [sum(palavras[4 * r:4 * r + 4], []) for r in range(nr + 1)]


# ---------------------------------------------------------------------------
# Transformações de rodada. O estado é uma lista de 16 bytes em ordem de
# coluna: estado[linha + 4 * coluna].
# ---------------------------------------------------------------------------

def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # Linha r é rotacionada r posições para a esquerda
    return [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    return [s[(r + 4 * ((c - r) % 4))] for c in range(4) for r in range(4)]


def mix_columns(s):
    saida = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        saida += [
            _MUL2[a0] ^ _MUL3[a1] ^ a2 ^ a3,
            a0 ^ _MUL2[a1] ^ _MUL3[a2] ^ a3,
            a0 ^ a1 ^ _MUL2[a2] ^ _MUL3[a3],
            _MUL3[a0] ^ a1 ^ a2 ^ _MUL2[a3],
        ]
    return saida


def inv_mix_columns(s):
    saida = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        saida += [
            _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3],
            _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3],
            _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3],
            _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3],
        ]
    return saida


def add_round_key(s, k):
    return [a ^ b for a, b in zip(s, k)]


class AES:
    """Cifra de bloco AES-128/192/256. Uso: AES(chave).encrypt_block(bloco)."""

    block_size = 16

    def __init__(self, chave: bytes):
        self._chaves = expandir_chave(chave)
        self.rodadas = len(self._chaves) - 1
        self.nome = f"AES-{len(chave) * 8}"

    def encrypt_block(self, bloco: bytes) -> bytes:
        if len(bloco) != 16:
            raise ValueError("O bloco AES deve ter exatamente 16 bytes.")
        s = add_round_key(list(bloco), self._chaves[0])
        for r in range(1, self.rodadas):
            s = add_round_key(mix_columns(shift_rows(sub_bytes(s))), self._chaves[r])
        s = add_round_key(shift_rows(sub_bytes(s)), self._chaves[self.rodadas])
        return bytes(s)

    def decrypt_block(self, bloco: bytes) -> bytes:
        if len(bloco) != 16:
            raise ValueError("O bloco AES deve ter exatamente 16 bytes.")
        s = add_round_key(list(bloco), self._chaves[self.rodadas])
        for r in range(self.rodadas - 1, 0, -1):
            s = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(s)), self._chaves[r]))
        s = add_round_key(inv_sub_bytes(inv_shift_rows(s)), self._chaves[0])
        return bytes(s)
