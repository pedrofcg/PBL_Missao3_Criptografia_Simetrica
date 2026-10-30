"""
RC5 (Ron Rivest, 1994)
======================

Implementação didática, em Python puro, da cifra de bloco RC5-w/r/b.

O RC5 é totalmente parametrizável:
    * w = tamanho da palavra em bits (16, 32 ou 64) -> bloco de 2w bits;
    * r = número de rodadas (0 a 255; recomendado >= 12 para w = 32);
    * b = tamanho da chave em bytes (0 a 255).

A notação usual é RC5-32/12/16: palavra de 32 bits (bloco de 64 bits),
12 rodadas e chave de 128 bits.

Ideia central: usa apenas três operações simples (soma modular, XOR e rotação),
mas a rotação é DEPENDENTE DOS DADOS (o número de posições rotacionadas vem do
próprio texto), o que torna a cifra não linear sem precisar de S-boxes.

As palavras são lidas em little-endian, como no artigo original e no RFC 2040.
"""

# Constantes mágicas: P = Odd((e - 2) * 2^w), Q = Odd((phi - 1) * 2^w)
CONSTANTES = {
    16: (0xB7E1, 0x9E37),
    32: (0xB7E15163, 0x9E3779B9),
    64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
}


class RC5:
    """Cifra de bloco RC5-w/r/b. Padrão: RC5-32/12/<len(chave)>."""

    def __init__(self, chave: bytes, rodadas: int = 12, tamanho_palavra: int = 32):
        if tamanho_palavra not in CONSTANTES:
            raise ValueError("O tamanho da palavra deve ser 16, 32 ou 64 bits.")
        if not 0 <= rodadas <= 255:
            raise ValueError("O número de rodadas deve estar entre 0 e 255.")
        if len(chave) > 255:
            raise ValueError("A chave RC5 deve ter no máximo 255 bytes.")
        self.w = tamanho_palavra
        self.r = rodadas
        self.u = tamanho_palavra // 8          # bytes por palavra
        self.mask = (1 << tamanho_palavra) - 1
        self.block_size = 2 * self.u
        self.nome = f"RC5-{self.w}/{self.r}/{len(chave)}"
        self._S = self._expandir_chave(chave)

    # --- operações básicas -------------------------------------------------
    def _rotl(self, x: int, n: int) -> int:
        n %= self.w
        return ((x << n) | (x >> (self.w - n))) & self.mask

    def _rotr(self, x: int, n: int) -> int:
        n %= self.w
        return ((x >> n) | (x << (self.w - n))) & self.mask

    # --- escalonamento de chave ---------------------------------------------
    def _expandir_chave(self, chave: bytes) -> list:
        u, mask = self.u, self.mask
        p, q = CONSTANTES[self.w]

        # 1) Converte a chave secreta K em c palavras L (little-endian)
        c = max(1, (len(chave) + u - 1) // u)
        L = [0] * c
        for i in range(len(chave) - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + chave[i]) & mask

        # 2) Inicializa a tabela S (t = 2r + 2 palavras) com P e Q
        t = 2 * self.r + 2
        S = [0] * t
        S[0] = p
        for i in range(1, t):
            S[i] = (S[i - 1] + q) & mask

        # 3) Mistura a chave na tabela: 3 * max(t, c) iterações
        A = B = i = j = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = self._rotl((S[i] + A + B) & mask, 3)
            B = L[j] = self._rotl((L[j] + A + B) & mask, A + B)
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    # --- cifragem / decifragem ----------------------------------------------
    def encrypt_block(self, bloco: bytes) -> bytes:
        if len(bloco) != self.block_size:
            raise ValueError(f"O bloco RC5 deve ter {self.block_size} bytes.")
        u, mask, S = self.u, self.mask, self._S
        A = (int.from_bytes(bloco[:u], "little") + S[0]) & mask
        B = (int.from_bytes(bloco[u:], "little") + S[1]) & mask
        for i in range(1, self.r + 1):
            A = (self._rotl(A ^ B, B) + S[2 * i]) & mask
            B = (self._rotl(B ^ A, A) + S[2 * i + 1]) & mask
        return A.to_bytes(u, "little") + B.to_bytes(u, "little")

    def decrypt_block(self, bloco: bytes) -> bytes:
        if len(bloco) != self.block_size:
            raise ValueError(f"O bloco RC5 deve ter {self.block_size} bytes.")
        u, mask, S = self.u, self.mask, self._S
        A = int.from_bytes(bloco[:u], "little")
        B = int.from_bytes(bloco[u:], "little")
        for i in range(self.r, 0, -1):
            B = self._rotr((B - S[2 * i + 1]) & mask, A) ^ A
            A = self._rotr((A - S[2 * i]) & mask, B) ^ B
        B = (B - S[1]) & mask
        A = (A - S[0]) & mask
        return A.to_bytes(u, "little") + B.to_bytes(u, "little")
