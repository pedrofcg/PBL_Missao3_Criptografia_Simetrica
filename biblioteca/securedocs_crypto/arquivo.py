"""
Cifragem de arquivos do SecureDocs com AES-256
==============================================

Fluxo do experimento da Missão 3:

    Arquivo original -> AES -> Arquivo cifrado -> AES -> Arquivo original

Decisões de projeto:
    * AES-256 em modo CBC com IV aleatório de 16 bytes (novo a cada arquivo);
    * a chave é derivada da senha com PBKDF2-HMAC-SHA256 e um salt aleatório,
      para que a mesma senha gere chaves diferentes em cada arquivo;
    * Encrypt-then-MAC com HMAC-SHA256: se alguém alterar um único bit do
      arquivo cifrado, a decifragem é recusada (protege a INTEGRIDADE, problema
      do contrato adulterado relatado pela TechSecure).

Formato do arquivo .sdoc:

    | "SDOC" (4) | versão (1) | salt (16) | IV (16) | texto cifrado (n) | HMAC (32) |
"""

import hashlib
import hmac
import os

from .aes import AES
from .modos import cbc_decrypt, cbc_encrypt

MAGICO = b"SDOC"
VERSAO = 1
ITERACOES_PBKDF2 = 200_000
_CABECALHO = len(MAGICO) + 1 + 16 + 16
_TAMANHO_TAG = 32


class ArquivoCorrompido(Exception):
    """O arquivo foi alterado, está truncado ou a senha está errada."""


def derivar_chaves(senha: str, salt: bytes, iteracoes: int = ITERACOES_PBKDF2):
    """Deriva 64 bytes da senha: 32 para o AES-256 e 32 para o HMAC."""
    material = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, iteracoes, dklen=64)
    return material[:32], material[32:]


def cifrar_bytes(dados: bytes, senha: str) -> bytes:
    salt = os.urandom(16)
    chave_aes, chave_mac = derivar_chaves(senha, salt)
    iv, cifrado = cbc_encrypt(AES(chave_aes), dados)
    corpo = MAGICO + bytes([VERSAO]) + salt + iv + cifrado
    tag = hmac.new(chave_mac, corpo, hashlib.sha256).digest()
    return corpo + tag


def decifrar_bytes(pacote: bytes, senha: str) -> bytes:
    if len(pacote) < _CABECALHO + 16 + _TAMANHO_TAG or pacote[:4] != MAGICO:
        raise ArquivoCorrompido("Não é um arquivo SecureDocs válido.")
    if pacote[4] != VERSAO:
        raise ArquivoCorrompido(f"Versão de formato não suportada: {pacote[4]}.")
    corpo, tag = pacote[:-_TAMANHO_TAG], pacote[-_TAMANHO_TAG:]
    salt, iv = corpo[5:21], corpo[21:37]
    chave_aes, chave_mac = derivar_chaves(senha, salt)
    esperado = hmac.new(chave_mac, corpo, hashlib.sha256).digest()
    # Verifica a integridade ANTES de decifrar (comparação em tempo constante)
    if not hmac.compare_digest(tag, esperado):
        raise ArquivoCorrompido("Falha de integridade: arquivo adulterado ou senha incorreta.")
    return cbc_decrypt(AES(chave_aes), iv, corpo[_CABECALHO:])


def cifrar_arquivo(origem: str, destino: str, senha: str) -> None:
    with open(origem, "rb") as f:
        dados = f.read()
    with open(destino, "wb") as f:
        f.write(cifrar_bytes(dados, senha))


def decifrar_arquivo(origem: str, destino: str, senha: str) -> None:
    with open(origem, "rb") as f:
        pacote = f.read()
    dados = decifrar_bytes(pacote, senha)
    with open(destino, "wb") as f:
        f.write(dados)
