"""
EXPERIMENTO DA MISSÃO 3

    Arquivo original -> AES -> Arquivo cifrado -> AES -> Arquivo original

1. cria (se não existir) um contrato confidencial de exemplo;
2. cifra o arquivo com AES-256-CBC + HMAC-SHA256 (senha -> PBKDF2);
3. mostra que o arquivo cifrado não revela nada do conteúdo;
4. decifra e prova, pelo hash SHA-256, que o arquivo recuperado é idêntico;
5. simula o ataque do "contrato adulterado": altera 1 bit do arquivo cifrado
   e mostra que o SecureDocs detecta e recusa o documento.

Executar a partir da pasta `biblioteca`:
    python exemplos/demo_aes_arquivo.py
"""

import hashlib
import math
import os
import sys
from collections import Counter

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, ".."))

from securedocs_crypto import ArquivoCorrompido, cifrar_arquivo, decifrar_arquivo, decifrar_bytes  # noqa: E402

SAIDA = os.path.join(AQUI, "saida")
ORIGINAL = os.path.join(SAIDA, "contrato_confidencial.txt")
CIFRADO = ORIGINAL + ".sdoc"
RECUPERADO = os.path.join(SAIDA, "contrato_recuperado.txt")
SENHA = "TechSecure#Missao3-2026"

CONTRATO = """CONTRATO DE PRESTAÇÃO DE SERVIÇOS N. 2026/031 - CONFIDENCIAL

CONTRATANTE: TechSecure Soluções Digitais Ltda.
CONTRATADA:  Cliente Exemplo S.A.

Cláusula 1 - Objeto: licenciamento da plataforma SecureDocs para 1.200 usuários.
Cláusula 2 - Valor: R$ 1.250.000,00 (um milhão, duzentos e cinquenta mil reais),
             pagos em 10 parcelas mensais de R$ 125.000,00.
Cláusula 3 - Vigência: 36 meses a partir da assinatura.
Cláusula 4 - Sigilo: as partes se obrigam a manter sigilo absoluto sobre
             este documento e sobre as informações estratégicas trocadas.

Conta para depósito: Banco 000, Agência 1234, Conta 99999-9 (dados fictícios).
"""


def sha256(caminho):
    with open(caminho, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def entropia(dados):
    """Entropia de Shannon em bits por byte (máximo = 8.0)."""
    total = len(dados)
    return -sum(n / total * math.log2(n / total) for n in Counter(dados).values())


def hexdump(dados, linhas=4):
    for i in range(0, min(len(dados), 16 * linhas), 16):
        trecho = dados[i:i + 16]
        texto = "".join(chr(b) if 32 <= b < 127 else "." for b in trecho)
        print(f"   {i:04x}  {trecho.hex(' '):<47}  {texto}")


def main():
    os.makedirs(SAIDA, exist_ok=True)
    if not os.path.exists(ORIGINAL):
        with open(ORIGINAL, "w", encoding="utf-8") as f:
            f.write(CONTRATO)

    print("=" * 72)
    print(" EXPERIMENTO: Arquivo original -> AES -> cifrado -> AES -> original")
    print("=" * 72)

    with open(ORIGINAL, "rb") as f:
        original = f.read()
    print(f"\n[1] Arquivo original : {os.path.basename(ORIGINAL)} ({len(original)} bytes)")
    print(f"    SHA-256          : {sha256(ORIGINAL)}")
    print(f"    Entropia         : {entropia(original):.2f} bits/byte")
    hexdump(original)

    cifrar_arquivo(ORIGINAL, CIFRADO, SENHA)
    with open(CIFRADO, "rb") as f:
        cifrado = f.read()
    print(f"\n[2] AES-256-CBC + HMAC-SHA256 -> {os.path.basename(CIFRADO)} ({len(cifrado)} bytes)")
    print(f"    SHA-256          : {sha256(CIFRADO)}")
    print(f"    Entropia         : {entropia(cifrado):.2f} bits/byte")
    print(f"    Contém 'R$ 1.250.000'? {'SIM' if b'1.250.000' in cifrado else 'NÃO'}")
    hexdump(cifrado)

    decifrar_arquivo(CIFRADO, RECUPERADO, SENHA)
    iguais = sha256(ORIGINAL) == sha256(RECUPERADO)
    print(f"\n[3] AES-256 (decifrar) -> {os.path.basename(RECUPERADO)}")
    print(f"    SHA-256          : {sha256(RECUPERADO)}")
    print(f"    Idêntico ao original? {'SIM' if iguais else 'NÃO'}")

    print("\n[4] Ataque: invasor altera 1 bit do arquivo cifrado (contrato adulterado)")
    adulterado = bytearray(cifrado)
    adulterado[50] ^= 0x01
    try:
        decifrar_bytes(bytes(adulterado), SENHA)
        print("    Documento aceito (FALHA DE SEGURANÇA!)")
    except ArquivoCorrompido as erro:
        print(f"    Documento RECUSADO -> {erro}")

    print("\n[5] Ataque: invasor tenta abrir o arquivo roubado com outra senha")
    try:
        decifrar_bytes(cifrado, "123456")
        print("    Documento aberto (FALHA DE SEGURANÇA!)")
    except ArquivoCorrompido as erro:
        print(f"    Documento RECUSADO -> {erro}")

    print("\nResultado:", "SUCESSO - ciclo completo verificado." if iguais else "FALHA")
    return 0 if iguais else 1


if __name__ == "__main__":
    sys.exit(main())
