"""
Linha de comando:

    python -m securedocs_crypto cifrar   contrato.pdf contrato.pdf.sdoc
    python -m securedocs_crypto decifrar contrato.pdf.sdoc contrato_recuperado.pdf

A senha é pedida no terminal (não fica no histórico) ou pode ser passada com
--senha, apenas para testes.
"""

import argparse
import getpass
import sys

from .arquivo import ArquivoCorrompido, cifrar_arquivo, decifrar_arquivo


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="securedocs_crypto",
                                     description="Cifra/decifra arquivos com AES-256-CBC + HMAC-SHA256.")
    parser.add_argument("operacao", choices=["cifrar", "decifrar"])
    parser.add_argument("origem")
    parser.add_argument("destino")
    parser.add_argument("--senha", help="senha (se omitida, será pedida no terminal)")
    args = parser.parse_args(argv)

    senha = args.senha or getpass.getpass("Senha: ")
    try:
        if args.operacao == "cifrar":
            cifrar_arquivo(args.origem, args.destino, senha)
        else:
            decifrar_arquivo(args.origem, args.destino, senha)
    except ArquivoCorrompido as erro:
        print(f"ERRO: {erro}", file=sys.stderr)
        return 1
    print(f"OK: {args.origem} -> {args.destino}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
