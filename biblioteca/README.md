# securedocs_crypto — Biblioteca de criptografia simétrica (Missão 3)

Implementações **em Python puro** (sem dependências externas) das cifras de bloco
estudadas na Missão 3 do projeto SecureDocs / TechSecure:

| Módulo | Conteúdo |
|---|---|
| `securedocs_crypto/des.py` | DES (FIPS 46-3) e 3DES-EDE |
| `securedocs_crypto/rc5.py` | RC5-w/r/b parametrizável (padrão RC5-32/12/16) |
| `securedocs_crypto/aes.py` | AES-128/192/256 (FIPS 197), S-box calculada em GF(2⁸) |
| `securedocs_crypto/modos.py` | Modos ECB, CBC e CTR + padding PKCS#7 |
| `securedocs_crypto/arquivo.py` | Cifragem de arquivos: AES-256-CBC + HMAC-SHA256 + PBKDF2 |

Requisito: Python 3.8 ou superior.

## Testes (vetores oficiais)

```bash
python -m unittest discover -s tests -v
```

18 testes: FIPS-197 (AES-128/192/256), NIST SP 800-38A (CBC e CTR), DES (vetor
clássico e NIST SP 800-17), RC5 (vetores do artigo de Rivest), ida e volta em
todos os modos, detecção de adulteração e de senha errada.

## Experimento da missão: Arquivo → AES → Cifrado → AES → Arquivo

```bash
python exemplos/demo_aes_arquivo.py
```

Ou para qualquer arquivo, pela linha de comando:

```bash
python -m securedocs_crypto cifrar   contrato.pdf contrato.pdf.sdoc
python -m securedocs_crypto decifrar contrato.pdf.sdoc contrato_recuperado.pdf
```

## Demais demonstrações

| Script | O que mostra |
|---|---|
| `exemplos/ataque_forca_bruta_des.py` | Força bruta real contra DES (14 bits) e estimativa para 2⁵⁶, 2¹¹², 2¹²⁸, 2²⁵⁶ |
| `exemplos/comparativo_desempenho.py` | Vazão em KB/s de DES, 3DES, RC5 e AES em modo CBC |
| `exemplos/demo_ecb_vs_cbc.py` | Gera `saida/ecb_vs_cbc.svg`: o modo ECB vaza o desenho, o CBC não |

As saídas já obtidas estão em `exemplos/saida/*.txt`.

## Uso como biblioteca

```python
from securedocs_crypto import AES, DES, RC5, cbc_encrypt, cbc_decrypt, ctr_crypt

cifra = AES(bytes(32))                      # AES-256
iv, c = cbc_encrypt(cifra, b"relatorio financeiro")
assert cbc_decrypt(cifra, iv, c) == b"relatorio financeiro"

RC5(b"chave-de-16-byte", rodadas=12).encrypt_block(b"8 bytes!")
DES(bytes.fromhex("133457799BBCDFF1")).encrypt_block(bytes.fromhex("0123456789ABCDEF"))
```

> **Aviso:** código didático. Em produção use bibliotecas auditadas (`cryptography`,
> OpenSSL, libsodium), que têm proteção contra ataques de canal lateral (tempo e
> cache) e aceleração por hardware (AES-NI).
