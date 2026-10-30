# PBL – Missão 3: Milhares de documentos foram roubados (SecureDocs)

| Arquivo / pasta | Produto da missão |
|---|---|
| `Resumo_Missao3_SecureDocs.pdf` | **1 – Resumo**: (a) implementações de DES, AES e RC5; (b) justificativa da escolha (AES-256); (c) resposta a “Como entregar a chave secreta ao destinatário?” |
| `biblioteca/` | **2 – Biblioteca Python** `securedocs_crypto` (DES, 3DES, RC5, AES, modos, cifragem de arquivos), testes e exemplos. Veja `biblioteca/README.md` |
| `Apresentacao_Missao3_SecureDocs.pdf` | **3 – Apresentação de 10 minutos** (14 slides, dividida entre 5 alunos de 2 minutos cada) |
| `Roteiro_de_Fala_5_Alunos.pdf` | Texto sugerido para cada aluno + perguntas prováveis |
| `fontes/` | HTML de origem dos PDFs (para editar nomes e textos) |

## Como rodar

```bash
cd biblioteca
python -m unittest discover -s tests -v       # 18 testes com vetores oficiais
python exemplos/demo_aes_arquivo.py           # experimento: arquivo -> AES -> cifrado -> AES -> arquivo
python exemplos/ataque_forca_bruta_des.py
python exemplos/comparativo_desempenho.py
python exemplos/demo_ecb_vs_cbc.py
```

## Para trocar "Aluno 1…5" pelos nomes reais

Edite os arquivos em `fontes/` (procure por "Aluno 1") e gere o PDF de novo: abra o HTML no Edge ou no Chrome,
use **Ctrl+P → Salvar como PDF**, escolha **Margens: nenhuma** e marque **Gráficos de plano de fundo**.
