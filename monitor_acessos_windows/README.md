# Monitor de Tentativas de Acesso (Windows) — CLI em Python

Ferramenta em Python para:

1) **Monitorar em tempo real** eventos de logon no Windows (Log de Segurança):
- 4624 (sucesso), 4625 (falha), 4634 (logoff)

2) **Analisar um intervalo** de eventos já registrados em um arquivo **JSONL** (um JSON por linha) e gerar um relatório em **JSON** via **Ollama**.

> Observação: o monitoramento usa `watcher.ps1`. Se a assinatura do log Security não for autorizada, ele cai automaticamente em um modo de polling.

## Requisitos
- Windows + PowerShell (5.1 ou 7+)
- Python 3.x
- Para análise: Ollama rodando localmente (default `http://localhost:11434`).

## Monitoramento (tempo real)

### Exemplos

```powershell
# Monitorar e imprimir no console
python .\ferramenta.py --stdout

# Monitorar e gravar em JSONL
python .\ferramenta.py --json --log-file C:\logs\acessos.jsonl

# Apenas falhas (4625)
python .\ferramenta.py --only 4625 --stdout

# Rodar em background
python .\ferramenta.py --background --json --log-file C:\logs\acessos.jsonl
```

## Análise (Ollama)

> **Entrada:** arquivo JSONL produzido pela ferramenta em monitoramento com `--json`.

```powershell
python .\ferramenta.py --analyze \
  --log-file C:\logs\acessos.jsonl \
  --from "2025-11-03T21:00:00-03:00" \
  --to   "2025-11-03T22:00:00-03:00" \
  --ollama-model "qwen3.5:latest" \
  --analysis-out .\reports\relatorio_2025-11-03_21-22.json
```

O relatório gerado (`--analysis-out`) conterá:
- estatísticas agregadas do intervalo
- amostra de eventos
- análise do modelo (em JSON)

## Arquivos
- `ferramenta.py`: CLI (monitoramento e análise)
- `monitor_core.py`: núcleo do monitoramento + logging com rotação
- `watcher.ps1`: coleta eventos do Windows em tempo real (com fallback)
- `ollama_analyzer.py`: integra /api/generate do Ollama para análise do intervalo
