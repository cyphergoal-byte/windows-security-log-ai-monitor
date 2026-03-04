# Windows Security Log AI Monitor

Cybersecurity tool in **Python** that monitors Windows authentication events and can generate an automated security analysis using **AI (Ollama)**.

> **Autor:** Diogo Carvalho Conceição  
> **RM:** 566792  
> **Disciplina:** Coding (FIAP)  

---

## Objetivo

Construir uma ferramenta para:

- Monitorar eventos de autenticação do **Windows Event Log (Security)**
- Registrar eventos em **JSONL** (um evento por linha)
- Analisar um intervalo de eventos com **IA via Ollama** para identificar padrões suspeitos

---

## Eventos monitorados (Windows Security Log)

- **4624** — Logon bem-sucedido  
- **4625** — Logon falhou (tentativa inválida)  
- **4634** — Logoff  

Esses eventos são úteis para observar comportamentos como:
- múltiplas tentativas de login falhas (força bruta)
- horários incomuns de autenticação
- usuários e padrões recorrentes

---

## Funcionalidades

- **Monitoramento em tempo real** do log de segurança do Windows
- **Armazenamento estruturado** (JSON/JSONL)
- **Logs do próprio app** com `logging` (inclui rotação)
- **Modo de análise por IA** (Ollama) para gerar relatório automático

---

## Tecnologias e bibliotecas

- Python 3.x  
- `argparse` (CLI)  
- `datetime` (datas/horas)  
- `logging` (registro e rastreabilidade)  
- PowerShell (captura de eventos do Windows)  
- JSON / JSONL (estruturação)  
- Ollama (análise por IA)

---

## Requisitos

- Windows 10/11
- PowerShell **5.1+** (ou 7+)
- Python **3.x**
- (Opcional) **Ollama** instalado e rodando localmente

---

## Como executar

### 1) Clonar o repositório

```bash
git clone https://github.com/cyphergoal-byte/windows-security-log-ai-monitor.git
cd windows-security-log-ai-monitor
