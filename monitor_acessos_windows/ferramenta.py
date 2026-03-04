# -*- coding: utf-8 -*-
"""ferramenta.py

CLI da ferramenta:
- Modo padrão: monitoramento em tempo real do Log de Segurança do Windows.
- Modo análise: lê um arquivo JSONL (gerado com --json) e gera um relatório (JSON) via Ollama.
"""

from __future__ import annotations

import argparse
import sys
import os
import shutil
import json
from pathlib import Path

from monitor_core import AccessMonitor
from ollama_analyzer import analyze_jsonl_interval_with_ollama

DEFAULT_EVENTS = [4624, 4625, 4634]


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description='Monitor/Analisador de tentativas de acesso (logons) no Windows (Security Log).',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # --- comuns ---
    p.add_argument('--log-file', default=str(Path('logs') / 'access_monitor.jsonl'),
                   help='No monitoramento: destino do log. Na análise: caminho do arquivo JSONL de entrada.')

    # --- monitoramento ---
    p.add_argument('--json', action='store_true', help='No monitoramento, grava o log em formato JSON por linha (JSONL).')
    p.add_argument('--stdout', action='store_true', help='No monitoramento, também imprime no console.')
    p.add_argument('--include-success', action='store_true', default=True, help='Incluir logons bem-sucedidos (4624).')
    p.add_argument('--include-failure', action='store_true', default=True, help='Incluir logons mal-sucedidos (4625).')
    p.add_argument('--only', nargs='+', type=int, default=None, help='Substitui a lista de Event IDs monitorados (ex.: 4624 4625 4634).')
    p.add_argument('--max-bytes', type=int, default=5 * 1024 * 1024, help='Tamanho máximo do arquivo de log antes da rotação.')
    p.add_argument('--backups', type=int, default=5, help='Quantidade de arquivos de backup de log mantidos.')
    p.add_argument('--background', action='store_true', help='No monitoramento, tenta rodar em segundo plano via pythonw.exe (Windows).')
    p.add_argument('--detached', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--verbose', action='store_true', help='Ativa saída no console (equivale a --stdout).')

    # --- análise (Ollama) ---
    p.add_argument('--analyze', action='store_true',
                   help='Analisa um intervalo do arquivo JSONL e gera relatório em JSON via Ollama (não monitora em tempo real).')
    p.add_argument('--from', dest='start_time',
                   help='Início do intervalo (ISO-8601, ex.: 2025-11-03T21:00:00-03:00).')
    p.add_argument('--to', dest='end_time',
                   help='Fim do intervalo (ISO-8601, ex.: 2025-11-03T22:00:00-03:00).')
    p.add_argument('--analysis-out', default=str(Path('reports') / 'analysis.json'),
                   help='Arquivo JSON de saída com estatísticas + análise do Ollama.')
    p.add_argument('--ollama-url', default='http://localhost:11434/api/generate',
                   help='Endpoint do Ollama (padrão: /api/generate).')
    p.add_argument('--ollama-model', default='qwen3.5:latest',
                   help='Modelo Ollama (ex.: qwen3.5:latest).')

    return p.parse_args(argv)


def relaunch_background() -> bool:
    """Relança o processo via pythonw.exe (ou start /b) para rodar sem console."""
    if os.name != 'nt':
        print('--background é suportado apenas no Windows.')
        return False

    pyw = Path(sys.executable).with_name('pythonw.exe')
    if pyw.exists():
        cmd = [str(pyw), __file__, '--detached']
        for a in sys.argv[1:]:
            if a != '--background':
                cmd.append(a)
        os.spawnv(os.P_NOWAIT, str(pyw), cmd)
        return True

    # fallback com cmd/start
    try:
        cmd = ['cmd', '/c', 'start', '"MonitorAcessos"', '/b', sys.executable, __file__, '--detached']
        for a in sys.argv[1:]:
            if a != '--background':
                cmd.append(a)
        os.spawnv(os.P_NOWAIT, shutil.which('cmd'), cmd)
        return True
    except Exception as e:
        print('Falha ao iniciar em background:', e)
        return False


def main(argv=None) -> int:
    ns = parse_args(argv)

    # ------------------- MODO ANÁLISE -------------------
    if ns.analyze:
        if not ns.start_time or not ns.end_time:
            print('Erro: para --analyze, informe --from e --to em ISO-8601.')
            return 2
        in_path = Path(ns.log_file)
        if not in_path.exists():
            print(f'Erro: arquivo JSONL não encontrado: {in_path}')
            return 2
        out_path = Path(ns.analysis_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            result = analyze_jsonl_interval_with_ollama(
                log_path=str(in_path),
                start_iso=ns.start_time,
                end_iso=ns.end_time,
                ollama_url=ns.ollama_url,
                model=ns.ollama_model,
                include_event_ids=(4624, 4625, 4634),
            )
        except Exception as e:
            print('Falha na análise:', e)
            return 1

        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'Relatório salvo em: {out_path}')
        return 0

    # ------------------- MODO MONITORAMENTO -------------------
    if ns.verbose:
        ns.stdout = True

    if ns.background and not ns.detached:
        if relaunch_background():
            print('Monitor iniciado em background.')
            return 0
        print('Não foi possível iniciar em background. Continuando em primeiro plano...')

    events = ns.only if ns.only else DEFAULT_EVENTS

    mon = AccessMonitor(
        log_file=Path(ns.log_file),
        event_ids=events,
        json_format=ns.json,
        include_success=ns.include_success,
        include_failure=ns.include_failure,
        console=ns.stdout,
        log_max_bytes=ns.max_bytes,
        log_backup_count=ns.backups,
    )

    try:
        mon.run()
    except KeyboardInterrupt:
        pass
    finally:
        mon.stop()

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
