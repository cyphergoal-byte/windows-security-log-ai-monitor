# -*- coding: utf-8 -*-
"""ollama_analyzer.py

Funções para analisar um intervalo de tempo de eventos em um arquivo JSONL (um JSON por linha)
produzido pela ferramenta e pedir uma análise para um modelo via API local do Ollama.

Usa /api/generate com stream=false e format="json".
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from collections import Counter
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


def _parse_iso_to_utc(dt_str: str) -> datetime:
    s = dt_str.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _bucket_minute(dt: datetime) -> str:
    return dt.replace(second=0, microsecond=0).isoformat()


def analyze_jsonl_interval_with_ollama(
    *,
    log_path: str,
    start_iso: str,
    end_iso: str,
    ollama_url: str = 'http://localhost:11434/api/generate',
    model: str = 'qwen3.5:latest',
    include_event_ids=(4624, 4625, 4634),
    max_events: int = 20000,
    sample_events: int = 40,
    timeout_sec: int = 90,
) -> dict:
    start_dt = _parse_iso_to_utc(start_iso)
    end_dt = _parse_iso_to_utc(end_iso)
    if end_dt < start_dt:
        raise ValueError('end_iso deve ser >= start_iso')

    events = []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = ev.get('timestamp_utc')
            if not ts:
                continue
            try:
                ts_utc = _parse_iso_to_utc(ts)
            except Exception:
                continue

            if not (start_dt <= ts_utc <= end_dt):
                continue

            try:
                eid = int(ev.get('event_id'))
            except Exception:
                continue
            if eid not in include_event_ids:
                continue

            ev['_ts_utc'] = ts_utc
            events.append(ev)
            if len(events) >= max_events:
                break

    total = len(events)
    by_event_id = Counter(str(e.get('event_id')) for e in events)
    by_outcome = Counter((str(e.get('outcome') or '')).upper() for e in events)

    users = Counter()
    ips = Counter()
    logon_types = Counter()
    per_minute = Counter()
    per_ip_minute = Counter()

    for e in events:
        outcome = (str(e.get('outcome') or '')).upper()
        user = (e.get('target_user') or '').strip() or '(vazio)'
        ip = (e.get('ip_address') or '').strip() or '(sem_ip)'
        lt = str(e.get('logon_type') or '').strip() or '(sem_tipo)'
        minute = _bucket_minute(e['_ts_utc'])

        users[user] += 1
        ips[ip] += 1
        logon_types[lt] += 1
        per_minute[minute] += 1

        if str(e.get('event_id')) == '4625' or outcome == 'FAILURE':
            per_ip_minute[(ip, minute)] += 1

    stats = {
        'interval_utc': {'start': start_dt.isoformat(), 'end': end_dt.isoformat()},
        'total_events': total,
        'by_event_id': dict(by_event_id),
        'by_outcome': dict(by_outcome),
        'top_users': users.most_common(10),
        'top_ips': ips.most_common(10),
        'top_logon_types': logon_types.most_common(10),
        'top_minutes_by_volume': per_minute.most_common(10),
        'top_failure_ip_minute': [
            {'ip': ip, 'minute': minute, 'failures': c}
            for (ip, minute), c in per_ip_minute.most_common(10)
        ],
        'limits': {'max_events_read': max_events, 'sample_events': sample_events},
    }

    sample = []
    for e in events[:sample_events]:
        sample.append({
            'timestamp_utc': e['_ts_utc'].isoformat(),
            'event_id': e.get('event_id'),
            'outcome': e.get('outcome'),
            'target_user': e.get('target_user'),
            'ip_address': e.get('ip_address'),
            'logon_type': e.get('logon_type'),
            'logon_type_name': e.get('logon_type_name'),
            'status': e.get('status'),
            'substatus': e.get('substatus'),
            'failure_reason': e.get('failure_reason'),
            'computer': e.get('computer'),
        })

    prompt = f"""
Você é um analista SOC (Blue Team). Analise eventos de autenticação do Windows no intervalo UTC:
[{start_dt.isoformat()} .. {end_dt.isoformat()}]

Os eventos incluem:
- 4624 (logon bem-sucedido)
- 4625 (logon falhou)
- 4634 (logoff)

REGRAS:
- Responda APENAS em JSON válido.
- Não invente dados: use somente o que está nas estatísticas e amostra.
- Identifique padrões suspeitos (brute force, password spraying, picos por IP/minuto).
- Diferencie o que é “provável” vs “confirmado”.
- Sugira ações concretas de mitigação e investigação.

ESTATÍSTICAS (agregadas e confiáveis):
{json.dumps(stats, ensure_ascii=False, indent=2)}

AMOSTRA DE EVENTOS:
{json.dumps(sample, ensure_ascii=False, indent=2)}

SAÍDA JSON NO FORMATO:
{{
  "resumo_executivo": "...",
  "janela_analisada_utc": {{"inicio":"...", "fim":"..."}},
  "visao_geral": {{
    "total_eventos": 0,
    "contagem_por_event_id": {{"4624":0,"4625":0,"4634":0}},
    "contagem_por_resultado": {{"SUCCESS":0,"FAILURE":0,"OTHER":0}}
  }},
  "indicadores": {{
    "sinais_bruteforce": true,
    "sinais_password_spraying": false,
    "picos_relevantes": [{{"minuto":"...", "total":0, "observacao":"..."}}],
    "ips_suspeitos": [{{"ip":"...", "contagem":0, "observacao":"..."}}],
    "usuarios_alvo": [{{"user":"...", "contagem":0}}]
  }},
  "achados": [
    {{"titulo":"...", "evidencia":"...", "impacto":"...", "severidade":"baixa|media|alta"}}
  ],
  "recomendacoes": [
    {{"acao":"...", "prioridade":"baixa|media|alta", "como_fazer":"..."}}
  ],
  "perguntas_para_investigacao": ["..."]
}}
""".strip()

    payload = {
        'model': model,
        'prompt': prompt,
        'stream': False,
        'format': 'json',
    }

    req = Request(
        ollama_url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
            ollama_resp = json.loads(raw)
    except HTTPError as e:
        raise RuntimeError(f'Erro HTTP ao chamar Ollama: {e.code} {e.reason}') from e
    except URLError as e:
        raise RuntimeError(f'Falha ao conectar no Ollama ({ollama_url}): {e}') from e
    except json.JSONDecodeError:
        raise RuntimeError('Resposta do Ollama não é JSON válido')

    analysis_text = (ollama_resp.get('response') or '').strip()
    try:
        analysis = json.loads(analysis_text) if analysis_text else {'erro': 'Resposta vazia do modelo'}
    except json.JSONDecodeError:
        analysis = {'erro': 'Modelo não retornou JSON válido', 'response_text': analysis_text}

    return {
        'interval': {'start_utc': start_dt.isoformat(), 'end_utc': end_dt.isoformat()},
        'stats': stats,
        'ollama': {
            'model': ollama_resp.get('model'),
            'created_at': ollama_resp.get('created_at'),
            'analysis': analysis,
            'raw_response_text': analysis_text,
        },
        'events_used': total,
    }
