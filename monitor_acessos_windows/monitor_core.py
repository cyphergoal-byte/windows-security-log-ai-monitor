# -*- coding: utf-8 -*-
"""monitor_core.py

Núcleo do monitoramento em tempo real de tentativas de acesso no Windows.

- Executa watcher.ps1 (PowerShell) que emite eventos do Windows Event Log em JSON (uma linha por evento).
- No Python, filtra, formata e registra em arquivo com rotação (logging + RotatingFileHandler).

Bibliotecas obrigatórias (no projeto): argparse (na CLI), datetime, logging.
Bibliotecas stdlib adicionais usadas aqui: subprocess, json, signal, threading, pathlib, os.
"""

from __future__ import annotations

import sys
import os
import json
import signal
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

import logging
from logging.handlers import RotatingFileHandler

LOGON_TYPE_MAP = {
    '2': 'Interactive',
    '3': 'Network',
    '4': 'Batch',
    '5': 'Service',
    '7': 'Unlock',
    '8': 'NetworkCleartext',
    '9': 'NewCredentials',
    '10': 'RemoteInteractive',
    '11': 'CachedInteractive',
}


class PowerShellStreamer:
    """Executa watcher.ps1 e expõe stdout/stderr linha a linha."""

    def __init__(self, xpath: str, logname: str = 'Security'):
        self.xpath = xpath
        self.logname = logname
        self.proc: Optional[subprocess.Popen] = None
        self._stop_evt = threading.Event()

    @staticmethod
    def _pwsh_exe() -> str:
        for exe in ("pwsh", "powershell"):
            try:
                subprocess.run(
                    [exe, '-NoLogo', '-NoProfile', '-Command', '$PSVersionTable.PSVersion.ToString()'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                return exe
            except Exception:
                continue
        return 'powershell'

    def start(self) -> None:
        ps = self._pwsh_exe()
        script_path = Path(__file__).with_name('watcher.ps1')
        args = [
            ps,
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            str(script_path),
            '-LogName',
            self.logname,
            '-XPathFilter',
            self.xpath,
        ]
        creationflags = 0
        if os.name == 'nt':
            creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )

    def stop(self) -> None:
        self._stop_evt.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def iter_lines(self):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            if self._stop_evt.is_set():
                break
            yield line

    def errors(self):
        if not self.proc or not self.proc.stderr:
            return
        for line in self.proc.stderr:
            if self._stop_evt.is_set():
                break
            yield line


def _safe_get(d: Dict[str, Any], *path: str, default=None):
    cur: Any = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _parse_time(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.now(timezone.utc)
    try:
        if ts.endswith('Z'):
            ts2 = ts[:-1]
            if '.' in ts2:
                base, frac = ts2.split('.')
                frac = (frac + '000000')[:6]
                dt = datetime.fromisoformat(base + '.' + frac)
            else:
                dt = datetime.fromisoformat(ts2)
            return dt.replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def build_xpath(event_ids: list[int]) -> str:
    conds = ' or '.join(f"EventID={eid}" for eid in event_ids)
    return f"*[System[({conds})]]"


class AccessMonitor:
    def __init__(
        self,
        *,
        log_file: Path,
        event_ids: list[int],
        json_format: bool = False,
        include_success: bool = True,
        include_failure: bool = True,
        console: bool = False,
        log_max_bytes: int = 5 * 1024 * 1024,
        log_backup_count: int = 5,
    ):
        self.log_file = Path(log_file)
        self.event_ids = event_ids
        self.json_format = json_format
        self.include_success = include_success
        self.include_failure = include_failure
        self.console = console

        self._logger = logging.getLogger('monitor_acessos')
        self._logger.setLevel(logging.INFO)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        handler = RotatingFileHandler(
            self.log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
            encoding='utf-8',
        )
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(fmt)
        self._logger.addHandler(handler)

        if console:
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(fmt)
            self._logger.addHandler(ch)

        self._ps = PowerShellStreamer(build_xpath(self.event_ids))

    def _should_keep(self, event_id: str) -> bool:
        if not event_id:
            return False
        try:
            if int(event_id) not in self.event_ids:
                return False
        except Exception:
            return False
        if event_id == '4624' and not self.include_success:
            return False
        if event_id == '4625' and not self.include_failure:
            return False
        return True

    def _format_record(self, ev: Dict[str, Any]) -> str:
        sysn = ev.get('System', {}) if isinstance(ev.get('System'), dict) else {}

        # watcher.ps1 (v3.1) emite EventID como string em System.EventID
        event_id = str(sysn.get('EventID') or '')
        comp = str(sysn.get('Computer') or '')
        ts = str(sysn.get('TimeCreated') or '')
        dt = _parse_time(ts)

        eventdata = ev.get('EventData', {}) if isinstance(ev.get('EventData'), dict) else {}

        tgt_user = (eventdata.get('TargetUserName') or eventdata.get('SubjectUserName') or '').strip()
        ipaddr = (eventdata.get('IpAddress') or '').strip()
        logon_type = str(eventdata.get('LogonType') or '').strip()
        logon_type_name = LOGON_TYPE_MAP.get(logon_type, '')
        status = (eventdata.get('Status') or '').lower()
        substatus = (eventdata.get('SubStatus') or '').lower()
        failure_reason = eventdata.get('FailureReason') or ''

        outcome = 'OTHER'
        if event_id == '4624':
            outcome = 'SUCCESS'
        elif event_id == '4625':
            outcome = 'FAILURE'

        rec = {
            'timestamp_utc': dt.isoformat(),
            'computer': comp,
            'event_id': event_id,
            'outcome': outcome,
            'target_user': tgt_user,
            'ip_address': ipaddr,
            'logon_type': logon_type,
            'logon_type_name': logon_type_name,
            'status': status,
            'substatus': substatus,
            'failure_reason': failure_reason,
        }

        if self.json_format:
            return json.dumps(rec, ensure_ascii=False)

        pieces = [
            f"[{outcome}] EventID={event_id}",
            f"user={tgt_user}" if tgt_user else "user=-",
            f"type={logon_type}({logon_type_name})" if logon_type else "type=?",
            f"ip={ipaddr}" if ipaddr else "ip=-",
            f"host={comp}" if comp else "",
            f"status={status}/{substatus}" if outcome == 'FAILURE' and (status or substatus) else "",
        ]
        line = ' '.join(p for p in pieces if p)
        return f"{dt.isoformat()} {line}"

    def run(self) -> None:
        self._ps.start()

        def _stderr_thread():
            for err in self._ps.errors() or []:
                e = err.strip()
                if e:
                    self._logger.error(f"PowerShell: {e}")

        threading.Thread(target=_stderr_thread, daemon=True).start()

        def handle_signal(signum, frame):
            self._logger.info(f"Sinal {signum} recebido. Encerrando...")
            self.stop()

        try:
            signal.signal(signal.SIGINT, handle_signal)
            if hasattr(signal, 'SIGTERM'):
                signal.signal(signal.SIGTERM, handle_signal)
        except Exception:
            pass

        for line in self._ps.iter_lines() or []:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            sysn = ev.get('System', {}) if isinstance(ev.get('System'), dict) else {}
            event_id = str(sysn.get('EventID') or '')
            if not self._should_keep(event_id):
                continue

            msg = self._format_record(ev)
            self._logger.info(msg)

    def stop(self) -> None:
        self._ps.stop()
