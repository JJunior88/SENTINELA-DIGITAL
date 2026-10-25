"""Valida o inicializador real, inclusive o executável empacotado no Windows."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen


with tempfile.TemporaryDirectory() as tmp:
    output = Path(tmp) / 'startup.log'
    env = dict(os.environ, SENTINELA_NO_BROWSER='1', SENTINELA_DB=str(Path(tmp) / 'records.db'))
    command = sys.argv[1:] or [sys.executable, 'desktop.py']
    with output.open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            url = None
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                text = output.read_text(errors='replace')
                for line in text.splitlines():
                    if line.startswith('SENTINELA_URL='):
                        url = line.split('=', 1)[1]
                if url:
                    break
                if process.poll() is not None:
                    raise RuntimeError(text)
                time.sleep(0.2)
            if not url:
                raise RuntimeError('O aplicativo não iniciou em 45 segundos')
            with urlopen(url, timeout=5) as response:
                assert 'Novo registro' in response.read().decode()
            with urlopen(url + 'api/health', timeout=5) as response:
                assert json.load(response)['status'] == 'ok'
            record = dict(kind='auditoria', title='Teste desktop', asset='PC', priority='Baixa', status='Aberto', notes='')
            request = Request(url + 'api/records', data=json.dumps(record).encode(), headers={'Content-Type': 'application/json'})
            with urlopen(request, timeout=5) as response:
                assert response.status == 201
            with urlopen(url + 'api/records', timeout=5) as response:
                assert json.load(response)[0]['title'] == 'Teste desktop'
            assert Path(env['SENTINELA_DB']).is_file()
            print('Desktop OK: interface, saúde, cadastro e banco de dados.')
        finally:
            process.terminate()
            process.wait(timeout=10)
