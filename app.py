"""Servidor local do Sentinela Digital, sem dependências externas."""
import json
import os
import sqlite3
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit, parse_qs

from security import SecurityService

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('SENTINELA_DB', str(ROOT / 'data' / 'sentinela.db')))
KINDS = {'auditoria', 'incidente', 'recuperacao'}
STATUSES = {'Aberto', 'Em andamento', 'Concluído'}
PRIORITIES = {'Baixa', 'Média', 'Alta', 'Crítica'}
SECURITY = SecurityService()


@contextmanager
def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB)
    try:
        db.row_factory = sqlite3.Row
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, kind TEXT, title TEXT, asset TEXT, priority TEXT, status TEXT, notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)')
            yield db
    finally:
        db.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Não registre códigos OAuth nem os parâmetros da URL de retorno.
        if urlsplit(self.path).path != '/oauth/callback':
            super().log_message(format, *args)

    def local_request(self, mutation=False):
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if self.headers.get('Host') not in allowed:
            self.reply(403, {'error': 'Acesso permitido somente pelo endereço local do aplicativo'})
            return False
        origin = self.headers.get('Origin')
        if (origin and origin not in {'http://' + h for h in allowed}) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            # O retorno OAuth vem de uma navegação externa e é validado por state + PKCE.
            if urlsplit(self.path).path != '/oauth/callback' or mutation:
                self.reply(403, {'error': 'Origem não autorizada'})
                return False
        if mutation and self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            self.reply(415, {'error': 'Envie application/json'})
            return False
        return True

    def reply(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.local_request():
            return
        if self.path == '/api/security':
            return self.reply(200, SECURITY.status())
        if self.path == '/security-ui.js':
            data = (ROOT / 'security-ui.js').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(data)
            return
        if urlsplit(self.path).path == '/oauth/callback':
            try:
                SECURITY.callback(parse_qs(urlsplit(self.path).query))
            except ValueError as error:
                return self.reply(400, {'error': str(error)})
            self.send_response(303)
            self.send_header('Location', '/')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers()
            return
        if self.path == '/api/records':
            with connect() as db:
                records = [dict(r) for r in db.execute('SELECT * FROM records ORDER BY created_at DESC, rowid DESC')]
            return self.reply(200, records)
        if self.path == '/api/health':
            with connect() as db:
                db.execute('SELECT 1')
            return self.reply(200, {'status': 'ok'})
        if self.path != '/':
            return self.reply(404, {'error': 'Recurso não encontrado'})
        data = (ROOT / 'index.html').read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if not self.local_request(mutation=True):
            return
        if self.path in {'/api/google/connect', '/api/google/disconnect', '/api/google/scan', '/api/pc/status', '/api/pc/scan'}:
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 32768:
                    raise ValueError('Solicitação inválida')
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict):
                    raise ValueError('Solicitação inválida')
                if self.path == '/api/google/connect':
                    redirect = f'http://127.0.0.1:{self.server.server_port}/oauth/callback'
                    return self.reply(200, {'url': SECURITY.authorize(payload, redirect)})
                if self.path == '/api/google/disconnect':
                    SECURITY.disconnect()
                elif self.path == '/api/google/scan':
                    SECURITY.scan_drive()
                else:
                    if self.path == '/api/pc/scan' and payload.get('confirmed') is not True:
                        raise ValueError('Confirme a varredura: o Defender pode aplicar as ações de proteção configuradas no Windows.')
                    SECURITY.scan_pc(self.path == '/api/pc/scan')
                return self.reply(202, {'status': 'accepted'})
            except (ValueError, UnicodeDecodeError) as error:
                return self.reply(400, {'error': str(error) if not isinstance(error, json.JSONDecodeError) else 'JSON inválido'})
        if self.path != '/api/records':
            return self.reply(404, {'error': 'Recurso não encontrado'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 32768:
                return self.reply(400, {'error': 'Tamanho de solicitação inválido'})
            record = json.loads(self.rfile.read(size))
            if not isinstance(record, dict):
                raise ValueError()
            fields = ('kind', 'title', 'asset', 'priority', 'status', 'notes')
            if any(not isinstance(record.get(f, ''), str) for f in fields):
                raise ValueError()
            record = {f: record.get(f, '').strip() for f in fields}
            if record['kind'] not in KINDS or record['status'] not in STATUSES or record['priority'] not in PRIORITIES:
                raise ValueError()
            if not record['title'] or len(record['title']) > 160 or not record['asset'] or len(record['asset']) > 200 or len(record['notes']) > 5000:
                raise ValueError()
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {'error': 'Confira os campos enviados'})
        record['id'] = str(uuid4())
        with connect() as db:
            db.execute('INSERT INTO records (id, kind, title, asset, priority, status, notes) VALUES (:id, :kind, :title, :asset, :priority, :status, :notes)', record)
        return self.reply(201, record)

    def do_PATCH(self):
        if not self.local_request(mutation=True):
            return
        if not self.path.startswith('/api/records/'):
            return self.reply(404, {'error': 'Recurso não encontrado'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 1024:
                raise ValueError()
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict) or payload.get('status') not in STATUSES:
                raise ValueError()
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {'error': 'Status inválido'})
        with connect() as db:
            result = db.execute('UPDATE records SET status = ? WHERE id = ?', (payload['status'], self.path.rsplit('/', 1)[-1]))
            if not result.rowcount:
                return self.reply(404, {'error': 'Registro não encontrado'})
        return self.reply(200, {'status': payload['status']})


if __name__ == '__main__':
    server = ThreadingHTTPServer((os.environ.get('HOST', '127.0.0.1'), int(os.environ.get('PORT', '8000'))), Handler)
    print('Sentinela Digital disponível na porta', server.server_port, flush=True)
    server.serve_forever()
