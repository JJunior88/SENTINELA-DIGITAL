"""Servidor local do Sentinela Digital, sem dependências externas."""
import json
import os
import sqlite3
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('SENTINELA_DB', str(ROOT / 'data' / 'sentinela.db')))
KINDS = {'auditoria', 'incidente', 'recuperacao'}
STATUSES = {'Aberto', 'Em andamento', 'Concluído'}
PRIORITIES = {'Baixa', 'Média', 'Alta', 'Crítica'}


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
    def reply(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
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
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
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
