import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import app


class ApplicationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.DB
        app.DB = Path(self.temp.name) / 'test.db'
        self.start()

    def start(self):
        self.server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def tearDown(self):
        self.stop()
        app.DB = self.old_db
        self.temp.cleanup()

    def request(self, path, data=None, method=None):
        req = Request(self.url + path, data=json.dumps(data).encode() if data is not None else None,
                      headers={'Content-Type': 'application/json'}, method=method)
        with urlopen(req, timeout=5) as response:
            return json.load(response)

    def test_record_lifecycle_and_restart(self):
        self.assertEqual(self.request('/api/health'), {'status': 'ok'})
        self.assertEqual(self.request('/api/records'), [])
        for kind in app.KINDS:
            created = self.request('/api/records', {'kind': kind, 'title': 'Revisão de acessos',
                'asset': 'Portal', 'priority': 'Alta', 'status': 'Aberto', 'notes': 'Revisar permissões'})
            self.request('/api/records/' + created['id'], {'status': 'Concluído'}, 'PATCH')
        self.stop()
        self.start()
        records = self.request('/api/records')
        self.assertEqual(len(records), 3)
        self.assertTrue(all(r['status'] == 'Concluído' for r in records))
        self.assertTrue(all(r['notes'] == 'Revisar permissões' for r in records))

    def test_invalid_requests_and_missing_record(self):
        for payload in ({}, [], {'kind': 'incidente', 'title': ' ', 'asset': 'Portal',
                                  'priority': 'Alta', 'status': 'Aberto'}):
            with self.assertRaises(HTTPError) as error:
                self.request('/api/records', payload)
            self.assertEqual(error.exception.code, 400)
        with self.assertRaises(HTTPError) as error:
            self.request('/api/records/missing', {'status': 'Concluído'}, 'PATCH')
        self.assertEqual(error.exception.code, 404)
        self.assertEqual(self.request('/api/records'), [])

    def test_web_page(self):
        with urlopen(self.url + '/', timeout=5) as response:
            self.assertIn('Novo registro', response.read().decode())

    def test_database_connections_close(self):
        with app.connect() as db:
            db.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')
        with self.assertRaises(RuntimeError):
            with app.connect() as failed_db:
                raise RuntimeError('Falha simulada')
        with self.assertRaises(sqlite3.ProgrammingError):
            failed_db.execute('SELECT 1')


if __name__ == '__main__':
    unittest.main()
