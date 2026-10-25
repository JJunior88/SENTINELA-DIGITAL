"""Inicializador para uso no computador e empacotamento com PyInstaller."""
import os
from pathlib import Path
import sys
import threading
import webbrowser

import app


def main():
    if getattr(sys, 'frozen', False):
        app.ROOT = Path(sys._MEIPASS)
    base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'share')))
    app.DB = Path(os.environ.get('SENTINELA_DB', str(base / 'SentinelaDigital' / 'sentinela.db')))
    with app.connect() as db:
        db.execute('SELECT 1')
    server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
    url = f'http://127.0.0.1:{server.server_port}/'
    print(f'SENTINELA_URL={url}', flush=True)
    print('Sentinela Digital iniciado. Feche esta janela para encerrar.', flush=True)
    print(f'Banco de dados: {app.DB}', flush=True)
    if os.environ.get('SENTINELA_NO_BROWSER') != '1':
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    if os.environ.get('SENTINELA_TEST_CONTROL') == '1':
        def control():
            if sys.stdin.readline().strip() == 'STOP':
                server.shutdown()
        threading.Thread(target=control, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
