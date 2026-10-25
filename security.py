"""Integrações de leitura do Drive e varredura local pelo Microsoft Defender.

Credenciais e relatórios permanecem somente na memória desta execução.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SCOPE = 'https://www.googleapis.com/auth/drive.metadata.readonly'
RISK_EXTENSIONS = {'.exe', '.msi', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.dll', '.lnk', '.docm', '.xlsm'}


def google_request(url, token=None, data=None):
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = None
    if data is not None:
        body = urlencode(data).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    try:
        with urlopen(Request(url, data=body, headers=headers), timeout=30) as response:
            return json.load(response)
    except HTTPError as error:
        messages = {
            400: 'O Google recusou a autorização. Confira o aplicativo OAuth e conecte novamente.',
            401: 'A autorização expirou ou foi revogada. Conecte novamente.',
            403: 'Acesso negado pelo Google. Confira a Drive API, o consentimento e os usuários de teste.',
            429: 'Limite do Google atingido. Aguarde antes de tentar novamente.',
        }
        raise ValueError(messages.get(error.code, 'O serviço Google está indisponível. Tente novamente.')) from None
    except (URLError, TimeoutError, OSError):
        raise ValueError('Não foi possível conectar ao Google. Confira sua conexão.') from None


def review_files(files):
    findings = []
    for file in files:
        reasons = []
        name = file.get('name', '')
        if Path(name.lower()).suffix in RISK_EXTENSIONS:
            reasons.append('Formato executável, script ou documento com macros; revise a origem antes de abrir.')
        if file.get('shared'):
            reasons.append('Arquivo compartilhado: revise quem tem acesso. Isso não significa que seja público.')
        if reasons:
            findings.append({'name': name, 'id': file.get('id', ''), 'reasons': reasons})
    return findings


DEFENDER_STATUS = (
    "$status = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanStartTime,QuickScanEndTime; "
    "$history = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 ThreatID,InitialDetectionTime,ActionSuccess,Resources); "
    "@{protection=$status; history=$history} | ConvertTo-Json -Depth 6 -Compress"
)
DEFENDER_SCAN = "Start-MpScan -ScanType QuickScan; " + DEFENDER_STATUS


def run_defender(scan=False):
    if os.name != 'nt':
        raise ValueError('Microsoft Defender está disponível somente no Windows. Execute o aplicativo no seu PC.')
    executable = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    if not executable.is_file():
        raise ValueError('Windows PowerShell não foi encontrado neste computador.')
    script = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    script += DEFENDER_SCAN if scan else DEFENDER_STATUS
    try:
        result = subprocess.run([str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, encoding='utf-8-sig', errors='replace',
                                timeout=1800 if scan else 30, creationflags=0x08000000)
    except subprocess.TimeoutExpired:
        raise ValueError('A consulta excedeu o tempo limite. A varredura pode continuar no Windows; confira a Segurança do Windows.') from None
    except OSError:
        raise ValueError('Não foi possível iniciar o Microsoft Defender neste PC.') from None
    if result.returncode:
        raise ValueError('O Defender não concluiu a operação. Confira se ele está ativo e se sua conta tem permissão na Segurança do Windows. Não desative outro antivírus.')
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict) or not isinstance(data.get('protection'), dict) or 'AntivirusEnabled' not in data['protection']:
            raise ValueError()
        return data
    except (ValueError, TypeError):
        raise ValueError('O Windows retornou um resultado inesperado. Confira a Segurança do Windows.') from None


class SecurityService:
    def __init__(self):
        self.lock = threading.RLock()
        self.pending = None
        self.token = None
        self.expires = 0
        self.generation = 0
        self.drive = {'status': 'idle'}
        self.pc = {'status': 'idle'}

    def status(self):
        with self.lock:
            return {'google_connected': bool(self.token and time.monotonic() < self.expires),
                    'drive': self.drive, 'pc': self.pc, 'windows': os.name == 'nt'}

    def authorize(self, config, redirect):
        if not isinstance(config, dict):
            raise ValueError('Selecione o JSON de um cliente OAuth do tipo Aplicativo para computador.')
        installed = config.get('installed')
        if not isinstance(installed, dict):
            raise ValueError('O arquivo precisa ser de um cliente OAuth do tipo Aplicativo para computador.')
        client_id = installed.get('client_id', '')
        secret = installed.get('client_secret', '')
        if not isinstance(client_id, str) or not client_id.endswith('.apps.googleusercontent.com') or len(client_id) > 300:
            raise ValueError('Client ID do Google inválido.')
        if not isinstance(secret, str) or len(secret) > 500:
            raise ValueError('Configuração OAuth inválida.')
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        with self.lock:
            self.pending = dict(state=state, verifier=verifier, client_id=client_id, secret=secret,
                                redirect=redirect, expires=time.monotonic() + 600)
        return 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode({
            'client_id': client_id, 'redirect_uri': redirect, 'response_type': 'code',
            'scope': SCOPE, 'state': state, 'code_challenge': challenge,
            'code_challenge_method': 'S256', 'access_type': 'online', 'prompt': 'select_account consent'})

    def callback(self, params):
        state = params.get('state', [''])[0]
        with self.lock:
            pending = self.pending
            if not pending or time.monotonic() > pending['expires'] or not secrets.compare_digest(state, pending['state']):
                raise ValueError('Autorização inválida ou expirada. Inicie a conexão novamente.')
            self.pending = None
            generation = self.generation
        if params.get('error'):
            raise ValueError('A autorização não foi concedida pelo Google. Você pode tentar novamente.')
        code = params.get('code', [''])[0]
        if not code:
            raise ValueError('O Google não retornou uma autorização válida.')
        data = google_request('https://oauth2.googleapis.com/token', data={
            'code': code, 'client_id': pending['client_id'], 'client_secret': pending['secret'],
            'redirect_uri': pending['redirect'], 'grant_type': 'authorization_code',
            'code_verifier': pending['verifier']})
        if not isinstance(data.get('access_token'), str) or SCOPE not in data.get('scope', '').split():
            raise ValueError('A permissão de leitura dos metadados do Drive não foi concedida.')
        with self.lock:
            if self.generation != generation:
                raise ValueError('Esta conexão foi cancelada. Conecte novamente.')
            self.generation += 1
            self.token = data['access_token']
            self.expires = time.monotonic() + max(0, int(data.get('expires_in', 3600)) - 30)
            self.drive = {'status': 'idle'}
        self.scan_drive()

    def disconnect(self):
        with self.lock:
            self.generation += 1
            self.token = self.pending = None
            self.expires = 0
            self.drive = {'status': 'idle'}

    def scan_drive(self):
        with self.lock:
            if not self.token or time.monotonic() >= self.expires:
                raise ValueError('Conecte sua conta Google antes de analisar o Drive.')
            if self.drive['status'] == 'running':
                raise ValueError('Uma revisão do Drive já está em andamento.')
            self.drive = {'status': 'running'}
            token, generation = self.token, self.generation
        def work():
            try:
                user = google_request('https://www.googleapis.com/drive/v3/about?' + urlencode({'fields': 'user(displayName,emailAddress)'}), token=token)
                files, page, incomplete = [], None, False
                for _ in range(10):
                    query = {'q': 'trashed = false', 'pageSize': 100,
                             'fields': 'nextPageToken,incompleteSearch,files(id,name,mimeType,shared)',
                             'spaces': 'drive', 'orderBy': 'modifiedTime desc'}
                    if page:
                        query['pageToken'] = page
                    data = google_request('https://www.googleapis.com/drive/v3/files?' + urlencode(query), token=token)
                    files.extend(data.get('files', []))
                    incomplete = incomplete or data.get('incompleteSearch', False)
                    page = data.get('nextPageToken')
                    if not page:
                        break
                report = {'status': 'complete', 'user': user.get('user', {}), 'reviewed': len(files),
                          'partial': bool(page or incomplete), 'findings': review_files(files)}
            except (ValueError, TypeError, KeyError):
                report = {'status': 'error', 'error': 'Não foi possível concluir a revisão. Verifique a Drive API, a conexão e a autorização Google; tente reconectar.'}
            with self.lock:
                if generation == self.generation:
                    self.drive = report
        threading.Thread(target=work, daemon=True).start()

    def scan_pc(self, scan):
        with self.lock:
            if self.pc['status'] == 'running':
                raise ValueError('Uma operação do Defender já está em andamento.')
            if os.name != 'nt':
                raise ValueError('Abra o aplicativo no seu PC Windows para usar o Microsoft Defender.')
            self.pc = {'status': 'running', 'operation': 'scan' if scan else 'status'}
        def work():
            try:
                result = run_defender(scan)
                report = {'status': 'complete', 'operation': 'scan' if scan else 'status', 'result': result}
            except ValueError as error:
                report = {'status': 'error', 'error': str(error)}
            with self.lock:
                self.pc = report
        threading.Thread(target=work, daemon=True).start()
