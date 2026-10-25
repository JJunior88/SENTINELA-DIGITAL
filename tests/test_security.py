import base64
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import security


CONFIG = {'installed': {'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'test-only'}}


def immediate_thread(target, daemon):
    return SimpleNamespace(start=target)


class GoogleTest(unittest.TestCase):
    def setUp(self):
        self.service = security.SecurityService()

    def authorize(self):
        url = self.service.authorize(CONFIG, 'http://127.0.0.1:1234/oauth/callback')
        return parse_qs(urlsplit(url).query)

    def test_pkce_state_scope_and_secret_privacy(self):
        params = self.authorize()
        self.assertEqual(params['scope'], [security.SCOPE])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        digest = hashlib.sha256(self.service.pending['verifier'].encode()).digest()
        self.assertEqual(params['code_challenge'], [base64.urlsafe_b64encode(digest).rstrip(b'=').decode()])
        self.assertNotIn('client_secret', params)
        with patch('security.google_request') as request:
            with self.assertRaises(ValueError):
                self.service.callback({'state': ['wrong'], 'code': ['test']})
            request.assert_not_called()
        self.assertNotIn('test-only', json.dumps(self.service.status()))

    def test_authorization_review_and_disconnect(self):
        state = self.authorize()['state']
        responses = [
            {'access_token': 'token-for-test', 'scope': security.SCOPE, 'expires_in': 3600},
            {'user': {'emailAddress': 'test@example.com'}},
            {'files': [{'id': '1', 'name': 'script.PS1', 'shared': False}], 'nextPageToken': 'next'},
            {'files': [{'id': '2', 'name': 'plan.pdf', 'shared': True}]}]
        with patch('security.google_request', side_effect=responses) as request, patch('security.threading.Thread', side_effect=immediate_thread):
            self.service.callback({'state': state, 'code': ['test-code']})
            self.assertEqual(request.call_count, 4)
            token_body = request.call_args_list[0].kwargs['data']
            self.assertEqual(token_body['grant_type'], 'authorization_code')
            self.assertIn('code_verifier', token_body)
        status = self.service.status()
        self.assertTrue(status['google_connected'])
        self.assertEqual(status['drive']['reviewed'], 2)
        self.assertEqual(len(status['drive']['findings']), 2)
        self.assertFalse(status['drive']['partial'])
        self.assertNotIn('token-for-test', json.dumps(status))
        with self.assertRaises(ValueError):
            self.service.callback({'state': state, 'code': ['test-code']})
        self.service.disconnect()
        self.assertFalse(self.service.status()['google_connected'])
        self.assertEqual(self.service.status()['drive'], {'status': 'idle'})
        self.assertIsNone(self.service.token)

    def test_denied_expired_and_missing_scope(self):
        state = self.authorize()['state']
        with self.assertRaises(ValueError):
            self.service.callback({'state': state, 'error': ['access_denied']})
        self.assertFalse(self.service.status()['google_connected'])
        state = self.authorize()['state']
        self.service.pending['expires'] = 0
        with self.assertRaises(ValueError):
            self.service.callback({'state': state, 'code': ['code']})
        state = self.authorize()['state']
        with patch('security.google_request', return_value={'access_token': 'test', 'scope': 'openid'}):
            with self.assertRaises(ValueError):
                self.service.callback({'state': state, 'code': ['code']})
        self.assertFalse(self.service.status()['google_connected'])

    def test_limit_and_error_are_not_clean_results(self):
        self.service.token = 'test'
        self.service.expires = float('inf')
        with patch('security.google_request', side_effect=[{'user': {}}] + [{'files': [], 'nextPageToken': 'more'}] * 10), patch('security.threading.Thread', side_effect=immediate_thread):
            self.service.scan_drive()
        self.assertTrue(self.service.status()['drive']['partial'])
        with patch('security.google_request', side_effect=ValueError('expired')), patch('security.threading.Thread', side_effect=immediate_thread):
            self.service.scan_drive()
        self.assertEqual(self.service.status()['drive']['status'], 'error')

    def test_file_rules_do_not_mark_all_files(self):
        self.assertEqual(security.review_files([{'name': 'photo.jpg', 'shared': False}]), [])
        findings = security.review_files([{'name': 'invoice.pdf.exe', 'shared': True}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]['reasons']), 2)


class DefenderTest(unittest.TestCase):
    def test_not_supported_is_explicit(self):
        with patch('security.os', SimpleNamespace(name='posix')):
            with self.assertRaises(ValueError):
                security.run_defender(True)

    def test_windows_command_and_report(self):
        payload = {'protection': {'AntivirusEnabled': True}, 'history': []}
        with patch('security.os', SimpleNamespace(name='nt', environ={'SystemRoot': 'C:/Windows'})), patch('security.Path.is_file', return_value=True), patch('security.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload))) as run:
            self.assertEqual(security.run_defender(True), payload)
            command = run.call_args.args[0]
            self.assertIn('Start-MpScan -ScanType QuickScan', command[-1])
            self.assertIn('Get-MpThreatDetection', command[-1])
            self.assertNotIn('shell', run.call_args.kwargs)
            self.assertEqual(run.call_args.kwargs['timeout'], 1800)

    def test_windows_failure_does_not_report_success(self):
        with patch('security.os', SimpleNamespace(name='nt', environ={})), patch('security.Path.is_file', return_value=True), patch('security.subprocess.run', return_value=SimpleNamespace(returncode=1, stdout='')):
            with self.assertRaises(ValueError):
                security.run_defender(True)


if __name__ == '__main__':
    unittest.main()
