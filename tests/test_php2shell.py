#!/usr/bin/env python3
"""Tests for `php2shell.py`. All paths run against local mock servers or
pure functions; nothing here touches the internet or sends exploit traffic.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import php2shell


def make_server(headers, body=b"hello"):
    """Return a (server, port) pair serving one fixed header set."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


class TestVersionParsing(unittest.TestCase):
    def test_powered_by(self):
        self.assertEqual(php2shell.parse_version("PHP/8.4.26"), (8, 4, 26))

    def test_plain(self):
        self.assertEqual(php2shell.parse_version("8.3.36"), (8, 3, 36))

    def test_php_v_output(self):
        sample = ("PHP 8.2.34 (cli) (built: Sep 30 2026 12:00:00) "
                  "(NTS)\nCopyright (c) The PHP Group")
        self.assertEqual(php2shell.parse_version(sample), (8, 2, 34))

    def test_garbage(self):
        self.assertIsNone(php2shell.parse_version("no version here"))
        self.assertIsNone(php2shell.parse_version(""))
        self.assertIsNone(php2shell.parse_version(None))

    def test_eol_versions(self):
        self.assertEqual(php2shell.parse_version("PHP/7.4.33"), (7, 4, 33))
        self.assertEqual(php2shell.parse_version("PHP/8.1.32"), (8, 1, 32))


class TestGrading(unittest.TestCase):
    def test_fixed_boundary(self):
        # Exact fixed versions are clean; one patch below is vulnerable.
        for ver, fixed in [((8, 2, 35), True), ((8, 2, 34), False),
                           ((8, 3, 36), True), ((8, 3, 35), False),
                           ((8, 4, 27), True), ((8, 4, 26), False),
                           ((8, 5, 12), True), ((8, 5, 11), False)]:
            verdict, _ = php2shell.grade_version(ver)
            self.assertEqual(verdict == "CLEAN", fixed, ver)

    def test_eol_branch(self):
        verdict, _ = php2shell.grade_version((8, 1, 32))
        self.assertEqual(verdict, "VULNERABLE_EOL")
        verdict, _ = php2shell.grade_version((7, 4, 33))
        self.assertEqual(verdict, "VULNERABLE_EOL")

    def test_unknown(self):
        verdict, _ = php2shell.grade_version(None)
        self.assertEqual(verdict, "UNKNOWN")


class TestRemoteScan(unittest.TestCase):
    def test_vulnerable_mod_php_is_critical(self):
        srv, port = make_server({
            "X-Powered-By": "PHP/8.4.26",
            "Server": "Apache/2.4.62 (Unix) mod_php",
        })
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertEqual(r["version"], "8.4.26")
        self.assertEqual(r["sapi"], "mod_php")
        self.assertEqual(r["verdict"], "VULNERABLE")
        self.assertEqual(r["severity"], "CRITICAL")

    def test_vulnerable_fpm_is_high(self):
        srv, port = make_server({
            "X-Powered-By": "PHP/8.3.35",
            "Server": "nginx/1.26.0",
        })
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertEqual(r["version"], "8.3.35")
        self.assertEqual(r["sapi"], "likely-fpm")
        self.assertEqual(r["severity"], "HIGH")

    def test_fixed_version_is_clean(self):
        srv, port = make_server({
            "X-Powered-By": "PHP/8.4.27",
            "Server": "nginx/1.26.0",
        })
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertEqual(r["verdict"], "CLEAN")
        self.assertEqual(r["severity"], "CLEAN")

    def test_missing_php_headers_is_unknown(self):
        srv, port = make_server({"Server": "nginx/1.26.0"})
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertIsNone(r["version"])
        self.assertEqual(r["verdict"], "UNKNOWN")
        self.assertEqual(r["severity"], "UNKNOWN")

    def test_eol_version_is_vulnerable(self):
        srv, port = make_server({
            "X-Powered-By": "PHP/8.1.32",
            "Server": "nginx/1.26.0",
        })
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertEqual(r["verdict"], "VULNERABLE_EOL")
        self.assertEqual(r["severity"], "HIGH")

    def test_version_in_server_header(self):
        srv, port = make_server({
            "Server": "Apache/2.4.62 (Unix) PHP/8.2.34",
        })
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertEqual(r["version"], "8.2.34")
        self.assertEqual(r["sapi"], "mod_php")
        self.assertEqual(r["severity"], "CRITICAL")

    def test_phpinfo_body_marker(self):
        body = (b"<html><title>phpinfo()</title><body>"
                b"<h1>PHP Version 8.4.26</h1></body></html>")
        srv, port = make_server({"Server": "Apache/2.4.62"}, body=body)
        try:
            r = php2shell.scan_target("http://127.0.0.1:%d/" % port)
        finally:
            srv.shutdown()
        self.assertTrue(any("phpinfo" in n for n in r["notes"]))

    def test_unreachable_target_raises(self):
        with self.assertRaises(Exception):
            php2shell.scan_target("http://127.0.0.1:1/", timeout=2)


class TestLocalMode(unittest.TestCase):
    def test_php_ini_upload_progress_disabled(self):
        ini = ("; sample\nsession.upload_progress.enabled = 0\n"
               "memory_limit = 128M\n")
        with tempfile.NamedTemporaryFile("w", suffix=".ini",
                                         delete=False) as f:
            f.write(ini)
            path = f.name
        try:
            r = php2shell.check_php_ini(path)
        finally:
            os.unlink(path)
        self.assertTrue(r["upload_progress_disabled"])
        self.assertEqual(r["memory_limit"], "128M")

    def test_php_ini_upload_progress_enabled(self):
        ini = "session.upload_progress.enabled = 1\n"
        with tempfile.NamedTemporaryFile("w", suffix=".ini",
                                         delete=False) as f:
            f.write(ini)
            path = f.name
        try:
            r = php2shell.check_php_ini(path)
        finally:
            os.unlink(path)
        self.assertFalse(r["upload_progress_disabled"])

    def test_php_ini_missing_file(self):
        r = php2shell.check_php_ini("/nonexistent/php.ini")
        self.assertIn("error", r)


class TestCli(unittest.TestCase):
    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            php2shell.main(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_no_mode_errors(self):
        with self.assertRaises(SystemExit) as cm:
            php2shell.main([])
        self.assertNotEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
