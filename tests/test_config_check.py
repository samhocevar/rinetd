import pathlib
import tempfile

FILE = pathlib.Path(__file__).resolve().parents[1] / 'bin' / 'rinetd-ng-config-check'
# Extensionless executables are loaded with SourceFileLoader explicitly.
from importlib.machinery import SourceFileLoader
import types
checker = types.ModuleType('checker')
exec(compile(FILE.read_text(), str(FILE), 'exec'), checker.__dict__)

def run(text):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / 'rinetd.conf'
        p.write_text(text)
        return checker.validate(p)

def test_compat_ipv4():
    errors, _, n = run('127.0.0.1 8080 10.0.0.1 80\nallow 127.0.0.*\ndeny *\n')
    assert not errors and n == 1

def test_udp_and_src():
    errors, _, n = run('127.0.0.1 5353/udp 127.0.0.1 53/udp [timeout=60,src=127.0.0.1]\n')
    assert not errors and n == 1

def test_bad_ports():
    errors, _, _ = run('127.0.0.1 70000 127.0.0.1 0\n')
    assert len(errors) == 2

def test_bad_config():
    errors, _, _ = run('127.0.0.1 8000\n')
    assert errors

def test_bad_options():
    errors, _, _ = run('127.0.0.1 80 127.0.0.1 8080 [timeout=0]\n')
    assert errors

def test_comments_blank():
    errors, warnings, n = run('# hello\n\n')
    assert not errors and warnings and n == 0

def test_wildcard_notice():
    errors, warnings, _ = run('0.0.0.0 80 127.0.0.1 8080\n')
    assert not errors and warnings

def test_missing_file():
    assert checker.validate('/path/that/does/not/exist')[0]

def test_ipv6():
    errors, _, n = run('[::1] 8080 [::1] 8081\n')
    assert not errors and n == 1

def test_unspecified_allow_warning():
    errors, warnings, n = run('127.0.0.1 18080 127.0.0.1 300\nallow 0.0.0.0\ndeny *\n')
    assert not errors and n == 1
    assert any('allow 0.0.0.0' in w for w in warnings)

def test_allow_all_no_warning():
    errors, warnings, n = run('127.0.0.1 18080 127.0.0.1 300\nallow *\n')
    assert not errors and n == 1 and not warnings


def test_deny_star_overrides_allow():
    errors, warnings, n = run('127.0.0.1 18080 127.0.0.1 300\nallow 127.0.0.1\ndeny *\n')
    assert not errors and n == 1
    assert any('deny * overrides allow' in w for w in warnings)

def test_allow_list_without_deny_star():
    errors, warnings, n = run('127.0.0.1 18080 127.0.0.1 300\nallow 127.0.0.1\n')
    assert not errors and n == 1 and not warnings
