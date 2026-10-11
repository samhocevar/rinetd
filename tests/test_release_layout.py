"""Release assembly checks that do not need the upstream source checkout."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_service_never_advertises_validation_only_reload():
    service = (ROOT/'packaging/rinetd-ng.service').read_text()
    assert 'ExecReload=' not in service
    assert 'NoNewPrivileges=yes' in service
    assert 'User=rinetd' in service


def test_rpm_has_license_and_noreplace_configuration():
    spec=(ROOT/'packaging/rpm/rinetd-ng.spec').read_text()
    assert '%license upstream/COPYING' in spec
    assert '%config(noreplace)' in spec
    assert 'systemd-rpm-macros' in spec


def test_patch_tool_syntax_and_guards():
    script = ROOT/'tools/patch-engine.py'
    subprocess.run(['python3','-m','py_compile',str(script)],check=True)
    txt=script.read_text()
    assert 'rinetd_ng_reload_pending' in txt
    assert 'refusing patch' in txt
