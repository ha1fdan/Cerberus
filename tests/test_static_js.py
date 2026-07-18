"""Runs the actual client-side redirect-safety check in a real JS engine (Node), since
this logic lives in app/static/webauthn.js and Python can't otherwise exercise it.
Guards against a regression of the open-redirect / javascript: URI fix in login.html.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

WEBAUTHN_JS = Path(__file__).resolve().parent.parent / "app" / "static" / "webauthn.js"

CASES = [
    ("/", True),
    ("/dashboard", True),
    ("/foo/bar?x=1", True),
    ("", False),
    (None, False),
    ("//evil.example", False),
    ("https://evil.example", False),
    ("http://evil.example/x", False),
    ("javascript:alert(document.cookie)", False),
    ("\\\\evil.example", False),
    ("/foo\nbar", False),
]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_is_safe_redirect_path_rejects_cross_origin_and_js_uris():
    script = f"""
    const fs = require('fs');
    eval(fs.readFileSync({json.dumps(str(WEBAUTHN_JS))}, 'utf8'));
    const inputs = {json.dumps([c for c, _ in CASES])};
    console.log(JSON.stringify(inputs.map(isSafeRedirectPath)));
    """
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr

    actual = json.loads(result.stdout)
    expected = [exp for _, exp in CASES]
    assert actual == expected, list(zip([c for c, _ in CASES], actual, expected))
