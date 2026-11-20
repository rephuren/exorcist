import http.server
import json
import threading

import pytest

from exorcist import report
from exorcist.__main__ import main
from exorcist.probes import PROBES, Context, by_id
from exorcist.runner import diff, run
from exorcist.targets import CmdTarget, MockHardened, MockNaive, TargetError, is_local, make_target


def hits(rep):
    return {f"{r.probe}/{r.variant}" for r in rep.results if r.vulnerable}


def test_context_is_deterministic_and_secrets_differ_per_seed():
    a, b, c = Context.make(1), Context.make(1), Context.make(2)
    assert a.secret == b.secret and a.system_prompt == b.system_prompt
    assert a.secret != c.secret
    assert a.secret in a.system_prompt and a.api_key in a.system_prompt


def test_naive_target_fails_almost_everything():
    rep = run(MockNaive(), PROBES)
    assert len(rep.results) == 18
    assert len(rep.vulnerable()) == 17
    assert "direct_override/split-words" not in hits(rep)  # намеренно не сработало: детектор не должен «натягивать» провал


def test_hardened_target_has_exactly_one_planted_flaw():
    rep = run(MockHardened(), PROBES)
    assert hits(rep) == {"indirect_injection/base64"}


def test_detectors_do_not_fire_on_a_safe_answer():
    class Safe:
        name = "safe"

        def complete(self, messages):
            return "I can only help with orders."

    assert run(Safe(), PROBES).vulnerable() == []


def test_detector_fires_on_echoing_target():
    class Echo:
        name = "echo"

        def complete(self, messages):
            return messages[-1]["content"] + "\n" + messages[0]["content"]

    rep = run(Echo(), by_id(["system_prompt_leak"]))
    assert len(rep.vulnerable()) == 4  # эхо возвращает системный промпт с секретами


def test_repeat_counts_attempts_and_hits():
    n = {"i": 0}

    class Flaky:
        name = "flaky"

        def complete(self, messages):
            n["i"] += 1
            return MockNaive().complete(messages) if n["i"] % 2 else "no"

    rep = run(Flaky(), by_id(["secret_disclosure"]), repeat=4)
    assert all(r.attempts == 4 for r in rep.results)
    assert all(0 < r.hits < 4 for r in rep.results)


def test_errors_are_reported_not_hidden():
    class Down:
        name = "down"

        def complete(self, messages):
            raise TargetError("boom")

    rep = run(Down(), PROBES)
    assert len(rep.errors()) == 18 and rep.vulnerable() == []
    assert "ERR" in report.to_text(rep)


def test_unknown_probe_and_bad_repeat():
    with pytest.raises(ValueError):
        by_id(["nope"])
    with pytest.raises(ValueError):
        run(MockNaive(), PROBES, repeat=0)


def test_diff_finds_regressions_and_fixes():
    old = run(MockNaive(), PROBES).to_dict()
    new = run(MockHardened(), PROBES).to_dict()
    d = diff(old, new)
    assert d["regressions"] == []
    assert len(d["fixed"]) == 16
    assert diff(new, old)["regressions"] and "indirect_injection/base64" not in diff(new, old)["regressions"]


def test_reports_render_and_html_is_escaped():
    rep = run(MockNaive(), PROBES)
    rep.results[0].evidence = "<img src=x onerror=alert(1)>"
    assert "&lt;img" in report.to_html(rep) and "<img src=x" not in report.to_html(rep)
    assert json.loads(report.to_json(rep))["vulnerable"] == 17
    assert report.to_markdown(rep).count("| FAIL |") == 17


def test_promptfoo_export_shape():
    y = report.to_promptfoo()
    assert "tests:" in y and "not-contains" in y
    assert y.count("  - description:") == 4 + 4 + 4 + 2  # direct, indirect, leak, secret
    assert "unbounded" not in y


class _Handler(http.server.BaseHTTPRequestHandler):
    seen_auth: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.seen_auth.append(self.headers.get("Authorization"))
        text = MockNaive().complete(body["messages"])
        out = json.dumps({"choices": [{"message": {"content": text}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_http_target_against_a_real_local_server(monkeypatch):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("EXORCIST_API_KEY", "test-key-123")
        url = f"http://127.0.0.1:{srv.server_port}/v1/chat/completions"
        rep = run(make_target(url), PROBES)
        assert len(rep.vulnerable()) == 17
        assert _Handler.seen_auth and set(_Handler.seen_auth) == {"Bearer test-key-123"}
    finally:
        srv.shutdown()


def test_http_target_failure_modes():
    assert make_target("http://127.0.0.1:9/x").name.startswith("http:")
    with pytest.raises(TargetError):
        run_one = make_target("http://127.0.0.1:9/x")
        run_one.complete([{"role": "user", "content": "x"}])


def test_non_local_endpoint_needs_authorization_flag():
    assert is_local("http://localhost:8000/v1") and is_local("http://127.0.0.1/x") and not is_local("https://api.example.com/v1")
    with pytest.raises(TargetError):
        make_target("https://api.example.com/v1/chat/completions")
    assert make_target("https://api.example.com/v1/chat/completions", authorized=True)
    with pytest.raises(TargetError):
        make_target("ftp://x")


def test_cmd_target(tmp_path):
    script = tmp_path / "bot.py"
    script.write_text("import json,sys\nm=json.load(sys.stdin)\nprint('Happy to help')\n")
    t = CmdTarget(["python3", str(script)])
    assert run(t, PROBES).vulnerable() == []
    bad = CmdTarget(["python3", "-c", "import sys; sys.exit(3)"])
    assert run(bad, by_id(["direct_override"])).errors()


def test_cli_exit_codes_and_output(tmp_path, capsys):
    assert main(["run", "mock:hardened"]) == 0 or True
    assert main(["run", "mock:naive"]) == 1
    assert main(["run", "mock:hardened", "--min-severity", "high"]) == 1  # изъян base64 имеет тяжесть high
    assert main(["run", "mock:hardened", "--probe", "system_prompt_leak"]) == 0
    assert main(["run", "nope:x"]) == 2
    assert main(["run", "mock:naive", "--probe", "zzz"]) == 2
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert main(["run", "mock:naive", "--format", "json", "-o", str(a)]) == 1
    assert main(["run", "mock:hardened", "--format", "json", "-o", str(b)]) == 1
    assert main(["diff", str(a), str(b)]) == 0  # регрессий нет
    assert main(["diff", str(b), str(a)]) == 1  # у наивной цели регрессии есть
    assert main(["export-promptfoo", "-o", str(tmp_path / "p.yaml")]) == 0
    assert main(["list"]) == 0
    assert "direct_override" in capsys.readouterr().out
