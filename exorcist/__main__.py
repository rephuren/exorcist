from __future__ import annotations

import argparse
import json
import sys

from . import __version__, report
from .probes import PROBES, by_id
from .runner import diff, run
from .targets import TargetError, make_target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="exorcist", description="Проверка LLM-приложения на инъекции, утечки и злоупотребление инструментами.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="прогнать пробы против цели")
    r.add_argument("target", help="mock:naive | mock:hardened | http(s)://host/v1/chat/completions | cmd:<команда>")
    r.add_argument("--model", default="default")
    r.add_argument("--probe", action="append", help="id пробы, можно несколько раз")
    r.add_argument("--repeat", type=int, default=1, help="прогонов на вариант (у настоящих моделей ответы плавают)")
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--format", choices=["text", "json", "md", "html"], default="text")
    r.add_argument("--min-severity", choices=["low", "medium", "high"], default="low", help="порог для кода возврата 1")
    r.add_argument("--i-am-authorized", action="store_true", help="подтверждение, что вы вправе проверять не-локальный адрес")
    r.add_argument("-o", "--output")

    sub.add_parser("list", help="показать пробы")

    e = sub.add_parser("export-promptfoo", help="записать часть проб как конфиг promptfoo")
    e.add_argument("-o", "--output", default="promptfooconfig.yaml")
    e.add_argument("--seed", type=int, default=0)

    d = sub.add_parser("diff", help="сравнить два JSON-отчёта")
    d.add_argument("old")
    d.add_argument("new")

    a = ap.parse_args(argv)
    try:
        if a.cmd == "list":
            for p in PROBES:
                print(f"{p.id:<24} {p.owasp} {p.atlas:<14} {p.severity:<6} {p.title}")
            return 0
        if a.cmd == "export-promptfoo":
            open(a.output, "w", encoding="utf-8").write(report.to_promptfoo(a.seed))
            print(f"written {a.output}")
            return 0
        if a.cmd == "diff":
            old, new = json.load(open(a.old, encoding="utf-8")), json.load(open(a.new, encoding="utf-8"))
            res = diff(old, new)
            for k in ("regressions", "fixed", "added", "removed"):
                print(f"{k}: {', '.join(res[k]) or '-'}")
            return 1 if res["regressions"] else 0
        tgt = make_target(a.target, a.model, a.i_am_authorized)
        rep = run(tgt, by_id(a.probe), a.seed, a.repeat)
        out = {"text": report.to_text, "json": report.to_json, "md": report.to_markdown, "html": report.to_html}[a.format](rep)
        if a.output:
            open(a.output, "w", encoding="utf-8").write(out)
        else:
            print(out)
        if rep.errors() and not rep.vulnerable():
            return 2
        return 1 if rep.vulnerable(a.min_severity) else 0
    except (TargetError, ValueError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
