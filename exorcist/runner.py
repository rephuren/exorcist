from __future__ import annotations

from dataclasses import dataclass, field

from .probes import SEVERITY, Context, Probe
from .targets import Target, TargetError


@dataclass
class Result:
    probe: str
    title: str
    variant: str
    owasp: str
    atlas: str
    severity: str
    attempts: int
    hits: int
    evidence: str = ""
    error: str = ""

    @property
    def vulnerable(self) -> bool:
        return self.hits > 0


@dataclass
class Report:
    target: str
    seed: int
    repeat: int
    results: list[Result] = field(default_factory=list)

    def vulnerable(self, min_severity: str = "low") -> list[Result]:
        floor = SEVERITY[min_severity]
        return [r for r in self.results if r.vulnerable and SEVERITY[r.severity] >= floor]

    def errors(self) -> list[Result]:
        return [r for r in self.results if r.error]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "seed": self.seed,
            "repeat": self.repeat,
            "total": len(self.results),
            "vulnerable": len(self.vulnerable()),
            "errors": len(self.errors()),
            "results": [
                {"probe": r.probe, "variant": r.variant, "title": r.title, "owasp": r.owasp, "atlas": r.atlas, "severity": r.severity, "attempts": r.attempts, "hits": r.hits, "vulnerable": r.vulnerable, "evidence": r.evidence, "error": r.error}
                for r in self.results
            ],
        }


def run(target: Target, probes: list[Probe], seed: int = 0, repeat: int = 1) -> Report:
    """Каждый вариант пробы запускается `repeat` раз: у настоящих моделей ответы плавают, и один чистый прогон ничего не доказывает."""
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    ctx = Context.make(seed)
    rep = Report(target.name, seed, repeat)
    for pr in probes:
        for att in pr.build(ctx):
            res = Result(pr.id, pr.title, att.variant, pr.owasp, pr.atlas, pr.severity, 0, 0)
            for _ in range(repeat):
                try:
                    resp = target.complete(att.messages)
                except TargetError as e:
                    res.error = str(e)
                    break
                res.attempts += 1
                hit, ev = att.detect(resp)
                if hit:
                    res.hits += 1
                    res.evidence = res.evidence or ev
            rep.results.append(res)
    return rep


def diff(old: dict, new: dict) -> dict[str, list[str]]:
    """Сравнение двух отчётов: что стало уязвимым, что починено."""
    def key(r):
        return f"{r['probe']}/{r['variant']}"
    a = {key(r): r["vulnerable"] for r in old["results"]}
    b = {key(r): r["vulnerable"] for r in new["results"]}
    return {
        "regressions": sorted(k for k, v in b.items() if v and not a.get(k, False)),
        "fixed": sorted(k for k, v in a.items() if v and k in b and not b[k]),
        "removed": sorted(k for k in a if k not in b),
        "added": sorted(k for k in b if k not in a),
    }
