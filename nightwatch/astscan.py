"""Night Watch code guard, v2: reads the code's structure (Python AST), not just text.

For every changed Python file it compares the old and new version function by function:

  GUARD_REMOVED      a call that protects money or data (check, verify, screen, authorize, audit,
                     limit, ...) existed in this function before and is gone now
  RAISE_REMOVED      the function raises fewer errors than before (a refusal path disappeared)
  OWNER_CHECK_GONE   a comparison against an owner / customer / principal disappeared
  LIMIT_CHECK_GONE   a comparison against a limit / balance / threshold disappeared
  GUARD_WEAKENED     a refusal (`if ...: raise`) still exists but now only fires under an extra
                     condition: `False and ...`, an env-var kill switch, a feature flag, a wrapper `if`
  DEAD_GUARD         a refusal can never fire (its condition is a constant false)
  HARDCODED_BYPASS   a new branch keyed on a literal account, IBAN or user id
  SKIP_FLAG          a call passes skip_*/bypass*/verify=False style switches
  SECRET_IN_CODE     a high-entropy literal or known key format assigned in code
  NEW_EGRESS         a network call to a host outside the bank's allowlist
  DANGEROUS_CALL     eval/exec, pickle.loads, os.system, subprocess(shell=True), yaml.load
  SQL_INJECTION      execute() built from an f-string, + or % formatting

A regex scanner sees lines; this sees *which function lost which protection*, so renaming a
variable or moving code around does not fool it, and a removed check is reported at the
function where it used to be.
"""
from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass

GUARD_NAME = re.compile(r"(?i)(check|verify|validat|screen|authori[sz]|permission|owner|ensure|require|"
                        r"limit|audit|sanction|aml|kyc|mfa|otp|assert_|deny|forbid|compare_digest)")
SKIP_KW = re.compile(r"(?i)^(skip|bypass|no_check|disable|unsafe|force|insecure)")
SECRET_NAME = re.compile(r"(?i)(secret|token|password|passwd|api_?key|private_?key|credential)")
SECRET_PREFIX = re.compile(r"^(sk_live_|plk_live_|pk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_|xox[bp]-|"
                           r"-----BEGIN)")
OWNER_WORDS = re.compile(r"(?i)(owner|customer_id|principal|user_id|account_holder)")
LIMIT_WORDS = re.compile(r"(?i)(limit|balance|threshold|max_|spent)")
NET_CALLS = {"urlopen", "post", "get", "put", "request", "connect", "create_connection", "send"}
NET_MODULES = {"requests", "httpx", "urllib", "http", "socket", "aiohttp"}
ALLOWED_HOSTS = re.compile(r"(\.bank\.internal|^localhost|^127\.0\.0\.1|^api\.devin\.ai|^api\.github\.com)$")
HOST = re.compile(r"https?://([A-Za-z0-9.-]+)")

SEVERITY = {"GUARD_REMOVED": "high", "OWNER_CHECK_GONE": "high", "HARDCODED_BYPASS": "high",
            "SKIP_FLAG": "high", "SECRET_IN_CODE": "high", "NEW_EGRESS": "high", "DANGEROUS_CALL": "high",
            "SQL_INJECTION": "high", "LIMIT_CHECK_GONE": "high", "RAISE_REMOVED": "medium",
            "GUARD_WEAKENED": "high", "DEAD_GUARD": "high"}
WEIGHT = {"high": 35, "medium": 15, "low": 5}


@dataclass
class Finding:
    file: str
    line: int
    code: str
    reason: str
    function: str = ""
    snippet: str = ""

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.code, "low")

    def to_dict(self) -> dict:
        return {**asdict(self), "severity": self.severity}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _name(node.func)
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _functions(tree: ast.AST) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}

    def walk(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}"
                out[q] = child
                walk(child, q + ".")
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}.")
    walk(tree)
    return out


def _shape(cmp: ast.Compare) -> str:
    """A rename-proof fingerprint of a comparison: operators plus attribute/key names, not variable names."""
    def part(x):
        if isinstance(x, ast.Attribute):
            return x.attr
        if isinstance(x, ast.Subscript) and isinstance(x.slice, ast.Constant):
            return str(x.slice.value)
        if isinstance(x, ast.Constant):
            return repr(x.value)
        if isinstance(x, ast.Call):
            return _name(x).split(".")[-1] + "()"
        return "_"
    return " ".join([part(cmp.left)] + [f"{type(o).__name__} {part(c)}" for o, c in zip(cmp.ops, cmp.comparators)])


def _key(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _refuses(node: ast.If) -> bool:
    return any(isinstance(x, ast.Raise) for st in node.body for x in ast.walk(st))


def _refusals(fn: ast.AST) -> dict[str, tuple[int, str, list[str]]]:
    """Every `if <test>: raise` in a function: test fingerprint -> (line, source, enclosing if-tests).
    An `and` test is split into its parts so `if A and B: raise` is seen as a refusal on A gated by B."""
    out: dict[str, tuple[int, str, list[str]]] = {}

    def visit(body, gates):
        for st in body:
            if isinstance(st, ast.If):
                if _refuses(st):
                    parts = st.test.values if isinstance(st.test, ast.BoolOp) and isinstance(st.test.op, ast.And) else [st.test]
                    keys = [_key(x) for x in parts]
                    for i, x in enumerate(parts):
                        others = [k for j, k in enumerate(keys) if j != i]
                        out.setdefault(_key(x), (st.lineno, ast.unparse(x), gates + others))
                visit(st.body, gates + [_key(st.test)])
                visit(st.orelse, gates + ["not " + _key(st.test)])
            elif isinstance(st, (ast.For, ast.While, ast.With, ast.Try)):
                for f in ("body", "orelse", "finalbody"):
                    visit(getattr(st, f, []) or [], gates)
                for h in getattr(st, "handlers", []) or []:
                    visit(h.body, gates)
    visit(getattr(fn, "body", []), [])
    return out


def _falsy(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return not node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Constant):
        return bool(node.operand.value)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return any(_falsy(v) for v in node.values)
    return False


def _facts(fn: ast.AST) -> dict:
    guards: dict[str, int] = {}
    raises, owner_cmps, limit_cmps = 0, {}, {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            nm = _name(n)
            if nm and GUARD_NAME.search(nm):
                guards.setdefault(nm, n.lineno)
        elif isinstance(n, ast.Raise):
            raises += 1
        elif isinstance(n, ast.Compare):
            src, key = ast.unparse(n), _shape(n)
            if OWNER_WORDS.search(src):
                owner_cmps.setdefault(key, (n.lineno, src))
            elif LIMIT_WORDS.search(src):
                limit_cmps.setdefault(key, (n.lineno, src))
    return {"guards": guards, "raises": raises, "owner": owner_cmps, "limit": limit_cmps, "refusals": _refusals(fn)}


def _literal_bypass(node: ast.If) -> str | None:
    for cmp in [n for n in ast.walk(node.test) if isinstance(n, ast.Compare)]:
        consts = [c for c in [cmp.left, *cmp.comparators] if isinstance(c, ast.Constant) and isinstance(c.value, str)]
        consts += [e for c in cmp.comparators if isinstance(c, (ast.List, ast.Tuple, ast.Set))
                   for e in c.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        names = [ast.unparse(x) for x in [cmp.left, *cmp.comparators] if not isinstance(x, ast.Constant)]
        if any(len(c.value) >= 8 and re.fullmatch(r"[A-Za-z0-9_\-]+", c.value) and re.search(r"\d", c.value)
               for c in consts) and any(re.search(r"(?i)(iban|account|user|customer|payee|caller|id)", n) for n in names):
            return ast.unparse(node.test)
    return None


def _module_findings(path: str, tree: ast.AST, new_lines: set[int] | None) -> list[Finding]:
    out: list[Finding] = []
    fn_at = {}
    for q, f in _functions(tree).items():
        for ln in range(f.lineno, (f.end_lineno or f.lineno) + 1):
            fn_at[ln] = q

    def fresh(n):  # only report code that is new in this change
        return new_lines is None or getattr(n, "lineno", 0) in new_lines

    for n in ast.walk(tree):
        if not fresh(n):
            continue
        ln = getattr(n, "lineno", 0)
        where = fn_at.get(ln, "")
        if isinstance(n, ast.If) and _refuses(n) and _falsy(n.test):
            out.append(Finding(path, ln, "DEAD_GUARD", f"This refusal can never fire: `if {ast.unparse(n.test)[:90]}` is always false.",
                               where, ast.unparse(n.test)[:120]))
        if isinstance(n, ast.If):
            b = _literal_bypass(n)
            if b:
                out.append(Finding(path, ln, "HARDCODED_BYPASS", f"New branch keyed on a hard-coded identifier: `{b}`.", where, b))
        if isinstance(n, ast.Call):
            nm = _name(n)
            last = nm.split(".")[-1]
            for kw in n.keywords:
                if kw.arg and (SKIP_KW.search(kw.arg) and not (isinstance(kw.value, ast.Constant) and kw.value.value in (False, None))
                               or kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False):
                    out.append(Finding(path, ln, "SKIP_FLAG", f"`{nm}(... {kw.arg}={ast.unparse(kw.value)})` switches a protection off.", where, ast.unparse(n)[:120]))
            if nm in ("eval", "exec", "os.system", "pickle.loads", "marshal.loads") or \
                    nm in ("yaml.load",) and not any(k.arg == "Loader" for k in n.keywords) or \
                    nm.startswith("subprocess.") and any(k.arg == "shell" and getattr(k.value, "value", False) is True for k in n.keywords):
                out.append(Finding(path, ln, "DANGEROUS_CALL", f"`{nm}` can run attacker-controlled code.", where, ast.unparse(n)[:120]))
            if last in ("execute", "executemany") and n.args and isinstance(n.args[0], (ast.JoinedStr, ast.BinOp)):
                out.append(Finding(path, ln, "SQL_INJECTION", "SQL built from string formatting; use parameters.", where, ast.unparse(n)[:120]))
            if last in NET_CALLS and (nm.split(".")[0] in NET_MODULES or last == "urlopen" or "net" in nm or "http" in nm):
                hosts = [h for a in ast.walk(n) if isinstance(a, ast.Constant) and isinstance(a.value, str)
                         for h in HOST.findall(a.value)]
                bad = [h for h in hosts if not ALLOWED_HOSTS.search(h)]
                if bad:
                    out.append(Finding(path, ln, "NEW_EGRESS", f"Sends data to {bad[0]}, which is outside the bank's allowlist.", where, ast.unparse(n)[:120]))
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.keyword)):
            targets = [n.arg] if isinstance(n, ast.keyword) else \
                [ast.unparse(t) for t in (n.targets if isinstance(n, ast.Assign) else [n.target])]
            val = n.value
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                s = val.value
                named = any(t and SECRET_NAME.search(t) for t in targets)
                if SECRET_PREFIX.search(s) or (named and len(s) >= 12 and _entropy(s) >= 3.3):
                    out.append(Finding(path, ln, "SECRET_IN_CODE", f"Looks like a real credential in `{targets[0]}` "
                                       f"(entropy {_entropy(s):.1f} bits/char).", where, f"{targets[0]} = '{s[:4]}…'"))
    return out


def scan_change(path: str, old: str | None, new: str | None, new_lines: set[int] | None = None) -> list[Finding]:
    """Compare one file before and after a change. old=None for a new file, new=None for a deleted one."""
    if new is None:
        return []
    try:
        new_tree = ast.parse(new)
    except SyntaxError as e:
        return [Finding(path, e.lineno or 1, "PARSE_ERROR", f"Could not parse: {e.msg}")]
    out = _module_findings(path, new_tree, new_lines)
    if old:
        try:
            old_tree = ast.parse(old)
        except SyntaxError:
            return out
        old_fns, new_fns = _functions(old_tree), _functions(new_tree)
        for q, ofn in old_fns.items():
            nfn = new_fns.get(q)
            if nfn is None:
                continue
            a, b = _facts(ofn), _facts(nfn)
            for g, ln in a["guards"].items():
                if g not in b["guards"]:
                    out.append(Finding(path, nfn.lineno, "GUARD_REMOVED", f"`{q}()` no longer calls `{g}()` "
                                       f"(it did at old line {ln}).", q, g))
            for key, (ln, cmp) in a["owner"].items():
                if key not in b["owner"]:
                    out.append(Finding(path, nfn.lineno, "OWNER_CHECK_GONE", f"`{q}()` lost the ownership check `{cmp}`.", q, cmp))
            for key, (ln, cmp) in a["limit"].items():
                if key not in b["limit"]:
                    out.append(Finding(path, nfn.lineno, "LIMIT_CHECK_GONE", f"`{q}()` lost the limit check `{cmp}`.", q, cmp))
            for key, (ln, src, gates) in a["refusals"].items():
                if key in b["refusals"]:
                    nln, _, ngates = b["refusals"][key]
                    extra = [g for g in ngates if g not in gates]
                    if extra:
                        cond = next((ast.unparse(x) for x in ast.walk(nfn) if isinstance(x, ast.expr) and _key(x) == extra[0].removeprefix("not ")), "a new condition")
                        out.append(Finding(path, nln, "GUARD_WEAKENED", f"`{q}()` still has the refusal `if {src[:80]}`, but it now "
                                           f"only fires when `{cond[:80]}` also holds: a kill switch or bypass.", q, cond[:120]))
            if b["raises"] < a["raises"]:
                out.append(Finding(path, nfn.lineno, "RAISE_REMOVED", f"`{q}()` raises {a['raises'] - b['raises']} fewer "
                                   "error(s) than before: a refusal path is gone.", q))
    return out


def risk(findings: list[Finding]) -> int:
    return min(100, sum(WEIGHT[f.severity] for f in findings))


def markdown(findings: list[Finding], score: int) -> str:
    if not findings:
        return "### Night Watch code guard: passed\nNo change weakens a protection."
    rows = "\n".join(f"| {f.severity} | `{f.code}` | `{f.file}:{f.line}` | {f.function or '-'} | {f.reason} |" for f in findings)
    verdict = "blocked" if any(f.severity == "high" for f in findings) else "warning"
    return (f"### Night Watch code guard: {verdict} (risk {score}/100)\n\n"
            "| Severity | Finding | Where | Function | Why |\n|---|---|---|---|---|\n" + rows)
