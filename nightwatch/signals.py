"""Risk detectors.

Each detector looks at one event in the context of the identity's baseline and
recent activity, and returns a list of Signals (points + plain-English reason).

To add a detector: write a function with the signature below, decorate it with
@detector, and add a test in tests/test_signals.py. The engine picks it up
automatically.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Callable

from .codescan import scan
from .models import Event, Identity, Signal
from .state import IdentityState

Detector = Callable[[Event, Identity, IdentityState], list[Signal]]
DETECTORS: list[Detector] = []

PROTECTED_BRANCHES = ("main", "release")
SENSITIVE_TABLES = {"customers_pii", "cards", "kyc_documents"}
CASH_OUT_TYPES = {"non_custodial_wallet"}
SAFETY_CONTROLS = {"payments.daily_limit_enforced", "payments.aml_screening",
                   "auth.mfa_required", "audit.enabled"}
OFF_VALUES = {"false", "off", "0", "no", "disabled", "none"}
WIRE_LIMIT_KEY = "payments.max_wire_aed"

CODE_WEIGHTS = {
    "SAFETY_CHECK_REMOVED": 30,
    "HARDCODED_BYPASS": 35,
    "SECRET_IN_CODE": 25,
    "AUDIT_LOG_REMOVED": 15,
    "NEW_EGRESS": 20,
}


def detector(fn: Detector) -> Detector:
    DETECTORS.append(fn)
    return fn


def _in_hours(hour: int, window: tuple[int, int]) -> bool:
    start, end = window
    return start <= hour < end if start < end else (hour >= start or hour < end)


# ---------- apply to every kind of event ----------
@detector
def off_hours(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if _in_hours(e.ts.hour, ident.active_hours):
        return []
    s, t = ident.active_hours
    return [Signal("OFF_HOURS", 10, f"{ident.name} is never active at {e.ts:%H:%M} "
                   f"(normal window {s:02d}:00 to {t:02d}:00).")]


@detector
def new_network(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.network and e.network not in ident.usual_networks:
        return [Signal("NEW_NETWORK", 15, f"Request comes from {e.network}, a network this "
                       "identity has never used.", e.network)]
    return []


@detector
def revoked_identity(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if st.revoked:
        return [Signal("REVOKED", 100, "This credential was already revoked by Night Watch.")]
    return []


# ---------- payment rails / API gateway ----------
@detector
def scope_escalation(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind == "api_call" and e.scope_used and e.scope_used not in ident.scopes:
        return [Signal("SCOPE_ESCALATION", 25, f"Key is using '{e.scope_used}', a permission it was "
                       "never granted for this use.", e.scope_used)]
    return []


@detector
def rate_spike(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind == "api_call" and ident.typical_rate and e.rate >= 10 * ident.typical_rate:
        return [Signal("RATE_SPIKE", 15, f"{e.rate:.0f} requests/min against a normal "
                       f"{ident.typical_rate:.0f}: machine speed.")]
    return []


@detector
def value_spike(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind != "api_call" or not e.amount or not ident.typical_value:
        return []
    ratio = e.amount / ident.typical_value
    if ratio >= 20:
        return [Signal("VALUE_SPIKE", 20, f"Payment is {ratio:.0f}x this integration's typical value.")]
    return []


@detector
def cash_out_destination(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind != "api_call" or not e.amount:
        return []
    if e.destination_type in CASH_OUT_TYPES:
        return [Signal("CASH_OUT_RAIL", 20, "Money is going to a non-custodial wallet: once it "
                       "leaves, it cannot be recalled.", e.destination or "")]
    if e.destination and ident.usual_destinations and e.destination not in ident.usual_destinations:
        return [Signal("NEW_CORRIDOR", 10, f"First ever payment to {e.destination} from this integration.")]
    return []


@detector
def velocity_burst(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind != "api_call":
        return []
    recent = [t for t in st.recent_calls if e.ts - t <= timedelta(seconds=60)]
    if len(recent) >= 2:
        return [Signal("VELOCITY_BURST", 15, f"{len(recent) + 1} payment calls in under a minute.")]
    return []


# ---------- code ----------
@detector
def unreviewed_push(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind == "commit" and e.reviewed is False and e.target.endswith(PROTECTED_BRANCHES):
        return [Signal("UNREVIEWED_PUSH", 20, f"Pushed straight to {e.target} with no second reviewer.")]
    return []


@detector
def code_findings(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind != "commit" or not e.diff:
        return []
    return [Signal(f.code, CODE_WEIGHTS.get(f.code, 15), f.reason, f.line) for f in scan(e.diff)]


# ---------- data ----------
@detector
def bulk_read(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind != "db_query" or not ident.typical_rows:
        return []
    if e.rows >= 50 * ident.typical_rows:
        return [Signal("BULK_READ", 25, f"Read {e.rows:,} rows; this account normally reads about "
                       f"{ident.typical_rows:,}.")]
    return []


@detector
def sensitive_table(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind == "db_query" and e.target in SENSITIVE_TABLES:
        return [Signal("SENSITIVE_DATA", 15, f"Query touches {e.target}, which holds customer "
                       "personal data.", e.target)]
    return []


@detector
def unusual_egress(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind == "db_query" and e.destination and e.destination not in ident.usual_destinations:
        return [Signal("DATA_EGRESS", 25, f"Results are being written to {e.destination}, outside "
                       "the bank.", e.destination)]
    return []


# ---------- production config ----------
def _number(value: str | None) -> float | None:
    try:
        return float(str(value).replace(",", "").replace("_", ""))
    except ValueError:
        return None


@detector
def config_tamper(e: Event, ident: Identity, st: IdentityState) -> list[Signal]:
    if e.kind != "config_change":
        return []
    found: list[Signal] = []
    if e.target in SAFETY_CONTROLS and str(e.new_value).strip().lower() in OFF_VALUES:
        found.append(Signal("CONTROL_DISABLED", 35, f"Switches off {e.target} in production: "
                            "a payment safety control is disabled.", f"{e.target} = {e.new_value}"))
    if e.target == WIRE_LIMIT_KEY:
        old, new = _number(e.old_value), _number(e.new_value)
        if old is not None and new is not None and new > 5 * old:
            ratio = f" ({new / old:.0f}x)" if old > 0 else ""
            found.append(Signal("LIMIT_RAISED", 20, f"Raises the wire limit from AED {old:,.0f} to "
                                f"AED {new:,.0f}{ratio}.", f"{e.target} = {e.new_value}"))
    if found and e.reviewed is False:
        found.append(Signal("UNAPPROVED_CHANGE", 15, "Changed a payment control with no approved "
                            "change ticket."))
    return found
