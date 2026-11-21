"""Fake AML screening."""
SANCTIONED = {"SC00SANCTIONED0000000000"}


class SanctionsHit(Exception):
    pass


def screen(payee_iban: str) -> None:
    if payee_iban in SANCTIONED:
        raise SanctionsHit(payee_iban)
