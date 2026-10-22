"""Ora UTC e formato unico delle date nel DB: le stringhe si confrontano in ordine."""
from datetime import datetime, timezone

_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def now() -> datetime:
    return datetime.now(timezone.utc)


def fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_FMT)


def parse(s: str) -> datetime:
    return datetime.strptime(s, _FMT).replace(tzinfo=timezone.utc)
