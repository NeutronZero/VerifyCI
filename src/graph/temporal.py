from typing import Optional


def is_valid_at(valid_from: Optional[float], valid_until: Optional[float], as_of: float) -> bool:
    if valid_from is not None and valid_from > as_of:
        return False
    if valid_until is not None and valid_until <= as_of:
        return False
    return True


def is_live(t_expired: Optional[float]) -> bool:
    return t_expired is None


def filter_at(items: list, as_of: float) -> list:
    return [i for i in items if is_valid_at(i.valid_from, i.valid_until, as_of) and is_live(i.t_expired)]


def expire(item, at: float):
    import dataclasses
    return dataclasses.replace(item, valid_until=at, t_expired=at)
