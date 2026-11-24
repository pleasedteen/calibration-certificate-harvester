"""Tiny shim for the subset of pytest used in this repository."""

from __future__ import annotations

import inspect
from contextlib import contextmanager
from pathlib import Path


class Mark:
    def __init__(self, name, args, kwargs):
        self.name = name
        self.args = args
        self.kwargs = kwargs


class MarkDecorator:
    def __init__(self, mark):
        self.mark = mark

    def __call__(self, fn):
        marks = list(getattr(fn, "_compat_marks", []))
        marks.append(self.mark)
        fn._compat_marks = marks
        return fn


class MarkProxy:
    def parametrize(self, argnames, argvalues):
        if isinstance(argnames, str):
            names = [n.strip() for n in argnames.split(",") if n.strip()]
        else:
            names = list(argnames)
        return MarkDecorator(Mark("parametrize", (names, list(argvalues)), {}))

    def __getattr__(self, name):
        return MarkDecorator(Mark(name, (), {}))


mark = MarkProxy()


def fixture(*args, **kwargs):
    # The compat runner supplies these fixtures itself, so this is a passthrough.
    def decorate(fn):
        fn._compat_fixture = True
        return fn

    if args and callable(args[0]):
        return decorate(args[0])
    return decorate


@contextmanager
def raises(expected):
    try:
        yield
    except expected:
        return
    except Exception as exc:  # pragma: no cover - diagnostic
        raise AssertionError(f"expected {expected.__name__}, got {type(exc).__name__}: {exc}")
    raise AssertionError(f"expected {expected.__name__} but nothing was raised")


def cases(fn):
    """Yield (case_id, kwargs) for a test function, expanding parametrize marks."""
    marks = getattr(fn, "_compat_marks", [])
    param_marks = [m for m in marks if m.name == "parametrize"]
    if not param_marks:
        return [( "", {})]
    # expand all parametrize marks as a cartesian product
    combos: list[dict] = [{}]
    ids: list[str] = []
    for mark_obj in param_marks:
        names, values = mark_obj.args
        new_combos = []
        for base in combos:
            for value in values:
                row = dict(base)
                if len(names) == 1:
                    row[names[0]] = value
                else:
                    row.update(dict(zip(names, value)))
                new_combos.append(row)
        combos = new_combos
    out = []
    for row in combos:
        sig = inspect.signature(fn)
        case_parts = [f"{k}={row[k]}" for k in row if k in sig.parameters]
        out.append(("-".join(case_parts), row))
    return out
