"""The generated models' codec: JSON in and out, checked against each field's type descriptor.

A descriptor is a tuple: ("str",), ("int",), ("number",), ("bool",), ("any",), ("datetime",), ("list", d),
("map", d), ("nullable", d) or ("ref", "ClassName"). _models.py declares each class's fields with them.
"""

from __future__ import annotations

import dataclasses
import datetime
from typing import Any, ClassVar, NamedTuple


class DecodeError(ValueError):
    """A JSON value that does not fit the contract's type (the path names where)."""


class Field(NamedTuple):
    json: str
    attr: str
    type: tuple
    required: bool


class Operation(NamedTuple):
    method: str
    path: str
    auth: str
    max_body: int
    request: type[Model] | None
    response: type[Model] | None


class Model:
    """The base of every generated class."""

    __slots__ = ()
    _STRICT: ClassVar[bool] = False
    _FIELDS: ClassVar[tuple[Field, ...]] = ()

    def to_dict(self) -> dict[str, Any]:
        """The JSON object; an optional field that is None is left out."""
        out: dict[str, Any] = {}
        for f in self._FIELDS:
            value = getattr(self, f.attr)
            if value is None and not f.required:
                continue
            out[f.json] = _encode(value, f.type, f"{type(self).__name__}.{f.attr}")
        return out

    @classmethod
    def from_dict(cls, data: Any, *, strict: bool = True, _path: str = ""):
        """Decode a JSON object. strict refuses a key the contract does not name; a missing required key and a
        value of the wrong JSON type are always refused (DecodeError)."""
        path = _path or cls.__name__
        if not isinstance(data, dict):
            raise DecodeError(f"{path}: an object is expected, not {_kind(data)}")
        known = {f.json for f in cls._FIELDS}
        if strict:
            unknown = sorted(k for k in data if k not in known)
            if unknown:
                raise DecodeError(f"{path}: unknown field {unknown[0]!r}")
        kwargs: dict[str, Any] = {}
        for f in cls._FIELDS:
            if f.json not in data:
                if f.required:
                    raise DecodeError(f"{path}: missing field {f.json!r}")
                continue
            kwargs[f.attr] = _decode(data[f.json], f.type, f"{path}.{f.json}", strict)
        return cls(**kwargs)


def _models() -> dict[str, type[Model]]:
    from ._models import MODELS  # the generated module imports this one

    return MODELS


def _kind(v: Any) -> str:
    return "null" if v is None else type(v).__name__


def _decode(v: Any, d: tuple, path: str, strict: bool) -> Any:
    tag = d[0]
    if tag == "nullable":
        return None if v is None else _decode(v, d[1], path, strict)
    if tag == "any":
        return v
    if tag == "str":
        if isinstance(v, str):
            return v
    elif tag == "int":
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    elif tag == "number":
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    elif tag == "bool":
        if isinstance(v, bool):
            return v
    elif tag == "datetime":
        if isinstance(v, str):
            try:
                t = datetime.datetime.fromisoformat(v)
            except ValueError as e:
                raise DecodeError(f"{path}: not an RFC 3339 time: {v!r}") from e
            if t.tzinfo is None:
                raise DecodeError(f"{path}: a time without a zone: {v!r}")
            return t
    elif tag == "list":
        if isinstance(v, list):
            return [_decode(x, d[1], f"{path}[{i}]", strict) for i, x in enumerate(v)]
    elif tag == "map":
        if isinstance(v, dict):
            return {k: _decode(x, d[1], f"{path}.{k}", strict) for k, x in v.items()}
    elif tag == "ref":
        return _models()[d[1]].from_dict(v, strict=strict, _path=path)
    else:
        raise DecodeError(f"{path}: unknown descriptor {d!r}")
    raise DecodeError(f"{path}: {tag} expected, not {_kind(v)}")


def _encode(v: Any, d: tuple, path: str) -> Any:
    tag = d[0]
    if v is None:
        if tag in ("nullable", "any"):
            return None
        raise ValueError(f"{path} is required")
    if tag == "nullable":
        return _encode(v, d[1], path)
    if tag == "datetime":
        if not isinstance(v, datetime.datetime) or v.tzinfo is None:
            raise ValueError(f"{path}: an aware datetime is expected")
        return v.isoformat()
    if tag == "ref":
        if isinstance(v, Model):
            return v.to_dict()
        if isinstance(v, dict):
            return v
        raise ValueError(f"{path}: {d[1]} or a dict is expected, not {_kind(v)}")
    if tag == "list":
        return [_encode(x, d[1], path) for x in v]
    if tag == "map":
        return {k: _encode(x, d[1], path) for k, x in v.items()}
    if tag == "any":
        return _plain(v)
    return v


def _plain(v: Any) -> Any:
    """A JSON value, with any model inside it turned into its dict."""
    if isinstance(v, Model):
        return v.to_dict()
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return dataclasses.asdict(v)
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v
