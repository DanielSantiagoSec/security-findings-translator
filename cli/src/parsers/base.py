from __future__ import annotations
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Union
from ..models.finding import NormalizedFinding

logger = logging.getLogger(__name__)

class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, data: Any) -> bool: ...

    @abstractmethod
    def parse(self, data: Any) -> list[NormalizedFinding]: ...

    def _safe_get(self, d: dict, *keys, default=None) -> Any:
        val = d
        for key in keys:
            if not isinstance(val, dict):
                return default
            val = val.get(key, default)
            if val is None:
                return default
        return val

class ParserFactory:
    _registry = None

    @classmethod
    def _get_registry(cls):
        if cls._registry is None:
            from .guardduty import GuardDutyParser
            from .security_hub import SecurityHubParser
            from .nessus import NessusParser
            from .generic_json import GenericJSONParser
            from .generic_csv import GenericCSVParser
            cls._registry = [
                GuardDutyParser(),
                SecurityHubParser(),
                NessusParser(),
                GenericJSONParser(),
                GenericCSVParser(),
            ]
        return cls._registry

    @classmethod
    def for_data(cls, data: Any) -> BaseParser:
        for parser in cls._get_registry():
            try:
                if parser.can_parse(data):
                    return parser
            except Exception as e:
                logger.warning(f"Parser {parser.__class__.__name__} raised during can_parse: {e}")
        from .generic_json import GenericJSONParser
        return GenericJSONParser()

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> list[NormalizedFinding]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Finding file not found: {path}")
        if path.suffix.lower() == ".csv":
            from .generic_csv import GenericCSVParser
            parser = GenericCSVParser()
            with open(path, "r", encoding="utf-8-sig") as f:
                data = f.read()
            return parser.parse(data)
        with open(path, "r", encoding="utf-8-sig") as f:
            raw = json.load(f)
        parser = cls.for_data(raw)
        return parser.parse(raw)
