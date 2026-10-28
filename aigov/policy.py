"""Loading and validation of aigov.policy.json."""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

from .models import CONTROL_IDS

POLICY_FILENAME = "aigov.policy.json"
DEFAULT_MAX_FILE_BYTES = 1_000_000


class PolicyError(ValueError):
    """Raised when a policy file is missing, malformed or invalid."""


@dataclass
class Policy:
    ai_usage: str = "declared"
    min_score: float = 70.0
    block_on_critical: bool = True
    review_threshold: float = 0.8
    min_test_ratio: float = 0.1
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    ignore: List[str] = field(default_factory=list)
    disabled_controls: List[str] = field(default_factory=list)
    extra_ai_commit_patterns: List[str] = field(default_factory=list)
    source: Optional[str] = None  # path the policy was loaded from, if any

    def __post_init__(self):
        self.compiled_commit_patterns: List[Pattern] = []
        for pattern in self.extra_ai_commit_patterns:
            try:
                self.compiled_commit_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as exc:
                raise PolicyError(
                    "extra_ai_commit_patterns: invalid regex %r (%s)" % (pattern, exc)
                )

    def is_disabled(self, control_id: str) -> bool:
        return control_id in self.disabled_controls

    def to_dict(self) -> dict:
        return {
            "ai_usage": self.ai_usage,
            "min_score": self.min_score,
            "block_on_critical": self.block_on_critical,
            "review_threshold": self.review_threshold,
            "min_test_ratio": self.min_test_ratio,
            "max_file_bytes": self.max_file_bytes,
            "ignore": list(self.ignore),
            "disabled_controls": list(self.disabled_controls),
            "extra_ai_commit_patterns": list(self.extra_ai_commit_patterns),
            "source": self.source,
        }


def _is_number(value) -> bool:
    # bool is a subclass of int; `true` is never a valid number here.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _string_list(key: str, value) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError("%s must be a list of strings" % key)
    return list(value)


def policy_from_dict(data, source: Optional[str] = None) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")

    known = set(Policy.__dataclass_fields__) - {"source"}
    unknown = sorted(set(data) - known)
    if unknown:
        raise PolicyError("unknown policy key(s): %s" % ", ".join(unknown))

    kwargs = {}
    if "ai_usage" in data:
        if data["ai_usage"] not in ("declared", "none"):
            raise PolicyError('ai_usage must be "declared" or "none"')
        kwargs["ai_usage"] = data["ai_usage"]
    if "min_score" in data:
        value = data["min_score"]
        if not _is_number(value) or not 0 <= value <= 100:
            raise PolicyError("min_score must be a number between 0 and 100")
        kwargs["min_score"] = float(value)
    if "block_on_critical" in data:
        if not isinstance(data["block_on_critical"], bool):
            raise PolicyError("block_on_critical must be true or false")
        kwargs["block_on_critical"] = data["block_on_critical"]
    if "review_threshold" in data:
        value = data["review_threshold"]
        if not _is_number(value) or not 0 <= value <= 1:
            raise PolicyError("review_threshold must be a number between 0 and 1")
        kwargs["review_threshold"] = float(value)
    if "min_test_ratio" in data:
        value = data["min_test_ratio"]
        if not _is_number(value) or value < 0:
            raise PolicyError("min_test_ratio must be a non-negative number")
        kwargs["min_test_ratio"] = float(value)
    if "max_file_bytes" in data:
        value = data["max_file_bytes"]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PolicyError("max_file_bytes must be a positive integer")
        kwargs["max_file_bytes"] = value
    if "ignore" in data:
        kwargs["ignore"] = _string_list("ignore", data["ignore"])
    if "disabled_controls" in data:
        controls = _string_list("disabled_controls", data["disabled_controls"])
        bad = [c for c in controls if c not in CONTROL_IDS]
        if bad:
            raise PolicyError("disabled_controls: unknown control id(s): %s" % ", ".join(bad))
        kwargs["disabled_controls"] = controls
    if "extra_ai_commit_patterns" in data:
        kwargs["extra_ai_commit_patterns"] = _string_list(
            "extra_ai_commit_patterns", data["extra_ai_commit_patterns"]
        )

    return Policy(source=source, **kwargs)


def load_policy(path: Optional[str] = None, root: Optional[str] = None) -> Policy:
    """Load an explicit policy file, else `<root>/aigov.policy.json`, else defaults."""
    if path is None:
        if root is None:
            return Policy()
        candidate = os.path.join(root, POLICY_FILENAME)
        if not os.path.isfile(candidate) or os.path.islink(candidate):
            return Policy()
        path = candidate
    elif not os.path.isfile(path):
        raise PolicyError("policy file not found: %s" % path)

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise PolicyError("policy file is not valid JSON: %s (%s)" % (path, exc))
    except OSError as exc:
        raise PolicyError("cannot read policy file %s: %s" % (path, exc))
    return policy_from_dict(data, source=path)
