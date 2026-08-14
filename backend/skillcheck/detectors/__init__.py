from .prose import detect_prose
from .prose_intl import detect_prose_intl
from .code import detect_code, detect_shell_patterns
from .secrets import detect_secrets
from .unicode_tricks import detect_unicode
from .extended import detect_extended

ALL_DETECTORS = [
    ("prose", detect_prose),
    ("prose-intl", detect_prose_intl),
    ("code", detect_code),
    ("shell", detect_shell_patterns),
    ("secrets", detect_secrets),
    ("unicode", detect_unicode),
    ("extended", detect_extended),
]

__all__ = [
    "detect_prose", "detect_prose_intl", "detect_code", "detect_shell_patterns",
    "detect_secrets", "detect_unicode", "detect_extended", "ALL_DETECTORS",
]
