import re

_DOMAIN_CHARS = re.compile(r"[A-Za-z0-9.\-]+")
_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}", re.ASCII)


def is_valid_domain(text):
    if not text or not _DOMAIN_CHARS.fullmatch(text):
        return False
    return not text.startswith(".") and ".." not in text


def normalize(name):
    name = name.lower()
    return name[:-1] if name.endswith(".") else name


def is_ipv4(text):
    return bool(_IPV4.fullmatch(text)) and all(
        int(part) <= 255 for part in text.split(".")
    )


def matches(name, entries):
    labels = name.split(".")
    return any(
        ".".join(labels[i:]) in entries
        for i in range(len(labels))
    )


def fmt(value):
    return "-" if value is None else str(value)