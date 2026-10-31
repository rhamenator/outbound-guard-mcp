"""Classify selected controlled fixture URLs without retaining raw client input."""


def fixture_url_class(value):
    if value is None:
        return "missing"
    if not isinstance(value, str):
        return "non_string"
    if value == "https://tls-handshake.test/plain":
        return "tls_fixture"
    if value == "http://allowed.test/plain":
        return "allowed_plain"
    return "other"
