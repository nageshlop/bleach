from collections import OrderedDict
import re

import six


def _attr_key(attr):
    """Returns appropriate key for sorting attribute names

    Attribute names are a tuple of ``(namespace, name)`` where namespace can be
    ``None`` or a string. These can't be compared in Python 3, so we conver the
    ``None`` to an empty string.

    """
    key = (attr[0][0] or ""), attr[0][1]
    return key


def alphabetize_attributes(attrs):
    """Takes a dict of attributes (or None) and returns them alphabetized"""
    if not attrs:
        return attrs

    return OrderedDict([(k, v) for k, v in sorted(attrs.items(), key=_attr_key)])


def force_unicode(text):
    """Takes a text (Python 2: str/unicode; Python 3: unicode) and converts to unicode

    :arg str/unicode text: the text in question

    :returns: text as unicode

    :raises UnicodeDecodeError: if the text was a Python 2 str and isn't in
        utf-8

    """
    # If it's already unicode, then return it
    if isinstance(text, six.text_type):
        return text

    # If not, convert it
    return six.text_type(text, "utf-8", "strict")


# a subset of Django's URL validator
#
# from https://github.com/django/django/blob/3.1.3/django/core/validators.py#L63-L90

# IP patterns
ipv4_re = r"(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}"
ipv6_re = r"\[[0-9a-f:.]+\]"  # (simple regex, validated later)

# Host patterns
ul = ""  # "\u00a1-\uffff"  # Unicode letters range (must not be a raw string).

hostname_re = r"[a-z" + ul + r"0-9](?:[a-z" + ul + r"0-9-]{0,61}[a-z" + ul + r"0-9])?"
# Max length for domain name labels is 63 characters per RFC 1034 sec. 3.1
domain_re = r"(?:\.(?!-)[a-z" + ul + r"0-9-]{1,63}(?<!-))*"
tld_re = (
    r"\."  # dot
    r"(?!-)"  # can't start with a dash
    r"(?:[a-z" + ul + "-]{2,63}"  # domain label
    r"|xn--[a-z0-9]{1,59})"  # or punycode label
    r"(?<!-)"  # can't end with a dash
    r"\.?"  # may have a trailing dot
)
host_re = "(" + hostname_re + domain_re + tld_re + "|localhost)"

netloc_re = r"(?:" + ipv4_re + "|" + ipv6_re + "|" + host_re + ")"  # network location
port_re = r"(?::\d{2,5})?"  # port

netloc_port_re = re.compile("^" + netloc_re + port_re + "$", re.IGNORECASE)


# Characters valid in scheme names
scheme_chars = (
    "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789" "+-."
)


def _is_valid_netloc_and_port(netloc):
    """
    Returns the scheme for a URI or None when parsing the URI fails

    :arg str/unicode netloc:

    :returns: bool

    """
    return bool(netloc_port_re.match(netloc))


def _parse_uri_scheme(uri):
    """
    Returns the scheme for a URI or None when parsing the URI fails

    :arg str/unicode text:

    :returns: text or None

    """
    # replicate Python 3.9 urlparse scheme parsing for older Python versions
    i = uri.find(":")
    if i > 0:
        scheme = uri[:i]
        for c in uri[:i]:
            if c not in scheme_chars:
                break
        return scheme

    return None
