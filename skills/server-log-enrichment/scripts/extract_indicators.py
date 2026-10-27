#!/usr/bin/env python3
"""Extract unique IPs, hostnames and user agents from web server logs.

Streams one or more logs (plain or gzip, or "-" for stdin), so a multi-gigabyte
file is fine. Writes the unique indicators with counts to JSON Lines files and a
small summary.json. It never writes request paths, query strings, headers,
cookies, or bodies, so nothing but indicators can leave the log through it.

Formats it reads, per line, so a log whose format changes partway through still
works: JSON lines (nginx, Caddy, Traefik, Cloudflare Logpush, Google Cloud, and
most structured loggers), Apache and nginx common, combined and vhost combined,
W3C extended (IIS, CloudFront), AWS Application Load Balancer, Envoy default,
HAProxy HTTP, and any of those wrapped in a syslog or RFC 5424 prefix or in a
Docker json-file record. Anything else works through --regex or --map. See
references/formats.md in the skill for where each platform keeps the real client
address. Nothing here touches the network.

Output files, in the --out directory (rewritten on every run):
  ips.jsonl          one object per unique IP address
  hostnames.jsonl    one object per unique hostname
  user_agents.jsonl  one object per unique user agent string
  summary.json       counts, the format and keys used, malformed samples

These are working files, not a spreadsheet. Strings are written as found, so a
user agent can be sent to a lookup unchanged. The one exception is W3C logs,
which escape spaces in user agents (IIS writes +, CloudFront writes %20); those
are decoded so the lookup sees the real string. Use --no-decode to keep them.

Exit codes:
  0  success
  2  bad arguments
  3  an input file could not be read, or the output directory could not be made
  4  the format did not resolve (too few lines parsed). Outputs are still
     written; see malformed_samples in summary.json, show them to the user, and
     rerun with --format, --regex or --map.
"""

import argparse
import gzip
import ipaddress
import json
import os
import re
import sys
from functools import lru_cache
from urllib.parse import unquote, urlsplit

EXIT_USAGE = 2
EXIT_IO = 3
EXIT_FORMAT = 4

Q = r'(?:[^"\\]|\\.)*'
# Referer is either quoted or a bare "-". Traefik's CLF writes the empty
# referer unquoted and then a quoted user agent. The tail after that is ignored.
_PREFIX = (
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]*)\] "(?P<request>' + Q + r')" '
    r'(?P<status>\d{3}|-) (?P<bytes>\S+) '
    r'(?:"(?P<referer>' + Q + r')"|-) "(?P<ua>' + Q + r')"'
)
COMBINED = re.compile(_PREFIX + r'(?P<tail>.*)$')
COMBINED_XFF = re.compile(_PREFIX + r' "(?P<xff>' + Q + r')"\s*$')
VHOST = re.compile(r'^(?P<host>\S+):(?P<vport>\d+) ' + _PREFIX[1:] + r'(?P<tail>.*)$')
VHOST_XFF = re.compile(
    r'^(?P<host>\S+):(?P<vport>\d+) ' + _PREFIX[1:] + r' "(?P<xff>' + Q + r')"\s*$'
)
COMMON = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]*)\] "(?P<request>' + Q + r')" '
    r'(?P<status>\d{3}|-)(?: (?P<bytes>\S+))?(?P<tail>.*)$'
)
# AWS Application Load Balancer: type time elb client:port target:port three
# processing times, elb_status, target_status, received, sent, "request", "ua".
# The type list grows (http, https, h2, h2c, grpc, grpcs, ws, wss, tls). The
# client field is ip:port, [ipv6]:port, or "-" when the port is unknown, so it
# is one token and parse_ip strips the port. New fields are appended and ignored.
ALB = re.compile(
    r'^(?:https?|h2c?|grpcs?|wss?|tls) (?P<time>\S+) \S+ (?P<ip>\S+) \S+ '
    r'\S+ \S+ \S+ (?P<status>\S+) \S+ \S+ \S+ '
    r'"(?P<request>' + Q + r')" "(?P<ua>' + Q + r')"'
)
# Envoy default: [time] "request" status then five fields, then quoted
# X-Forwarded-For, User-Agent, request id, authority. It has no peer address.
# A status of 0 means the server never sent a response.
ENVOY = re.compile(
    r'^(?:ACCESS )?\[(?P<time>[^\]]+)\] "(?P<request>' + Q + r')" (?P<status>\d+|-) (?:\S+ ){5}'
    r'"(?P<xff>' + Q + r')" "(?P<ua>' + Q + r')" "' + Q + r'" "(?P<host>' + Q + r')"'
)
# HAProxy HTTP log (after any syslog prefix): client_ip:port [accept date]
# frontend backend/server [optional host] timers status bytes cookies state
# counts queues, optional {captured headers} "request". The optional host must
# not itself look like a timer, or a classic line would shift by one field.
_HAPROXY_HOST = r'(?:(?!-?\d+(?:/-?\d+){1,6}\s)\S+ )?'
HAPROXY = re.compile(
    r'^(?P<ip>\S+):(?P<port>\d+) \[(?P<time>[^\]]+)\] \S+ \S+/\S+ '
    + _HAPROXY_HOST +
    r'\S+ (?P<status>\d{3}) \S+ \S+ \S+ \S+ \S+ \S+ '
    r'(?:\{[^}]*\} ){0,2}"(?P<request>' + Q + r')"\s*$'
)
# A leading quoted comma-separated address list in front of a normal line:
# `"203.0.113.1, 198.51.100.2" 203.0.113.9 - - [time] ...`
_QUOTED_CHAIN = re.compile(r'^"(?P<chain>' + Q + r')"\s+(?P<rest>\S.*)$')
SYSLOG = re.compile(
    r'^(?:<\d+>)?(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d\S*) '
    r'\S+ [^\s:]+(?:\[\d+\])?: '
)
# RFC 5424: <pri>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA SP MSG
RFC5424 = re.compile(
    r'^<\d+>\d+ \d{4}-\d\d-\d\dT\S+ \S+ \S+ \S+ \S+ (?:-|\[[^\]]*\]) '
)
# Email shapes are scanned by hand, not with a regex. An unanchored
# `[local]+@...` search is quadratic on a long line that merely contains `@`.
_EMAIL_LOCAL = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-')
_EMAIL_DOMAIN = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-')
SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://')
QUERY_RE = re.compile(r'\?[^ \t"]*')
# Names that, followed by =, almost always carry a credential. The value is
# counted and redacted in samples. It is never stored.
# `_` counts as a separator, so oauth_token, access_token and id_token match
# `token` without also matching a word that merely contains those letters.
_SECRET_NAME = (
    r'password|passwd|pwd|pass|token|secret|api[_-]?key|access[_-]?key|'
    r'session(?:id)?'
)
_SECRET_EDGE = r'(?i)(?<![A-Za-z0-9])'
SENSITIVE_RE = re.compile(
    _SECRET_EDGE + r'(?:' + _SECRET_NAME + r')\s*=\s*[^\s&;,]+'
)
ASSIGN_RE = re.compile(
    _SECRET_EDGE + r'(' + _SECRET_NAME + r')\s*=\s*[^\s&;,\"\']+'
)
BEARER_RE = re.compile(r'(?i)\bBearer\s+\S+')
JWT_SAMPLE_RE = re.compile(
    r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}'
)
MAX_LINE = 262144
CGNAT = ipaddress.ip_network('100.64.0.0/10')

HOST_RE = re.compile(r'^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$')

# Candidate JSON key names per field, normalised to lower case with "-" as "_".
# Candidate JSON key paths per field. Dots nest, matching ignores case and treats
# "-" as "_". The first non-empty match wins, except xff, where every match is
# joined, most trustworthy first. Names come from the platforms' own docs:
# nginx and Apache JSON formats, Caddy (request.*), Traefik, Cloudflare Logpush,
# Google Cloud (httpRequest.*) and common structured loggers.
JSON_CANDIDATES = {
    'ip': ['remote_addr', 'client_ip', 'clientip', 'remote_ip', 'remoteip', 'c_ip',
           'src_ip', 'source_ip', 'clienthost', 'clientaddr',
           'request.remote_ip', 'httprequest.remoteip',
           'jsonpayload.httprequest.remoteip', 'ip'],
    'xff': ['request.client_ip', 'http_cf_connecting_ip', 'cf_connecting_ip',
            'request.headers.cf_connecting_ip', 'http_true_client_ip',
            'true_client_ip', 'request.headers.true_client_ip', 'http_x_real_ip',
            'x_real_ip', 'request.headers.x_real_ip', 'http_x_forwarded_for',
            'x_forwarded_for', 'xff', 'forwarded_for',
            'request.headers.x_forwarded_for'],
    'ua': ['http_user_agent', 'user_agent', 'useragent', 'ua', 'agent',
           'cs_user_agent', 'clientrequestuseragent', 'request_user_agent',
           'request.headers.user_agent', 'httprequest.useragent',
           'jsonpayload.httprequest.useragent'],
    'referer': ['http_referer', 'referer', 'referrer', 'cs_referer',
                'clientrequestreferer', 'request_referer',
                'request.headers.referer', 'httprequest.referer',
                'jsonpayload.httprequest.referer'],
    'host': ['server_name', 'http_host', 'host', 'cs_host', 'clientrequesthost',
             'requesthost', 'request.host'],
    'status': ['status', 'sc_status', 'response_code', 'status_code',
               'edgeresponsestatus', 'downstreamstatus', 'httprequest.status',
               'jsonpayload.httprequest.status'],
    'time': ['time_local', 'time_iso8601', 'timestamp', '@timestamp', 'time',
             'datetime', 'edgestarttimestamp', 'startutc', 'ts'],
    'request': ['request', 'request_line'],
    'uri': ['request_uri', 'uri', 'request_path', 'path', 'url',
            'clientrequesturi', 'requestpath', 'request.uri',
            'httprequest.requesturl', 'jsonpayload.httprequest.requesturl'],
    'method': ['request_method', 'method', 'http_method', 'cs_method',
               'clientrequestmethod', 'requestmethod', 'request.method',
               'httprequest.requestmethod',
               'jsonpayload.httprequest.requestmethod'],
}
JSON_FIELDS = list(JSON_CANDIDATES)
JSON_MULTI = ('xff',)

# W3C extended logs (IIS, CloudFront): field names that map to our fields.
W3C_ALIASES = {
    'ip': ['c-ip'],
    'xff': ['x-forwarded-for', 'cs(x-forwarded-for)'],
    'ua': ['cs(user-agent)', 'cs-user-agent'],
    'referer': ['cs(referer)', 'cs(referrer)', 'cs-referer'],
    'host': ['x-host-header', 'cs-host', 'cs(host)'],
    'status': ['sc-status'],
    'method': ['cs-method'],
    'uri': ['cs-uri-stem'],
}

SKIP_REFERERS = ('', '-', '(direct)')
LABEL_BITS = {'connecting': 1, 'chain_1': 2, 'chain_2': 4, 'chain_3plus': 8}
MAX_SAMPLES = 3
SAMPLE_CHARS = 200
FORMATS = ['auto', 'json', 'combined', 'combined-xff', 'common',
           'vhost-combined', 'w3c', 'alb', 'envoy', 'haproxy']


def norm_key(key):
    return str(key).lower().replace('-', '_')


def norm_parts(path):
    return [norm_key(p) for p in path.split('.')]


def get_ci(obj, parts, top):
    """Walk nested dicts, matching keys case-insensitively. top maps the
    normalised top-level keys of obj to the real ones."""
    cur = obj
    for depth, part in enumerate(parts):
        if not isinstance(cur, dict):
            return None
        if depth == 0:
            real = top.get(part)
            if real is None:
                return None
            cur = cur[real]
        elif part in cur:
            cur = cur[part]
        else:
            for k, v in cur.items():
                if norm_key(k) == part:
                    cur = v
                    break
            else:
                return None
    return cur


def as_text(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ','.join(str(v) for v in value)
    if isinstance(value, (dict, bool)):
        return None
    return str(value)


def parse_ip(token):
    """Return a canonical IP string, or None. Strips ports and brackets.

    Only short tokens are cached. A long unique token is never an address that
    repeats, and caching it would keep the whole log in memory.
    """
    if token is None:
        return None
    if len(token) > 256:
        return _parse_ip(token)
    return _parse_ip_cached(token)


@lru_cache(maxsize=262144)
def _parse_ip_cached(token):
    return _parse_ip(token)


def _parse_ip(token):
    s = token.strip().strip('"')
    if not s or s in ('-', 'unknown'):
        return None
    if s.startswith('['):
        end = s.find(']')
        if end == -1:
            return None
        s = s[1:end]
    elif s.count(':') == 1 and '.' in s:
        host, _, port = s.rpartition(':')
        # Only a numeric port. `8.8.8.8:not-an-address` must not become 8.8.8.8.
        if port.isdigit():
            s = host
    s = s.split('%', 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def norm_host(raw):
    """Return ('host', name), ('ip', literal) or None."""
    if raw is None or len(raw) > 512:
        return None
    return _norm_host(raw)


@lru_cache(maxsize=262144)
def _norm_host(raw):
    h = raw.strip().lower().rstrip('.')
    if not h:
        return None
    if h.startswith('['):
        return ('ip', h)
    if h.count(':') == 1:
        host, _, port = h.rpartition(':')
        if port.isdigit():
            h = host
    if '..' in h:
        return None
    if not HOST_RE.match(h):
        try:
            h = h.encode('idna').decode('ascii')
        except (UnicodeError, ValueError):
            return None
        if '..' in h or not HOST_RE.match(h):
            return None
    try:
        ipaddress.ip_address(h)
        return ('ip', h)
    except ValueError:
        return ('host', h)


def referer_host(raw):
    """Return (hostname or None, was_malformed).

    The host sits before the query, so a multi-kilobyte tracking URL is cut
    there. Anything still huge is not a hostname and is not cached.
    """
    if not raw:
        return None, False
    if len(raw) > 4096:
        cut = raw.find('?')
        if cut == -1 or cut > 2048:
            return None, True
        raw = raw[:cut]
    if len(raw) > 512:
        return _referer_host(raw)
    return _referer_host_cached(raw)


@lru_cache(maxsize=131072)
def _referer_host_cached(raw):
    return _referer_host(raw)


def _referer_host(raw):
    try:
        return urlsplit(raw).hostname, False
    except ValueError:
        return None, True


def status_bucket(status):
    if not status:
        return 4
    # JSON sometimes yields 200.0 once the number has been through a float.
    if len(status) == 5 and status.endswith('.0') and status[:3].isdigit():
        status = status[:3]
    if status[:1] in '2345' and len(status) == 3 and status.isdigit():
        return int(status[0]) - 2
    return 4


def clean_xff_token(token):
    """One forwarded-chain token: strip quotes, RFC 7239 `for=`, and `;params`.

    nginx writes a quote inside the quoted field as ``\\x22`` (or ``\\"``), so
    undo that before parsing. The address is what gets kept.
    """
    t = token.strip().replace('\\x22', '"').replace('\\"', '"')
    t = t.strip().strip('"').strip("'")
    if ';' in t:
        t = t.split(';', 1)[0].strip()
    if len(t) > 4 and t[:4].lower() == 'for=':
        t = t[4:].strip().strip('"').strip("'")
    return t


def peel_quoted_chain(line):
    """Split a leading quoted address list off a normal log line.

    Returns (chain, rest) or (None, line). The next token must be an address.
    A hostname sitting in front of the quotes is left untouched.
    """
    if not line.startswith('"'):
        return None, line
    m = _QUOTED_CHAIN.match(line)
    if not m:
        return None, line
    inside = m.group('chain')
    if ',' not in inside:
        return None, line
    if not any(parse_ip(clean_xff_token(t)) for t in inside.split(',')):
        return None, line
    rest = m.group('rest')
    nxt = rest.split(' ', 1)[0]
    if parse_ip(nxt) is None:
        return None, line
    return inside, rest


def fold_comma_list(line):
    """Rewrite `ip, ip, ip ident user [time]` so a normal parser can read it.

    The address tokens are one forwarded chain. When ident and user follow
    them directly, there is no connecting address. When one more address sits
    between the list and ident (`ip, ip real ident user`), that address is the
    connecting client and stays in the line.
    """
    bracket = line.find(' [')
    if bracket < 0 or ',' not in line[:bracket]:
        return None, line
    tokens = line[:bracket].split()
    if not tokens or ',' not in tokens[0]:
        return None, line
    addrs = []
    i = 0
    while i < len(tokens) and tokens[i].rstrip('"').endswith(','):
        tok = tokens[i].strip('"').rstrip(',')
        if not parse_ip(clean_xff_token(tok)):
            return None, line
        addrs.append(tok)
        i += 1
    if i >= len(tokens):
        return None, line
    last = tokens[i].strip('"').rstrip(',')
    if not parse_ip(clean_xff_token(last)):
        return None, line
    addrs.append(last)
    i += 1
    if len(addrs) < 2:
        return None, line
    rest = tokens[i:]
    client = '-'
    if len(rest) == 3 and parse_ip(rest[0]):
        client = rest[0]
        rest = rest[1:]
    if len(rest) != 2:
        return None, line
    rebuilt = '%s %s%s' % (client, ' '.join(rest), line[bracket:])
    return ', '.join(addrs), rebuilt


def recover_comma_chain(line, fields):
    """Turn `ip, ip, ip - - [time]` into one forwarded chain.

    Combined captures the first token as the client and the next two as ident
    and user. When those tokens are addresses, there is no connecting address:
    every one of them is a claim.
    """
    raw = fields.get('ip') or ''
    if ',' not in raw or parse_ip(raw) is not None:
        return fields
    bracket = line.find(' [')
    if bracket < 0:
        return fields
    head = line[:bracket].split()
    start = None
    for i, tok in enumerate(head):
        if tok == raw or tok.rstrip(',') == raw.rstrip(','):
            start = i
            break
    if start is None:
        return fields
    addrs = []
    i = start
    while i < len(head):
        tok = head[i].strip('"').rstrip(',')
        if parse_ip(clean_xff_token(tok)):
            addrs.append(tok)
            i += 1
            continue
        break
    if len(addrs) < 2:
        return fields
    fields = dict(fields)
    fields['ip'] = None
    chain = ', '.join(addrs)
    prev = fields.get('xff')
    fields['xff'] = chain if not prev else '%s, %s' % (chain, prev)
    return fields


def attach_chain(result, chain):
    """Prepend a peeled quoted chain to a parsed line's forwarded field."""
    if result is None or not chain:
        return result
    name, fields = result
    if not fields:
        return result
    fields = dict(fields)
    prev = fields.get('xff')
    fields['xff'] = chain if not prev else '%s, %s' % (chain, prev)
    return name, fields


def request_hostname(target):
    """Hostname of an absolute or protocol-relative request target, else None.

    A target that only contains `://` later on, such as a query value, is not a
    request to that host.
    """
    if not target:
        return None
    raw = 'http:' + target if target.startswith('//') else target
    if not SCHEME_RE.match(raw):
        return None
    try:
        return urlsplit(raw).hostname
    except ValueError:
        return None


def email_span(text, at):
    """(start, end) of an email-shaped address around this `@`, or None.

    The walk is capped (64 before, 253 after), so a line of `@` and letters
    stays linear. Longer than a real address is still detected; the span is
    the part that fits the cap.
    """
    i = at - 1
    seen = 0
    while i >= 0 and seen < 64 and text[i] in _EMAIL_LOCAL:
        i -= 1
        seen += 1
    if seen < 1:
        return None
    start = i + 1
    end_limit = min(len(text), at + 1 + 253)
    k = at + 1
    while k < end_limit and text[k] in _EMAIL_DOMAIN:
        k += 1
    if k > at + 1 and text[k - 1] == '.':
        k -= 1
    last_dot = text.rfind('.', at + 1, k)
    if last_dot == -1 or k - last_dot - 1 < 2:
        return None
    if not text[last_dot + 1:k].isalpha():
        return None
    return start, k


def contains_email(text):
    if not text or '@' not in text:
        return False
    start = 0
    while True:
        at = text.find('@', start)
        if at < 0:
            return False
        if email_span(text, at):
            return True
        start = at + 1


def redact_emails(text):
    if '@' not in text:
        return text
    out = []
    i = 0
    n = len(text)
    while i < n:
        at = text.find('@', i)
        if at < 0:
            out.append(text[i:])
            break
        span = email_span(text, at)
        if not span:
            out.append(text[i:at + 1])
            i = at + 1
            continue
        out.append(text[i:span[0]])
        out.append('[email]')
        i = span[1]
    return ''.join(out)


def redact_sample(line):
    """Query strings, emails, bearers and credential assignments stay out of samples."""
    line = redact_emails(line)
    line = ASSIGN_RE.sub(lambda m: m.group(1) + '=[redacted]', line)
    line = BEARER_RE.sub('Bearer [redacted]', line)
    line = JWT_SAMPLE_RE.sub('[jwt]', line)
    line = QUERY_RE.sub('?[redacted]', line)
    return line[:SAMPLE_CHARS]


def text_is_sensitive(text):
    """True when text holds a credential-shaped assignment.

    An email address does not count. Crawler user agents publish a contact
    address, and that must not block a lookup. Callers use this as a flag.
    They must not keep the match.
    """
    if not text:
        return False
    return SENSITIVE_RE.search(text) is not None


def strip_prefix(line):
    """Line with a BSD syslog or RFC 5424 header removed, or None."""
    m = RFC5424.match(line)
    if m:
        return line[m.end():]
    m = SYSLOG.match(line)
    if m:
        return line[m.end():]
    return None


def unwrap_docker(line):
    """Inner line of a Docker json-file record, or the line unchanged.

    A top-level `log` or `message` string plus `stream` of stdout or stderr.
    `log` wins when both are present. A JSON access log that merely mentions
    those words, and anything without `stream`, is left alone.
    """
    if line[:1] != '{' or '"stream"' not in line:
        return line
    if '"log"' not in line and '"message"' not in line:
        return line
    try:
        obj = json.loads(line)
    except (ValueError, RecursionError):
        return line
    if not isinstance(obj, dict) or obj.get('stream') not in ('stdout', 'stderr'):
        return line
    inner = obj.get('log')
    if not isinstance(inner, str):
        inner = obj.get('message')
    if not isinstance(inner, str):
        return line
    inner = inner.strip()
    return inner or line


def open_text(path):
    if path == '-':
        try:
            sys.stdin.reconfigure(errors='replace')
        except AttributeError:
            pass
        return sys.stdin
    with open(path, 'rb') as probe:
        magic = probe.read(4)
    if magic[:2] == b'\x1f\x8b':
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    if magic[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return open(path, 'r', encoding='utf-16', errors='replace', newline='')
    encoding = 'utf-8-sig' if magic.startswith(b'\xef\xbb\xbf') else 'utf-8'
    return open(path, 'r', encoding=encoding, errors='replace', newline='')


def iter_lines(stream, limit):
    """Yield text lines, never holding more than `limit` characters of one.

    A gzip stream with no newline would otherwise expand until memory runs out.
    A line past the limit is yielded as a shared marker of length limit+1; the
    rest of that physical line is discarded. Callers already treat that length
    as "too long, contents omitted".
    """
    buf = []
    size = 0
    overflow = False
    marker = 'x' * (limit + 1)

    def finish():
        nonlocal buf, size, overflow
        if overflow:
            buf = []
            size = 0
            overflow = False
            return marker
        text = ''.join(buf)
        if text.endswith('\r'):
            text = text[:-1]
        buf = []
        size = 0
        return text

    while True:
        chunk = stream.read(65536)
        if not chunk:
            if size or overflow:
                yield finish()
            return
        start = 0
        n = len(chunk)
        while start < n:
            nl = chunk.find('\n', start)
            if nl == -1:
                piece = chunk[start:]
                if not overflow:
                    room = limit + 1 - size
                    if len(piece) <= room:
                        buf.append(piece)
                        size += len(piece)
                    else:
                        if room > 0:
                            buf.append(piece[:room])
                        overflow = True
                start = n
                continue
            piece = chunk[start:nl]
            if not overflow and piece:
                room = limit + 1 - size
                if len(piece) <= room:
                    buf.append(piece)
                    size += len(piece)
                else:
                    if room > 0:
                        buf.append(piece[:room])
                    overflow = True
            yield finish()
            start = nl + 1


def regex_backtracks(pattern):
    """True when a quantifier wraps a group that already contains a quantifier.

    `(a+)+` and `(.*)*` are the shapes that take exponential time. A character
    class, a single `[^"]*`, or an alternation with no inner repeat is not this
    shape. `--regex` is the one pattern the script did not write, so this is
    refused up front. An alternation of different lengths, such as `(a|aa)+`,
    is a separate hang the caller still has to avoid.
    """
    i = 0
    n = len(pattern)
    stack = [[False, False]]  # this group contains a quantifier, an alternation
    atom_q = False
    atom_alt = False
    just = False

    def mark(unbounded):
        nonlocal atom_q, just
        if unbounded and atom_q:
            return True
        stack[-1][0] = True
        atom_q = True
        just = True
        return False

    while i < n:
        c = pattern[i]
        if c == '\\':
            i += 2
            atom_q = False
            atom_alt = False
            just = False
            continue
        if c == '[':
            i += 1
            if i < n and pattern[i] == '^':
                i += 1
            while i < n and pattern[i] != ']':
                if pattern[i] == '\\':
                    i += 2
                else:
                    i += 1
            i += 1
            atom_q = False
            atom_alt = False
            just = False
            continue
        if c == '(':
            if pattern.startswith('(?#', i):
                end = pattern.find(')', i)
                i = n if end == -1 else end + 1
                continue
            if pattern.startswith('(?P=', i):
                end = pattern.find(')', i)
                i = n if end == -1 else end + 1
                atom_q = False
                atom_alt = False
                just = False
                continue
            if pattern.startswith('(?P<', i):
                end = pattern.find('>', i)
                i = n if end == -1 else end + 1
            elif pattern.startswith(('(?=', '(?!', '(?:'), i):
                i += 3
            elif pattern.startswith(('(?<=', '(?<!'), i):
                i += 4
            elif i + 1 < n and pattern[i + 1] == '?':
                end = pattern.find(')', i)
                i = n if end == -1 else end + 1
                continue
            else:
                i += 1
            stack.append([False, False])
            atom_q = False
            atom_alt = False
            just = False
            continue
        if c == ')':
            frame = stack.pop() if len(stack) > 1 else [False, False]
            atom_q = frame[0]
            atom_alt = frame[1]
            just = False
            i += 1
            continue
        if c == '?' and just:
            just = False
            i += 1
            continue
        if c == '?':
            # Zero or one. Bounded, so it cannot explode even on a repeat inside.
            if mark(False):
                return True
            i += 1
            continue
        if c in '*+':
            if mark(True):
                return True
            i += 1
            continue
        if c == '{':
            end = pattern.find('}', i)
            if end == -1:
                i += 1
                continue
            body = pattern[i + 1:end]
            unbounded = True
            try:
                if ',' not in body:
                    unbounded = int(body) > 20
                else:
                    lo, hi = body.split(',', 1)
                    if hi.strip():
                        unbounded = int(hi) - int(lo or 0) > 20
            except ValueError:
                unbounded = True
            if mark(unbounded):
                return True
            i = end + 1
            continue
        if c == '|':
            stack[-1][1] = True
            atom_q = False
            atom_alt = False
            just = False
            i += 1
            continue
        atom_q = False
        atom_alt = False
        just = False
        i += 1
    return False


class Collector:
    def __init__(self, args, overrides, custom_regex, cdn_nets):
        self.args = args
        self.overrides = overrides
        self.custom_regex = custom_regex
        self.cdn_nets = cdn_nets
        self.top_cache = {}
        self.json_used = {f: set() for f in JSON_FIELDS}
        self.json_parts = {}
        for field in JSON_FIELDS:
            paths = overrides.get(field) or JSON_CANDIDATES[field]
            self.json_parts[field] = [(p, norm_parts(p)) for p in paths]
        self.w3c_fields = None
        self.w3c_map = {}
        self.saw_non_w3c = False
        self.last_parser = None
        self.lines_directive = 0
        self.saw_ip = False
        self.own = [h.strip().lower().rstrip('.')
                    for h in (args.own_hosts or '').split(',') if h.strip()]

        self.lines_read = 0
        self.lines_blank = 0
        self.lines_parsed = 0
        self.lines_malformed = 0
        self.formats = {}
        self.unmapped_tail_lines = 0
        self.malformed_samples = []
        self.tail_samples = []
        self.ips = {}
        self.hosts = {}
        self.uas = {}
        self.status_totals = [0, 0, 0, 0, 0]
        self.empty_ua_lines = 0
        self.bad_ip_values = 0
        self.bad_host_values = 0
        self.ip_literal_hosts = 0
        self.saw_chain = False
        self.email_hits = {}
        self.sensitive_lines = 0

    # ---- line parsing -------------------------------------------------
    def start_file(self):
        """Forget per-file state, such as a W3C #Fields header."""
        self.w3c_fields = None
        self.w3c_map = {}
        self.saw_non_w3c = False

    def _note_tail(self, line):
        self.unmapped_tail_lines += 1
        if len(self.tail_samples) < MAX_SAMPLES:
            self.tail_samples.append(redact_sample(line))

    def _defer_to_vhost(self, line, raw_ip):
        """True when this combined match is really vhost_combined.

        `example.com:80 203.0.113.5 - - ...` is a vhost prefix. An IPv4 with a
        port is the same shape when the next field is also an address
        (`1.2.3.4:80 203.0.113.5`). A bare token that is not host:port,
        including an anonymized client, `localhost`, or `unix:`, is the client
        field and must not be deferred.
        """
        token = (raw_ip or '').strip().strip('"')
        if not token:
            return False
        if parse_ip(token) is not None:
            if token.count(':') != 1 or '.' not in token:
                return False
            host, _, port = token.rpartition(':')
            if not port.isdigit() or parse_ip(host) is None:
                return False
            parts = line.split(' ')
            return len(parts) > 1 and parse_ip(parts[1]) is not None
        if token.count(':') != 1:
            return False
        host, _, port = token.rpartition(':')
        return bool(port.isdigit() and host and parse_ip(host) is None)

    def _regex(self, rx, line, note_tail=False):
        m = rx.match(line)
        if not m:
            return None
        d = m.groupdict()
        if note_tail and d.get('tail', '').strip():
            self._note_tail(line)
        return d

    def p_json(self, line):
        if line[:1] != '{':
            return None
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            return None
        if not isinstance(obj, dict):
            return None
        sig = tuple(obj.keys())
        entry = self.top_cache.get(sig)
        if entry is None:
            if len(self.top_cache) > 1000:
                self.top_cache.clear()
            top = {norm_key(k): k for k in obj}
            # Only candidates whose first path part exists in this key layout
            # can match, so the per-line loop never tries the others.
            plan = {f: [c for c in self.json_parts[f] if c[1][0] in top]
                    for f in JSON_FIELDS}
            entry = self.top_cache[sig] = (top, plan)
        top, plan = entry
        used = self.json_used
        out = {}
        for field in JSON_FIELDS:
            cands = plan[field]
            if field in JSON_MULTI:
                vals = []
                for label, parts in cands:
                    s = as_text(get_ci(obj, parts, top))
                    if s:
                        vals.append(s)
                        if label not in used[field] and len(used[field]) < 6:
                            used[field].add(label)
                out[field] = ','.join(vals) if vals else None
            else:
                val = None
                for label, parts in cands:
                    s = as_text(get_ci(obj, parts, top))
                    if s:
                        val = s
                        if label not in used[field] and len(used[field]) < 6:
                            used[field].add(label)
                        break
                out[field] = val
        # A JSON object that merely has an `ip` key is not an access log.
        # Accept it only when that key, or a forwarded field, is a real address,
        # so an application log cannot be counted as parsed traffic.
        if parse_ip(out.get('ip') or '') is None:
            xff = out.get('xff') or ''
            if not any(parse_ip(clean_xff_token(t)) for t in xff.split(',')):
                return None
        return out

    def _directive(self, line):
        if line.lower().startswith('#fields:'):
            # A header injected into a file that is already another format must
            # not make the following lines look like W3C clients. Concatenated
            # IIS files never parse as another format, so their headers still
            # apply.
            if self.saw_non_w3c:
                return
            names = [n.lower() for n in line.split(':', 1)[1].split()]
            self.w3c_fields = names
            mapping = {}
            for field, aliases in W3C_ALIASES.items():
                idxs = [names.index(alias) for alias in aliases if alias in names]
                if idxs:
                    mapping[field] = idxs
            if 'date' in names and 'time' in names:
                mapping['time'] = (names.index('date'), names.index('time'))
            elif 'time' in names:
                mapping['time'] = names.index('time')
            self.w3c_map = mapping

    def p_w3c(self, line):
        if not self.w3c_fields:
            return None
        tabbed = '\t' in line
        parts = line.split('\t') if tabbed else line.split(' ')
        # A trailing delimiter produces one empty extra column. Anything else
        # means this is not a W3C line (or the header does not match it).
        if parts and parts[-1] == '' and len(parts) == len(self.w3c_fields) + 1:
            parts.pop()
        if len(parts) != len(self.w3c_fields):
            return None
        out = {}
        for field, idx in self.w3c_map.items():
            if field == 'time' and isinstance(idx, tuple):
                out['time'] = '%s %s' % (parts[idx[0]], parts[idx[1]])
                continue
            if field == 'time':
                out['time'] = parts[idx]
                continue
            chosen = None
            for i in idx:
                v = parts[i]
                if v not in ('-', ''):
                    chosen = v
                    break
            if chosen and field in ('ua', 'referer', 'uri', 'xff') and not self.args.no_decode:
                # CloudFront is tab-separated and percent-encodes. IIS is
                # space-separated and writes '+' for a space. A value can
                # carry both, so percent-decoding does not replace the other.
                if tabbed or '%' in chosen:
                    chosen = unquote(chosen)
                if not tabbed and field != 'xff':
                    chosen = chosen.replace('+', ' ')
            out[field] = chosen
        if parse_ip(out.get('ip') or '') is None:
            xff = out.get('xff') or ''
            if not any(parse_ip(clean_xff_token(t)) for t in xff.split(',')):
                return None
        return out

    def p_combined(self, line):
        m = COMBINED.match(line)
        if not m:
            return None
        d = recover_comma_chain(line, m.groupdict())
        if self._defer_to_vhost(line, d.get('ip')):
            return None
        if d.get('tail', '').strip():
            self._note_tail(line)
        return d

    def p_combined_xff(self, line):
        m = COMBINED_XFF.match(line)
        if m:
            d = recover_comma_chain(line, m.groupdict())
            if not self._defer_to_vhost(line, d.get('ip')):
                return d
        m = VHOST_XFF.match(line)
        if not m:
            return None
        return recover_comma_chain(line, m.groupdict())

    def p_common(self, line):
        # Common is a prefix of combined, so it also matches a combined line
        # and drops the referer and user agent into the tail. Auto mode
        # retries the previous format first. One truncated line sticks that
        # format on common, and every later combined line would then lose
        # those fields. Let combined take the line instead.
        if self.args.format == 'auto' and COMBINED.match(line):
            return None
        m = COMMON.match(line)
        if not m:
            return None
        d = recover_comma_chain(line, m.groupdict())
        if self._defer_to_vhost(line, d.get('ip')):
            return None
        if d.get('tail', '').strip():
            self._note_tail(line)
        return d

    def p_vhost(self, line):
        m = VHOST.match(line)
        if not m:
            return None
        d = recover_comma_chain(line, m.groupdict())
        if d.get('tail', '').strip():
            self._note_tail(line)
        return d

    def p_alb(self, line):
        return self._regex(ALB, line)

    def p_envoy(self, line):
        return self._regex(ENVOY, line)

    def p_haproxy(self, line):
        return self._regex(HAPROXY, line)

    # W3C is last, so a line that already matches nginx or Apache is not
    # retargeted. A #Fields line is also ignored once any non-W3C line has
    # parsed (see _directive), which stops an injected header from adding a
    # client. Concatenated IIS files still honor each new #Fields line.
    PARSERS = [('json', 'p_json'), ('combined', 'p_combined'),
               ('common', 'p_common'), ('vhost-combined', 'p_vhost'),
               ('alb', 'p_alb'), ('envoy', 'p_envoy'), ('haproxy', 'p_haproxy'),
               ('w3c', 'p_w3c')]
    EXPLICIT = {'json': 'p_json', 'w3c': 'p_w3c', 'combined': 'p_combined',
                'combined-xff': 'p_combined_xff', 'common': 'p_common',
                'vhost-combined': 'p_vhost', 'alb': 'p_alb',
                'envoy': 'p_envoy', 'haproxy': 'p_haproxy'}

    def _auto(self, line):
        order = self.PARSERS
        if self.last_parser is not None:
            order = [self.last_parser] + [p for p in order if p != self.last_parser]
        for entry in order:
            d = getattr(self, entry[1])(line)
            if d is not None:
                self.last_parser = entry
                return entry[0], d
        return None

    def _match_format(self, line):
        fmt = self.args.format
        if fmt == 'auto':
            return self._auto(line)
        d = getattr(self, self.EXPLICIT[fmt])(line)
        return (fmt, d) if d is not None else None

    def _parse_known(self, line):
        # A handful of syslog wrappers at most. Looping beats recursing, so a
        # line of stacked prefixes cannot blow the stack.
        for _ in range(4):
            res = self._match_format(line)
            if res is not None:
                return res
            chain, body = peel_quoted_chain(line)
            if chain:
                res = self._match_format(body)
                if res is not None:
                    return attach_chain(res, chain)
            chain, body = fold_comma_list(line)
            if chain:
                res = self._match_format(body)
                if res is not None:
                    return attach_chain(res, chain)
            if self.args.format == 'json':
                return None
            rest = strip_prefix(line)
            if not rest or rest == line:
                return None
            line = rest
        return None

    def parse_line(self, line):
        line = unwrap_docker(line)
        if line[:1] == '#':
            self._directive(line)
            return ('directive', None)
        if self.custom_regex is not None:
            m = self.custom_regex.match(line)
            if not m:
                rest = strip_prefix(line)
                m = self.custom_regex.match(rest) if rest else None
            if m:
                self.saw_non_w3c = True
                return ('regex', m.groupdict())
            return None
        result = self._parse_known(line)
        if result and result[0] not in ('directive', 'w3c'):
            self.saw_non_w3c = True
        return result

    # ---- aggregation --------------------------------------------------
    def handle(self, f):
        ts = f.get('time') or ''
        bucket = status_bucket(f.get('status'))
        self.status_totals[bucket] += 1

        seen = {}
        conn_ip = None
        raw_ip = f.get('ip')
        if raw_ip is not None:
            conn_ip = parse_ip(raw_ip)
            if conn_ip:
                self.saw_ip = True
                seen[conn_ip] = seen.get(conn_ip, 0) | 1
            elif raw_ip.strip() not in ('', '-', 'unknown'):
                self.bad_ip_values += 1
        raw_xff = f.get('xff')
        if raw_xff:
            for pos, token in enumerate(raw_xff.split(','), start=1):
                token = clean_xff_token(token)
                ip = parse_ip(token)
                if ip:
                    if ip != conn_ip:
                        self.saw_chain = True
                    bit = 2 if pos == 1 else (4 if pos == 2 else 8)
                    seen[ip] = seen.get(ip, 0) | bit
                elif token.strip() not in ('', '-', 'unknown'):
                    self.bad_ip_values += 1
        ips = self.ips
        for ip, mask in seen.items():
            rec = ips.get(ip)
            if rec is None:
                rec = ips[ip] = [0, ts, ts, 0, 0, 0, 0, 0, 0]
            rec[0] += 1
            rec[2] = ts
            rec[3 + bucket] += 1
            rec[8] |= mask

        hosts = {}
        self._add_host(hosts, f.get('host'), 'host_header')
        referer = f.get('referer')
        if referer is not None and referer.strip() not in SKIP_REFERERS:
            ref_host, bad = referer_host(referer.strip())
            if bad:
                self.bad_host_values += 1
            self._add_host(hosts, ref_host, 'referer')
        uri_field = f.get('uri')
        if uri_field:
            self._add_host(hosts, request_hostname(uri_field), 'request_target')
        request = f.get('request')
        if request:
            parts = request.split(' ')
            if len(parts) >= 2:
                method, target = parts[0].upper(), parts[1]
                if method == 'CONNECT':
                    self._add_host(hosts, target.rsplit('@', 1)[-1],
                                   'request_target')
                else:
                    self._add_host(hosts, request_hostname(target),
                                   'request_target')
        self._note_email(f.get('host'), 'host')
        self._note_email(referer, 'referer')
        self._note_email(uri_field, 'uri')
        self._note_email(request, 'request')
        self._note_email(f.get('ua'), 'user_agent')
        for host, labels in hosts.items():
            rec = self.hosts.get(host)
            if rec is None:
                rec = self.hosts[host] = [0, set()]
            rec[0] += 1
            rec[1].update(labels)

        if 'ua' in f and f['ua'] is not None:
            ua = f['ua']
            if ua.strip() in ('', '-'):
                self.empty_ua_lines += 1
            else:
                rec = self.uas.get(ua)
                if rec is None:
                    self.uas[ua] = [1, ts, ts]
                else:
                    rec[0] += 1
                    rec[2] = ts

    def _note_email(self, text, field):
        if contains_email(text):
            self.email_hits[field] = self.email_hits.get(field, 0) + 1

    def _add_host(self, hosts, raw, label):
        if raw is None:
            return
        result = norm_host(raw)
        if result is None:
            if raw.strip():
                self.bad_host_values += 1
            return
        kind, value = result
        if kind == 'ip':
            self.ip_literal_hosts += 1
            return
        hosts.setdefault(value, set()).add(label)

    def _note_line_secrets(self, line):
        """Count secrets on the raw line. Query strings are not indicators, so
        this is the only place an email or token in one is visible, and only
        as a count."""
        if contains_email(line):
            self.email_hits['line'] = self.email_hits.get('line', 0) + 1
        if SENSITIVE_RE.search(line):
            self.sensitive_lines += 1

    def feed(self, line):
        self.lines_read += 1
        line = line.rstrip('\r\n')
        if not line.strip():
            self.lines_blank += 1
            return
        if len(line) > MAX_LINE:
            self.lines_malformed += 1
            if len(self.malformed_samples) < MAX_SAMPLES:
                self.malformed_samples.append(
                    '[line longer than %d characters, contents omitted]' % MAX_LINE)
            return
        self._note_line_secrets(line)
        result = self.parse_line(line)
        if result is None:
            self.lines_malformed += 1
            if len(self.malformed_samples) < MAX_SAMPLES:
                self.malformed_samples.append(redact_sample(line))
            return
        name, fields = result
        if name == 'directive':
            self.lines_directive += 1
            return
        self.lines_parsed += 1
        self.formats[name] = self.formats.get(name, 0) + 1
        self.handle(fields)

    # ---- classification ----------------------------------------------
    def is_own(self, host):
        if not self.own:
            return 'unknown'
        for d in self.own:
            if host == d or host.endswith('.' + d):
                return 'yes'
        return 'no'

    def cdn_edge(self, addr):
        if not self.cdn_nets:
            return 'unknown'
        for net in self.cdn_nets:
            if net.version == addr.version and addr in net:
                return 'yes'
        return 'no'


def load_ranges(paths):
    nets = []
    for path in paths:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for raw in fh:
                s = raw.split('#', 1)[0].strip()
                if not s:
                    continue
                try:
                    nets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    raise ValueError('bad range in %s: %s' % (path, s[:80]))
    return nets


def parse_map(text):
    """Parse --map field=key[.nested][+key2],... into {field: [paths]}."""
    overrides = {}
    for pair in (text or '').split(','):
        pair = pair.strip()
        if not pair:
            continue
        if '=' not in pair:
            raise ValueError('--map entries look like field=key, got: ' + pair)
        field, path = pair.split('=', 1)
        field = field.strip()
        if field not in JSON_FIELDS:
            raise ValueError('unknown field %r in --map; fields are: %s'
                             % (field, ', '.join(JSON_FIELDS)))
        paths = [x.strip() for x in path.split('+') if x.strip()]
        if not paths:
            raise ValueError('--map %s has no key' % field)
        overrides[field] = paths
    return overrides


    return False


def compile_user_regex(pattern):
    """Compile a --regex, or return (None, error).

    The built-in patterns are fixed. This is the one pattern a caller supplies,
    so a nested quantifier is refused before it can hang on a long line.
    """
    if not pattern:
        return None, None
    if regex_backtracks(pattern):
        return None, ('--regex nests a quantifier inside another, so a long '
                      'line can make it hang. Keep each group to one repeat, '
                      'for example [^"]* rather than (.*)*.')
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return None, 'bad --regex: %s' % exc
    if 'ip' not in compiled.groupindex and 'xff' not in compiled.groupindex:
        return None, '--regex needs a named group "ip" or "xff"'
    return compiled, None


def build_parser():
    p = argparse.ArgumentParser(
        prog='extract_indicators.py',
        description='Extract unique IPs, hostnames and user agents from web '
                    'server logs. Writes JSON Lines files and summary.json to '
                    '--out. Never writes paths or query strings.',
        epilog='Examples:\n'
               '  python3 scripts/extract_indicators.py access.log.gz --out work\n'
               '  python3 scripts/extract_indicators.py a.log b.log.gz --out work '
               '--own-hosts example.com --cdn-ranges cdn.txt\n'
               '  python3 scripts/extract_indicators.py app.log --out work '
               '--format combined-xff\n'
               '  python3 scripts/extract_indicators.py app.log --out work '
               '--map ip=client.addr,ua=client.agent\n'
               '\n'
               'Formats: auto (default, decided per line), json, combined, common, '
               'vhost-combined (Apache %v:%p prefix), combined-xff (combined plus '
               'one trailing quoted forwarded-chain field), w3c (IIS and '
               'CloudFront, driven by the #Fields line), alb (AWS Application '
               'Load Balancer), envoy (default format; it has no peer address), '
               'haproxy (HTTP log). A syslog or RFC 5424 prefix is stripped '
               'automatically, and a Docker json-file wrapper is unwrapped.\n'
               '--regex takes a Python regex with named groups ip, xff, ua, '
               'referer, host, status, time, request, uri, method (only ip is required).\n'
               '--map overrides JSON keys, as field=key[.nested],... for '
               'fields ' + ', '.join(JSON_FIELDS) + '. Join several keys for one '
               'field with +, for example xff=cf.ip+x.fwd.\n'
               '--cdn-ranges takes a text file of CIDR ranges, one per line. '
               'Fetch the CDN\'s published ranges yourself; none are built in.\n'
               'first_seen and last_seen are the raw log timestamps of the '
               'first and last line read, in reading order.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('logs', nargs='+', help='log files (plain or .gz), or - for stdin')
    p.add_argument('--out', required=True, help='output directory (created if missing)')
    p.add_argument('--format', default='auto',
                   choices=FORMATS)
    p.add_argument('--regex', help='custom line regex with named groups. '
                   'Must not nest a quantifier inside another; that hangs '
                   'on a long line')
    p.add_argument('--map', help='JSON key overrides, field=key,...')
    p.add_argument('--own-hosts', help='comma separated domains you own; subdomains match')
    p.add_argument('--cdn-ranges', action='append', default=[],
                   help='file of CDN CIDR ranges, repeatable')
    p.add_argument('--dominant-share', type=float, default=0.8,
                   help='flag IPs on at least this share of parsed lines (default 0.8)')
    p.add_argument('--min-parsed', type=float, default=0.5,
                   help='exit 4 if less than this share of lines parse (default 0.5)')
    p.add_argument('--max-lines', type=int, help='stop after this many lines (testing)')
    p.add_argument('--no-decode', action='store_true',
                   help='keep W3C user agents as written (IIS + and CloudFront %%20)')
    p.add_argument('--verbose', action='store_true', help='progress on stderr')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    custom_regex, err = compile_user_regex(args.regex)
    if err:
        print('error: %s' % err, file=sys.stderr)
        return EXIT_USAGE
    try:
        overrides = parse_map(args.map)
    except ValueError as exc:
        print('error: %s' % exc, file=sys.stderr)
        return EXIT_USAGE
    try:
        cdn_nets = load_ranges(args.cdn_ranges)
    except (OSError, ValueError) as exc:
        print('error: cannot read --cdn-ranges: %s' % exc, file=sys.stderr)
        return EXIT_USAGE
    if not 0 < args.dominant_share <= 1 or not 0 <= args.min_parsed <= 1:
        print('error: --dominant-share and --min-parsed must be between 0 and 1',
              file=sys.stderr)
        return EXIT_USAGE

    try:
        os.makedirs(args.out, exist_ok=True)
    except OSError as exc:
        print('error: cannot create %s: %s' % (args.out, exc), file=sys.stderr)
        return EXIT_IO

    col = Collector(args, overrides, custom_regex, cdn_nets)
    limit = args.max_lines
    for path in args.logs:
        try:
            stream = open_text(path)
        except OSError as exc:
            print('error: cannot read %s: %s' % (path, exc), file=sys.stderr)
            return EXIT_IO
        col.start_file()
        try:
            with stream:
                for line in iter_lines(stream, MAX_LINE):
                    col.feed(line)
                    if args.verbose and col.lines_read % 1000000 == 0:
                        print('read %d lines' % col.lines_read, file=sys.stderr)
                    if limit and col.lines_read >= limit:
                        break
        except (OSError, EOFError) as exc:
            print('error: failed while reading %s: %s' % (path, exc),
                  file=sys.stderr)
            return EXIT_IO
        if limit and col.lines_read >= limit:
            break

    parsed = col.lines_parsed
    considered = col.lines_read - col.lines_blank - col.lines_directive
    ratio = (parsed / considered) if considered > 0 else 0.0

    # ---- write outputs ---------------------------------------------------
    counts_ip = {'public': 0, 'non_public': 0, 'cdn_edge': 0, 'dominant': 0,
                 'public_not_cdn_not_dominant': 0}
    dominant = []
    ip_rows = []
    cgnat_n = 0
    for ip, rec in col.ips.items():
        addr = ipaddress.ip_address(ip)
        public = addr.is_global
        if addr.version == 4 and addr in CGNAT:
            cgnat_n += 1
        share = rec[0] / parsed if parsed else 0.0
        edge = col.cdn_edge(addr)
        is_dom = share >= args.dominant_share
        counts_ip['public' if public else 'non_public'] += 1
        if edge == 'yes':
            counts_ip['cdn_edge'] += 1
        if is_dom:
            counts_ip['dominant'] += 1
            dominant.append(ip)
        if public and edge != 'yes' and not is_dom:
            counts_ip['public_not_cdn_not_dominant'] += 1
        ip_rows.append({
            'ip': ip, 'count': rec[0], 'share': round(share, 6),
            'first_seen': rec[1], 'last_seen': rec[2],
            'status': {'2xx': rec[3], '3xx': rec[4], '4xx': rec[5],
                       '5xx': rec[6], 'other': rec[7]},
            'sources': sorted(n for n, b in LABEL_BITS.items() if rec[8] & b),
            'public': public,
            'cdn_edge': edge, 'dominant': is_dom,
        })
    ip_rows.sort(key=lambda r: (-r['count'], r['ip']))

    host_rows = []
    own_counts = {'own': 0, 'not_own': 0, 'unknown': 0}
    for host, rec in col.hosts.items():
        own = col.is_own(host)
        own_counts[{'yes': 'own', 'no': 'not_own', 'unknown': 'unknown'}[own]] += 1
        host_rows.append({'host': host, 'count': rec[0],
                          'sources': sorted(rec[1]), 'own': own})
    host_rows.sort(key=lambda r: (-r['count'], r['host']))

    ua_rows = []
    for ua, rec in col.uas.items():
        row = {'user_agent': ua, 'count': rec[0], 'first_seen': rec[1],
               'last_seen': rec[2]}
        # The string stays verbatim so it can be inspected. The flag says a
        # credential assignment must not be sent to a lookup. An email does not
        # set the flag.
        if text_is_sensitive(ua):
            row['contains_sensitive'] = True
        ua_rows.append(row)
    ua_rows.sort(key=lambda r: (-r['count'], r['user_agent']))

    def dump(name, rows):
        with open(os.path.join(args.out, name), 'w', encoding='utf-8') as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')

    dump('ips.jsonl', ip_rows)
    dump('hostnames.jsonl', host_rows)
    dump('user_agents.jsonl', ua_rows)

    notes = []
    if col.saw_ip and not col.saw_chain:
        notes.append('No forwarded-chain field was found. Every address is the '
                     'connecting address. Behind a proxy or CDN that address is '
                     'the infrastructure, not the client.')
    if col.saw_chain and not col.saw_ip:
        notes.append('This format has no connecting address. Every address came '
                     'from a forwarded-for style field, which the sender '
                     'controls, so treat them as claims.')
    if col.saw_chain and col.saw_ip:
        notes.append('Shares are of parsed lines. One line can contribute to '
                     'both the connecting address and a forwarded address, so '
                     'shares can overlap.')
    if col.email_hits:
        notes.append('Email-shaped text was present. Counts are in '
                     'email_shaped_values. `line` counts raw lines, including '
                     'query strings that were not extracted. Other keys are '
                     'parsed fields. Addresses were not recorded. An email in a '
                     'user agent does not by itself block a lookup; say that it '
                     'was present.')
    if col.sensitive_lines:
        notes.append('%d lines contained a password, token, or key assignment. '
                     'The values were not extracted. Do not go looking for them. '
                     'A user agent with contains_sensitive must not be sent to a '
                     'lookup.'
                     % col.sensitive_lines)
    if parsed and not ip_rows and col.bad_ip_values * 2 >= parsed:
        notes.append('The lines parsed, but the address field was not an IP on '
                     'most of them. Nothing was invented. If the field is an '
                     'anonymized token, there is no address to look up.')
    if cgnat_n:
        notes.append('%d addresses are carrier-grade NAT (100.64.0.0/10). They '
                     'are marked non-public because they are not globally '
                     'routable.' % cgnat_n)
    if not cdn_nets:
        notes.append('cdn_edge is "unknown" because no --cdn-ranges file was given.')
    if not col.own:
        notes.append('own is "unknown" because --own-hosts was not given.')
    if col.unmapped_tail_lines:
        notes.append('%d lines have an extra trailing field that was not used. If '
                     'it is a forwarded-chain field, rerun with --format '
                     'combined-xff; otherwise use --regex.' % col.unmapped_tail_lines)
    if col.lines_malformed:
        notes.append('%d lines did not parse. See malformed_samples.'
                     % col.lines_malformed)

    summary = {
        'inputs': args.logs,
        'lines_read': col.lines_read,
        'lines_blank': col.lines_blank,
        'lines_parsed': parsed,
        'lines_malformed': col.lines_malformed,
        'parsed_ratio': round(ratio, 4),
        'formats': col.formats,
        'lines_directive': col.lines_directive,
        'json_keys_used': {f: sorted(v) for f, v in col.json_used.items() if v},
        'unmapped_trailing_field_lines': col.unmapped_tail_lines,
        'unique': {'ips': len(ip_rows), 'hostnames': len(host_rows),
                   'user_agents': len(ua_rows)},
        'ips': counts_ip,
        'hostnames': own_counts,
        'dominant_ips': dominant[:20],
        'user_agent_empty_lines': col.empty_ua_lines,
        'status_totals': {'2xx': col.status_totals[0], '3xx': col.status_totals[1],
                          '4xx': col.status_totals[2], '5xx': col.status_totals[3],
                          'other': col.status_totals[4]},
        'malformed_values': {'ip': col.bad_ip_values,
                             'hostname': col.bad_host_values},
        'email_shaped_values': col.email_hits,
        'sensitive_assignments': col.sensitive_lines,
        'ip_literal_hosts_skipped': col.ip_literal_hosts,
        'malformed_samples': col.malformed_samples,
        'trailing_field_samples': col.tail_samples,
        'notes': notes,
    }
    with open(os.path.join(args.out, 'summary.json'), 'w', encoding='utf-8') as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
        fh.write('\n')
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if considered <= 0 or ratio < args.min_parsed:
        print('error: only %d of %d lines parsed (%.0f%%). The format did not '
              'resolve. Show malformed_samples to the user, then rerun with '
              '--format, --regex or --map.'
              % (parsed, max(considered, 0), ratio * 100), file=sys.stderr)
        return EXIT_FORMAT
    return 0


if __name__ == '__main__':
    sys.exit(main())
