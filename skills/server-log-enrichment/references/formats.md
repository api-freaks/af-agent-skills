# Log formats and where the client address lives

The most important question about any log is whether its address field is the
client or the infrastructure in front of the client. Answer it before you spend
anything. Most formats below are read automatically. Run
`python3 scripts/extract_indicators.py --help` for the flags.

How to tell, in any format: if one address is on nearly every line, or the
addresses fall inside a CDN's published ranges, or they are private, the field
holds infrastructure. Then look for a forwarded-for style field, or a platform
setting that restores the client address (below).

## Web servers

**nginx and Apache, common and combined.** Read automatically. The first field is
the connecting address. Behind a proxy or CDN that is the proxy.
- nginx can replace it with the real client using the realip module
  (`set_real_ip_from`, `real_ip_header`). `$realip_remote_addr` keeps the
  original connection address.
- Apache does the same with mod_remoteip. `%a` then records the replaced client
  address, and `%{c}a` the underlying connection address.
- Or add the forwarded header as a trailing quoted field, for example
  `"$http_x_forwarded_for"`, and read it with `--format combined-xff`.
- A first field that is already a comma-separated address list
  (`10.0.0.2, 10.0.0.1, 203.0.113.9 - - [time] ...`) is the forwarded chain.
  There is no separate connecting address. When one more address sits between
  that list and the ident field (`2a02:..., 10.225.192.17 10.2.2.121 - -`),
  the list is the chain and the extra address is the connecting client. A
  quoted list in front of a normal line (`"203.0.113.1, 198.51.100.2"
  203.0.113.9 - - ...`) is the chain, and the address after it is the
  connecting address. A token that is not an IP
  (`IP277299`, `localhost`, `unix:`) still parses: the line counts, and the
  token is not turned into an address. A host with no port in front of a
  quoted chain does not resolve; use `--regex`.

**Apache vhost_combined** (a `host:port` prefix from `%v:%p`): `--format
vhost-combined`, also found automatically. The host feeds the hostname list.

**IIS and other W3C extended logs.** Driven by the `#Fields:` line, space
separated. `c-ip` is the client address. IIS writes `+` for spaces and for
nonprintable characters, so user agents are decoded. There is no forwarded-for
field unless you added one, so behind a proxy the client address is not
recoverable from the log. A file with no `#Fields` line does not resolve; ask
for the header rather than guessing columns. A new `#Fields` line is honored
when the file is W3C throughout, including concatenated IIS logs. It is ignored
once any line has parsed as another format, so a header injected into nginx
cannot add a client.

**Caddy (JSON).** `request.remote_ip` is the directly connecting client.
`request.client_ip` is the parsed real client when `trusted_proxies` is
configured, and it is listed as the first forwarded address: that entry is the
proxy's parsed client, not only a raw header the sender wrote.
`request.headers.X-Forwarded-For` is also logged when sent. Headers are lists.
All three are read, and the proxy-aware one comes first.

**Traefik.** JSON keys: `ClientHost` (the remote IP), `ClientAddr` (usually
IP:port), `RequestHost`, `RequestMethod`, `RequestPath`, `DownstreamStatus`,
`StartUTC`. Request headers appear only if you configured
`accesslog.fields.headers`; if their key names differ, point at them with
`--map`. The default CLF output parses as combined. An empty referer written as
a bare `-` is still the referer, and the user agent after it is kept. Trailing
fields (request count, router, server URL, duration) are an unmapped tail, not
a forwarded chain, and are safe to ignore.

**Envoy default format.** It has no peer address at all. The only address is the
quoted `X-Forwarded-For`, which the sender controls, so treat addresses from it
as claims. The authority field gives the host. A leading `ACCESS ` tag, which
some collectors add, is ignored. To get the peer address, change
the access log format. `--format envoy`.

**HAProxy HTTP log.** `--format haproxy`. The client IP is the one that opened
the TCP connection, or the forwarded address when the PROXY protocol is accepted.
One extra token between the backend and the timers (often a host name) is
allowed. A client written as `-` is not an address. Captured request headers
appear in `{...}` blocks in the order you configured them, so the script does
not guess which is the user agent. If you capture it, use `--regex` with named
groups for your exact layout.

## Cloud and CDN logs

**AWS Application Load Balancer.** `--format alb`. The `client:port` field is the
requesting client, and when a proxy sits in front of the load balancer it holds
the proxy's address. The request is an absolute URL, so every row yields a
hostname. New fields are appended over time, so stop parsing after the last
documented one, which the script does.

**AWS CloudFront standard logs.** Tab-separated W3C with `#Version` and
`#Fields` header lines. `c-ip` is the viewer address, or the proxy's if the
viewer used one. There is an `x-forwarded-for` field, and `x-host-header` holds
the host the viewer asked for. Spaces and other characters in values are
percent-encoded, so user agents are decoded.

**Cloudflare Logpush (HTTP requests, JSON).** Fields include `ClientIP`,
`ClientRequestHost`, `ClientRequestUserAgent`, `ClientRequestReferer`,
`ClientRequestMethod`, `ClientRequestURI`, `EdgeResponseStatus`,
`EdgeStartTimestamp`, and also `ClientASN` and `ClientCountry`. `ClientIP` is
the client address as Cloudflare saw it, which is what an origin server's own
log usually lacks.

**Google Cloud HTTP load balancer (JSON).** `httpRequest.remoteIp`,
`httpRequest.userAgent`, `httpRequest.requestUrl`, `httpRequest.referer`,
`httpRequest.status`. Read automatically.

## Wrappers and anything else

- **Syslog prefix** (`Oct 20 10:00:00 host nginx: ...`, or with a `<priority>`),
  and an RFC 5424 header (`<pri>1 timestamp host app proc msgid - message`):
  stripped automatically. A Docker json-file wrapper (`log` plus `stream` of
  `stdout` or `stderr`) is unwrapped to the inner line. A Kubernetes or Fluent
  Bit wrapper that uses `message` instead of `log`, with the same `stream`, is
  unwrapped the same way. `log` wins when both are present.
- **Custom nginx or Apache formats.** Ask for the `log_format` or `LogFormat`
  line, then pass a regex with named groups `ip`, `xff`, `ua`, `referer`,
  `host`, `status`, `time`, `request`, `uri`, `method`. Only `ip` or `xff` is
  required. Example for `ip|user_agent|status` lines:
  `--regex '^(?P<ip>[^|]+)\|(?P<ua>[^|]+)\|(?P<status>\d+)$'`.
- **Other JSON.** Point at the keys with `--map ip=client.addr,ua=client.agent`.
  Nested keys use dots, and `xff=a+b` joins several keys into one forwarded
  field.
- **Application logs, stack traces, error logs.** Not what this skill is for.

If the script exits with code 4 the format did not resolve. Show the user the
sample lines from `summary.json` and ask, rather than guessing.
