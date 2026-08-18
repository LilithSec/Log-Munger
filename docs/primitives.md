# Primitive library (`base.yaml`)

`base` is the primitive library: a rule file that defines named regexps (`vars` and
`vars_templated`) and their tests, but no `rules:`. Consumer rule files pull it in with
`includes: [base]` and reference its primitives as `[% NAME %]`.

The names and semantics deliberately track the well-known
[Logstash grok default patterns](https://github.com/logstash-plugins/logstash-patterns-core/blob/main/patterns/legacy/grok-patterns),
so patterns ported from grok mostly work as-is.

> To see any primitive's fully-resolved regexp:
> `log_munger dump_rule_file -f base --var <NAME>`.

## `vars` — plain primitives

These are literal regexps (no templating).

| Name | Matches |
|------|---------|
| `IPv4` | An IPv4 address. |
| `IPv6` | An IPv6 address (including embedded-IPv4 and `::` forms). |
| `HOSTNAME` | A DNS hostname (RFC-ish, up to 255 chars). |
| `INT` | `[0-9]+` (unsigned integer). |
| `FLOAT` | `[0-9]+[.][0-9]+`. |
| `INTorFLOAT` | An integer or a float. |
| `BASE10NUM` | A signed base-10 number (int or decimal). |
| `BASE16NUM` | A hex number, optional `0x`/sign. |
| `BASE16FLOAT` | A hex float. |
| `POSINT` | A positive integer (`[1-9][0-9]*`). |
| `NONNEGINT` | A non-negative integer. |
| `WORD` | `\b\w+\b`. |
| `NOTSPACE` | `\S+`. |
| `SPACE` | `\s*`. |
| `DATA` | `(.*)?` (greedy catch-all — unlike grok's lazy `.*?`). |
| `GREEDYDATA` | `.*`. |
| `GREEDYDATA_NO_COLON` | `[^:]*`. |
| `GREEDYDATA_NO_SEMICOLON` | `[^;]*`. |
| `GREEDYDATA_NO_BRACKET` | `[^<>]*`. |
| `STATUS_WORD` | `[\w-]*` (a word possibly containing `-`). |
| `USERNAME` | `[a-zA-Z0-9._-]+`. |
| `EMAILLOCALPART` | The local part of an email address. |
| `EMAILADDRESS` | A full email address. |
| `QUOTEDSTRING` | A `"`, `'`, or `` ` `` quoted string (escape-aware). |
| `UUID` | A canonical UUID. |
| `URN` | A `urn:` URN. |
| `CISCOMAC` | Cisco-style MAC (`aabb.ccdd.eeff`). |
| `WINDOWSMAC` | Windows-style MAC (`aa-bb-cc-dd-ee-ff`). |
| `COMMONMAC` | Colon MAC (`aa:bb:cc:dd:ee:ff`). |
| `TTY` | A `/dev/tty*` / `/dev/pts*` device. |
| `WINPATH` | A Windows path. |
| `UNIXPATH` | A Unix path. |
| `URIPROTO` | A URI scheme (`http`, `smtp`, …). |
| `URIPATH` | A URI path. |
| `URIPARAM` | A URI query string. |
| `MONTH` | Month name (many languages/abbreviations). |
| `MONTHNUM` | Month number `1`–`12` (optional leading zero). |
| `MONTHNUM2` | Zero-padded month `01`–`12`. |
| `MONTHDAY` | Day of month `1`–`31`. |
| `DAY` | Weekday name (`Mon`, `Monday`, …). |
| `YEAR` | 2- or 4-digit year. |
| `HOUR` | Hour `0`–`23`. |
| `MINUTE` | Minute `00`–`59`. |
| `SECOND` | Second, with optional fractional part. |
| `LOGLEVEL` | A syslog/log level word (`ERROR`, `warn`, `INFO`, …). |
| `TZ` | A short timezone (`UTC`, `CST`, `EDT`, …). |
| `PROG` | A program name token (printable, no space). |

## `vars_templated` — composed primitives

These are built from the plain primitives (and each other) via `[% NAME %]` references and
resolved in dependency order.

| Name | Built from / matches |
|------|----------------------|
| `NUMBER` | Alias of `INTorFLOAT`. |
| `USER` | Alias of `USERNAME`. |
| `MAC` | `CISCOMAC` \| `WINDOWSMAC` \| `COMMONMAC`. |
| `IP` | `IPv6` \| `IPv4`. |
| `HOSTNAMEorIP` | `IPv6` \| `IPv4` \| `HOSTNAME`. |
| `HOSTandPORT` | `HOSTNAMEorIP:POSINT`. |
| `HOSTmaybePORT` | `HOSTNAMEorIP` with an optional `:port`. |
| `PATH` | `UNIXPATH` \| `WINPATH`. |
| `URIPATHPARAM` | `URIPATH` with an optional `URIPARAM`. |
| `URI` | A full URI (scheme, optional userinfo, host, path/params). |
| `TIME` | `HOUR:MINUTE:SECOND`. |
| `DATE_US` | `MONTHNUM/MONTHDAY/YEAR` (separator `/` or `-`). |
| `DATE_EU` | `MONTHDAY.MONTHNUM.YEAR` (separator `.`, `/`, or `-`). |
| `DATE` | `DATE_US` \| `DATE_EU`. |
| `ISO8601_TIMEZONE` | `Z` or `±HH:MM` (colon optional, so `±HHMM` too). |
| `ISO8601_SECOND` | `SECOND` or `60`. |
| `TIMESTAMP_ISO8601` | A full ISO-8601 timestamp. |
| `SYSLOGTIMESTAMP` | `MONTH MONTHDAY TIME` (classic syslog). |
| `HTTPDATE` | The Apache access-log timestamp. |
| `DATESTAMP` | `DATE` and `TIME` joined by `-` or a space. |
| `DATESTAMP_RFC822` | RFC-822 style date-time. |
| `DATESTAMP_RFC2822` | RFC-2822 style date-time. |
| `DATESTAMP_OTHER` | `DAY MONTH MONTHDAY TIME TZ YEAR`. |
| `DATESTAMP_EVENTLOG` | Compact `YYYYMMDDHHMMSS`. |

Every primitive has positive and negative cases under `vars_tests` in `base.yaml`. Run
`log_munger test_all -v` to exercise them. A few edge cases are knowingly imperfect —
`HOUR`, for instance, will match the leading digit of `25` — and the vars with known
problems (`WINPATH`, `UNIXPATH`, `URIPARAM`) carry a TODO comment in the file saying what
they get wrong.

## Adding your own primitives

You do not have to edit `base.yaml`. Any consumer file can define its own `vars` and
`vars_templated`, which are merged with the includes with the current file taking
precedence. That is how `http_access_logs.yaml` adds `HTTPD_QS`, `HTTPD_USER`, and the
`HTTPD_COMMONLOG` / `HTTPD_COMBINEDLOG` line patterns on top of `base`.
