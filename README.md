# Log-Munger

Extracts structured fields from log lines, akin to [grok](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html)
for Logstash — but as a standalone Perl distribution and a `log_munger` CLI, with
no Elasticsearch/Logstash stack required.

Feed it a decoded log record (a hash) or a raw log line, and it runs the record
through a set of YAML **rule files**. The first rule that matches returns the
named captures from its regexp — optionally broken down further (`decompose`),
type-coerced (`convert`), and enriched with GeoIP (`geoip`).

```
$ echo '{"PROGRAM":"sshd","MESSAGE":"Accepted publickey for kitsune from 192.0.2.5 port 54321 ssh2: RSA SHA256:AbCd"}' \
    | log_munger munge --rules sshd
---
ssh_key_fingerprint: SHA256:AbCd
ssh_key_type: RSA
ssh_method: publickey
ssh_src_ip: 192.0.2.5
ssh_src_port: 54321
ssh_user: kitsune
```

## Why

Grok patterns are great, but they live inside Logstash. Log-Munger takes the same
idea — a library of named regexp primitives (`%{IP}`, `%{WORD}`, …) composed into
larger patterns — and makes it:

- **Standalone.** A Perl module (`Log::Munger`) and a CLI (`log_munger`); pipe NDJSON
  or raw lines through it.
- **Templated, not string-spliced.** Primitives are composed with
  [Template Toolkit](https://metacpan.org/pod/Template) (`[% IP %]`) and resolved in
  dependency order, so a pattern can build on another pattern.
- **Testable.** Every primitive and every rule carries its own positive/negative
  `tests`, checkable with `log_munger test_all`.
- **Enriching, not just matching.** After a match it can split key=value blobs,
  re-match sub-fields, coerce numbers, and do GeoIP lookups.
- **Grok-compatible.** `log_munger degrok` / `grok2rules` convert existing grok
  patterns (`%{TOKEN}` / `%{TOKEN:name}`) into Log-Munger's form.

## Install

From a checkout:

```sh
perl Makefile.PL
make
make test
make install
```

Core dependencies (pulled in by `Makefile.PL`): `YAML::XS`, `JSON`, `File::ShareDir`,
`File::Slurp`, `Template`, `Hash::Merge`, `App::Cmd`, `Algorithm::Dependency`.
GeoIP enrichment additionally needs [`IP::Geolocation::MMDB`](https://metacpan.org/pod/IP::Geolocation::MMDB)
(an optional/recommended dependency, only loaded when you actually pass a database).

## Quick start

### As a CLI

```sh
# what rule files are available?
log_munger list

# run one item through a rule file and dump the fields
log_munger munge --rules sshd \
    --string '{"PROGRAM":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 44444 ssh2"}'

# a gateless rule (like http_access_logs) works on a raw line with --raw
log_munger munge --rules http_access_logs --raw \
    --string '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326'

# see WHICH rule/pattern fired
log_munger explain --rules sshd --string '{"PROGRAM":"sshd","MESSAGE":"..."}'

# stream NDJSON in, enriched NDJSON out
cat events.ndjson | log_munger enrich --rules sshd --rules postfix > enriched.ndjson
```

### As a library

```perl
use Log::Munger;

my $munger = Log::Munger->new( rules => [ 'sshd', 'postfix' ] );

# a decoded record (e.g. from journald / syslog-ng JSON output)
my $fields = $munger->process_item( item => {
    PROGRAM => 'sshd',
    MESSAGE => 'Failed password for root from 203.0.113.7 port 44444 ssh2',
} );
# $fields = { ssh_method => 'password', ssh_user => 'root', ssh_src_ip => '203.0.113.7', ... }

# a bare string is matched as the MESSAGE field
my $access = $munger->process_item( item => $raw_apache_line );
```

## Bundled rule files

The distribution ships a primitive library plus ready-to-use rule files
(installed into the dist share dir):

| Rule file | Matches |
|-----------|---------|
| `base` | The primitive library (`IP`, `WORD`, `TIMESTAMP_ISO8601`, …) — no rules of its own; included by the others |
| `sshd` | OpenSSH auth/connection events |
| `postfix` | Postfix mail log (smtpd, qmgr, delivery, …) |
| `http_access_logs` | Apache/nginx Common + Combined access logs |
| `http_error_logs` | Apache/nginx error logs |
| `netfilter` | iptables/nftables/UFW kernel firewall logs |
| `auditd` | Linux audit daemon records |
| `pam` / `su` / `sudo` | PAM, `su`, and `sudo` authentication |
| `cron` | cron/crond job execution |
| `named` / `unbound` / `dnsmasq` | DNS server logs |
| `dovecot` | Dovecot IMAP/POP3 |
| `squid` | Squid proxy access logs |

## Documentation

Full documentation lives in [`docs/`](docs/):

- [Getting started](docs/getting-started.md) — install, first munge, the log-record model
- [CLI reference](docs/cli.md) — every `log_munger` subcommand and option
- [Rule-file format](docs/rule-files.md) — the YAML schema (`vars`, `rules`, `gate`, `decompose`, `convert`, `geoip`, `tests`)
- [Writing a rule file](docs/writing-rules.md) — a step-by-step tutorial
- [Primitive library](docs/primitives.md) — the named patterns in `base.yaml`
- [Perl API](docs/api.md) — `Log::Munger` and the supporting modules
- [Architecture](docs/architecture.md) — how loading, templating, and matching fit together
- [GeoIP enrichment](docs/geoip.md) — enriching captured addresses
- [Grok migration](docs/grok.md) — converting existing grok patterns

## Authors and license

Copyright (c) 2026 Zane C. Bowers-Hadley `<vvelox at vvelox.net>`.

This is free software, licensed under the GNU General Public License, Version 3.
See [`LICENSE`](LICENSE).

Bugs and feature requests: [GitHub issues](https://github.com/LilithSec/Log-Munger)
or `bug-log-munger at rt.cpan.org`.
