# Getting started

## Install

From a checkout of the distribution:

```sh
perl Makefile.PL
make
make test
make install
```

This installs the `Log::Munger` modules, the `log_munger` CLI, and the bundled rule
files (into the distribution's share directory).

### Dependencies

Pulled in automatically by `Makefile.PL`:

`YAML::XS`, `JSON`, `File::ShareDir`, `File::Slurp`, `Template`, `Hash::Merge`,
`App::Cmd`, `Algorithm::Dependency::Source::HoA`, `Algorithm::Dependency::Ordered`.

Optional: [`IP::Geolocation::MMDB`](https://metacpan.org/pod/IP::Geolocation::MMDB), needed
only for [GeoIP enrichment](geoip.md) and loaded only when you actually pass a database
path. If you never use geoip you never need it installed.

## The log-record model

Log-Munger works on a **log record**: a hash of named fields. This mirrors what you get
out of structured syslog daemons (journald JSON, syslog-ng's JSON template, rsyslog
`mmjsonparse`, etc.), for example:

```json
{ "PROGRAM": "sshd", "HOST": "mail01", "MESSAGE": "Failed password for root from 203.0.113.7 port 44444 ssh2" }
```

- Rule :: Runs its patterns against one field of the record, `MESSAGE` unless told
  otherwise.
- Gate :: Tests some *other* field, commonly `PROGRAM`, so a rule only fires for the right
  kind of line. This is what lets you load `sshd`, `postfix`, and `netfilter` at once
  without them stepping on each other.
- Bare string :: Handed in instead of a hash, it is treated as `{ MESSAGE => $string }`.
  That is what `--raw` does on the CLI, and it is why the gateless `http_access_logs` rule
  works on raw access-log lines fed straight in.

## Your first munge

List what is available, then run a line through a rule file:

```sh
$ log_munger list
auditd
base
cron
...
sshd
...

$ log_munger munge --rules sshd \
    --string '{"PROGRAM":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 44444 ssh2"}'
---
ssh_method: password
ssh_src_ip: 203.0.113.7
ssh_src_port: 44444
ssh_user: root
```

If nothing matches, `munge` prints `--- ~` (a YAML null).

> **`--raw` and gated rules.** The `sshd` rule *gates* on `PROGRAM` being `sshd`, so it
> only fires when that field is present. `--raw` sets only `MESSAGE`, so
> `--rules sshd --raw` will **not** match — you must supply a record with the gate field
> (as JSON above). `--raw` is for *gateless* rules such as `http_access_logs`, which match
> a whole line regardless of other fields:
>
> ```sh
> log_munger munge --rules http_access_logs --raw \
>     --string '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326'
> ```

### Seeing why something matched (or didn't)

`explain` tells you which rule and which pattern index fired:

```sh
$ log_munger explain --rules sshd \
    --string '{"PROGRAM":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 44444 ssh2"}'
matched: yes
rule: sshd
pattern: 1
field: MESSAGE
fields:
---
ssh_method: password
ssh_src_ip: 203.0.113.7
ssh_src_port: 44444
ssh_user: root
```

The `pattern:` index is which entry in the rule's `patterns:` list fired (0-based).

### Processing a stream

`enrich` reads one record per line from stdin and writes enriched NDJSON:

```sh
# NDJSON in, NDJSON out — extracted fields nested under "enriched".
# Each record carries the gate fields (PROGRAM, ...) so gated rules can fire.
cat events.ndjson | log_munger enrich --rules sshd --rules postfix

# raw whole-line access logs in (each treated as MESSAGE), fields merged flat.
# http_access_logs is gateless, so --raw is enough here.
cat /var/log/apache2/access.log | log_munger enrich --rules http_access_logs --raw --flat
```

See the [CLI reference](cli.md) for every subcommand and option.

## Using it from Perl

```perl
use Log::Munger;

my $munger = Log::Munger->new( rules => [ 'sshd', 'postfix' ] );

my $fields = $munger->process_item( item => {
    PROGRAM => 'sshd',
    MESSAGE => 'Failed password for root from 203.0.113.7 port 44444 ssh2',
} );

if ( defined $fields ) {
    # $fields is a hashref of the winning rule's captures
}
```

See the [Perl API](api.md) for the full interface.

## Next steps

- Understand the YAML: [rule-file format](rule-files.md).
- Build your own: [writing a rule file](writing-rules.md).
- Browse the building blocks: [primitive library](primitives.md).
