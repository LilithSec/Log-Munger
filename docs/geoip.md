# GeoIP enrichment

Log-Munger can enrich captured IP addresses with data from a
[MaxMind](https://www.maxmind.com/) `.mmdb` database (GeoLite2 / GeoIP2), using
[`IP::Geolocation::MMDB`](https://metacpan.org/pod/IP::Geolocation::MMDB).

This is an **opt-in, soft dependency**: `IP::Geolocation::MMDB` is only `require`d — and
the database only opened — when you actually pass a database path. If you never use geoip,
you don't need the module installed.

## Enabling it

**CLI** — pass `--geoip`/`-g` to `munge`, `explain`, or `enrich`:

```sh
log_munger enrich -r sshd -r netfilter -g /var/lib/GeoIP/GeoLite2-City.mmdb < events.ndjson
```

**Perl** — pass `geoip` to the constructor:

```perl
my $munger = Log::Munger->new(
    rules => ['sshd'],
    geoip => '/var/lib/GeoIP/GeoLite2-City.mmdb',
);
```

Opening the database fails loudly (dies) if the module is missing or the path is bad, so a
misconfiguration is caught at startup rather than silently ignored.

## Marking fields for lookup

A rule (or a file-level default) lists the captured field names to look up under `geoip:`.
The bundled files already do this for their obvious address fields — e.g. `sshd` on
`ssh_src_ip`, `netfilter` on `nf_SRC`, `http_access_logs` on `http_clientip`, `postfix` on
`postfix_client_ip` / `postfix_relay_ip`.

```yaml
# file-level default: every rule that captures this field gets a lookup
geoip:
  - ssh_src_ip
```

```yaml
# or per-rule
rules:
  - name: http_access
    geoip:
      - http_clientip
    ...
```

A rule-level `geoip:` replaces the file-level default for that rule.

## Where the result lands

For each flagged field that was captured and successfully looked up, the MaxMind record is
stored under `geoip` in the result, keyed by the source field:

```jsonc
{
  "ssh_src_ip": "203.0.113.7",
  "ssh_user": "root",
  "geoip": {
    "ssh_src_ip": { /* the IP::Geolocation::MMDB record: country, city, location, ... */ }
  }
}
```

The exact shape of each record is whatever `IP::Geolocation::MMDB->record_for_address`
returns for your database (City vs Country databases differ).

## Failure handling

Lookups are best-effort and never cost the match:

- Undef, empty, or not an address :: Silently skipped.
- Absent from the database :: Skipped.
- A lookup that throws :: Caught locally, so one bad value never aborts the rest of the
  enrichment.

If no flagged field resolves, no `geoip` key is added.

## Timing

GeoIP runs **after** `decompose` and **before** `convert` (see
[architecture](architecture.md#why-the-enrichment-order-is-fixed)), which buys two things:

- It can look up an address a `decompose` step produced, such as `nf_SRC` split out of the
  kernel firewall blob.
- It sees the address as a string, before any `convert` coercion, so putting a numeric
  field through `convert` never interferes with a lookup.
