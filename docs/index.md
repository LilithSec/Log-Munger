# Log-Munger documentation

Log-Munger extracts structured fields from log records using YAML **rule files** —
grok-style pattern matching as a standalone Perl distribution and a `log_munger` CLI.

Start here:

1. **[Getting started](getting-started.md)** — install it, munge your first line, and
   understand the log-record model (fields, `MESSAGE`, gates).
2. **[CLI reference](cli.md)** — every `log_munger` subcommand: `munge`, `enrich`,
   `explain`, `list`, `degrok`, `test_all`, and the rest.
3. **[Rule-file format](rule-files.md)** — the complete YAML schema.
4. **[Writing a rule file](writing-rules.md)** — a worked tutorial from a raw log line
   to a tested rule file.
5. **[Primitive library](primitives.md)** — the named patterns provided by `base.yaml`.
6. **[Perl API](api.md)** — using `Log::Munger` from your own code, plus the internal
   modules.
7. **[Architecture](architecture.md)** — the load → template → compile → match pipeline.
8. **[GeoIP enrichment](geoip.md)** — enriching captured IP addresses.
9. **[Grok migration](grok.md)** — converting existing grok patterns.

## Core concepts at a glance

- **Rule file** — a YAML document. Either a *primitive library* (like `base`, which only
  defines reusable patterns) or a *consumer* (like `sshd`, which defines `rules:` that
  match log lines). See [rule-files.md](rule-files.md).
- **Primitive / var** — a named regexp (`IP`, `WORD`, `TIMESTAMP_ISO8601`). Referenced in
  larger patterns as `[% IP %]`. See [primitives.md](primitives.md).
- **Rule** — a gate + a target field + an ordered list of patterns. The first rule whose
  gates all pass and one of whose patterns matches wins, returning its named captures.
- **Enrichment** — after a match, captured fields can be `decompose`d (split further),
  `convert`ed (coerced to numbers), and `geoip`-looked up. These run in the order
  decompose → geoip → convert.
- **Log record** — a hash of fields. The pattern usually runs against `MESSAGE`; other
  fields (`PROGRAM`, `HOST`, …) are used by gates. A bare string is treated as
  `{ MESSAGE => $string }`.

## Rule-file search path

Rule files are resolved by name across, in precedence order:

1. `/etc/log_munger/rules/`
2. `/usr/local/etc/log_munger/rules/`
3. the distribution share directory (`File::ShareDir::dist_dir('Log-Munger')`)

An earlier match shadows a later one. A name with no `.yaml` also tries `name.yaml`; a
path starting with `/`, `./`, or `../` is used directly. `log_munger which_rule_file -f NAME`
shows what a name resolves to; `log_munger list` shows everything discoverable.
