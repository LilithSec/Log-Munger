# Grok migration

Log-Munger's pattern language is deliberately close to
[Logstash grok](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html),
so existing grok patterns port over with a mechanical rewrite. `Log::Munger::Degrok` (and
the `degrok` / `grok2rules` CLI commands) do that rewrite for you.

## The two syntaxes

| Grok | Log-Munger | Meaning |
|------|-----------|---------|
| `%{TOKEN}` | `[% TOKEN %]` | Reference the named pattern `TOKEN`. |
| `%{TOKEN:name}` | `(?<name>[% TOKEN %])` | Reference `TOKEN` and capture it as `name`. |

Log-Munger composes patterns with [Template Toolkit](https://metacpan.org/pod/Template)
(`[% ... %]`) and captures with Perl named groups (`(?<name>...)`). The primitive names
(`IP`, `WORD`, `TIMESTAMP_ISO8601`, …) match grok's, so once the delimiters are converted,
most patterns work as-is. See [primitives.md](primitives.md).

## Converting a single pattern or file

`degrok` rewrites the templating in place:

```sh
# a string
$ log_munger degrok -s 'client=%{IP:client_ip} user=%{USERNAME:user}'
client=(?<client_ip>[% IP %]) user=(?<user>[% USERNAME %])

# a whole file, line by line
$ log_munger degrok -f patterns.grok
```

Programmatically:

```perl
use Log::Munger::Degrok;
my $out = Log::Munger::Degrok->string( string => 'client=%{IP:client_ip}' );
```

## Converting a grok patterns file into a rules skeleton

A grok *patterns* file is lines of `NAME regexp` (with `%{...}` references). `grok2rules`
turns one into a Log-Munger rules-YAML skeleton: plain lines become `vars:` entries,
lines that reference other patterns become `vars_templated:` entries (after degrokking).

```sh
log_munger grok2rules -f /path/to/grok-patterns -i base > mypatterns.yaml
```

- `--includes`/`-i <name>` (repeatable) — rule files to treat as includes when resolving
  and overwriting names. Names already provided by an include are handled per the overwrite
  policy instead of being redefined.
- `--overwrite`/`-o <policy>` — what to do when a name is already defined by an include:
  `yes` (redefine), `no_silent` / `no_warn` (skip, quietly / with a warning), `no_die`.
  Default: `no_warn`.

The same skeleton generation is available from `degrok -f <file> -r` and from
`Log::Munger::Degrok->grok2rules(...)`.

## After conversion

`grok2rules` produces the `vars` / `vars_templated` scaffolding — it does **not** invent
`rules:`, gates, tests, or enrichment. To finish the job:

1. Add `includes: [base]` (or your own base) if the patterns rely on standard primitives.
2. Write the `rules:` section: gate on `PROGRAM` (or whatever field distinguishes the
   source), pick the target `field`, and list your line patterns. See
   [writing-rules.md](writing-rules.md).
3. Add `vars_tests` and rule `tests`, then run `log_munger test_all -v`. The test harness
   will flag any `%{...}` that wasn't converted, illegal capture names, and patterns that
   don't compile.

## Gotchas

- **Capture names.** Grok is liberal about capture names; Perl named groups must match
  `[A-Za-z_]\w*`. A `-` in a name (`%{IP:src-ip}`) becomes `(?<src-ip>...)`, which won't
  compile — rename it (`src_ip`). This is caught at load/test time.
- **No leftover `%{...}`.** Any `%{...}` that survives into a compiled pattern is a hard
  error, so an un-degrokked reference can't silently pass through.
- **Anchoring.** Grok patterns are often used unanchored; if you want whole-line matching
  (grok `^...$`), set `anchored: true` on the rule rather than baking `\A...\z` into every
  pattern.
