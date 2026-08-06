# CLI reference

The `log_munger` command is an [App::Cmd](https://metacpan.org/pod/App::Cmd)
application. Run `log_munger commands` to list subcommands and
`log_munger help <command>` for a command's usage.

Global options accepted by every subcommand:

- `--help`, `-h` :: Usage screen.
- `--version`, `-v` :: Version.

Options common to the processing commands (`munge`, `explain`, `enrich`):

- `--rules`, `-r <name>` :: A rule file to load. Repeatable — give it once per rule file,
  as in `-r sshd -r postfix`. Resolved via the
  [search path](index.md#rule-file-search-path).
- `--raw` :: Treat each input item as a raw log line, matched as the `MESSAGE` field,
  instead of JSON/NDJSON.
- `--geoip`, `-g <path>` :: Path to a MaxMind `.mmdb` database for
  [GeoIP enrichment](geoip.md).

---

## Processing log data

### `munge` — run one item through the rules

> Run one log item through the rules and dump the extracted fields.

Reads a single item from `--string`/`-s`, or from stdin if not given. Prints the winning
rule's captured fields as YAML, or `--- ~` (YAML null) if nothing matched.

| Option | Meaning |
|--------|---------|
| `--rules`, `-r <name>` | Rule file to load (repeatable). |
| `--string`, `-s <str>` | Item to process. If omitted, one is read from stdin. |
| `--raw` | Treat the item as a raw log line (matched as `MESSAGE`) instead of JSON. |
| `--geoip`, `-g <path>` | MaxMind `.mmdb` database for GeoIP enrichment. |

```sh
echo '{"PROGRAM":"sshd","MESSAGE":"Failed password for root from 203.0.113.7 port 44444 ssh2"}' \
    | log_munger munge -r sshd
# a gateless rule matches a raw whole line:
log_munger munge -r http_access_logs --raw -s '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326'
```

> **`--raw` only sets `MESSAGE`.** A rule that gates on another field (e.g. `sshd` gates on
> `PROGRAM`) will not match a `--raw` line — feed it a JSON record that includes the gate
> field. `--raw` is for gateless, whole-line rules like `http_access_logs`.

### `explain` — show which rule/pattern matched

> Show which rule/pattern a log item matched and the fields it produced.

Like `munge`, but instead of just the fields it reports match metadata: whether it
matched, the rule name (or `(unnamed)`), the pattern **index** that fired (0-based), the
target field, and the extracted fields (printed as a following `---` YAML document).

Same options as `munge` (`--rules`, `--string`, `--raw`, `--geoip`).

```sh
log_munger explain -r postfix -s '{"PROGRAM":"postfix/smtpd","MESSAGE":"connect from unknown[192.0.2.5]"}'
```

### `enrich` — stream NDJSON in, enriched NDJSON out

> Stream log lines from stdin and emit enriched NDJSON on stdout.

Reads one record per line from stdin (NDJSON, or raw log lines with `--raw`), runs each
through the rules, and emits NDJSON. Extracted fields are nested under a key (default
`enriched`) or merged in with `--flat`. Unmatched records pass through unchanged unless
`--drop-unmatched` is given. A non-JSON input line is warned about and passed through.

| Option | Meaning |
|--------|---------|
| `--rules`, `-r <name>` | Rule file to load (repeatable). |
| `--raw` | Each input line is a raw log line (matched as `MESSAGE`) instead of NDJSON. |
| `--geoip`, `-g <path>` | MaxMind `.mmdb` database for GeoIP enrichment. |
| `--into`, `-i <key>` | Key to nest the enrichment under. Default: `enriched`. |
| `--flat` | Merge the extracted fields into the record instead of nesting them. |
| `--drop-unmatched` | Do not emit records that did not match any rule. |

```sh
# nest matched fields under "enriched" (records carry PROGRAM so gates can fire)
cat events.ndjson | log_munger enrich -r sshd -r postfix

# gateless whole-line rule on raw input: merge fields flat, drop non-matches
cat /var/log/apache2/access.log | log_munger enrich -r http_access_logs --raw --flat --drop-unmatched
```

---

## Inspecting rule files

### `list` — list discoverable rule files

> List the rule files discoverable across the search path.

Lists rule files across `/etc/log_munger/rules`, `/usr/local/etc/log_munger/rules`, and
the dist share dir (in that precedence order — an earlier one shadows a later one; the
first occurrence of a name wins).

| Option | Meaning |
|--------|---------|
| `--paths`, `-p` | Also show the resolved path of each rule file. |

### `which_rule_file` — resolve a name to a path

> Print the path a rule file name resolves to.

Prints the path a name resolves to, searching the same places in the same order as
[`list`](#list--list-discoverable-rule-files). A name beginning with `/`, `./`, or `../`
is used as a path instead of being searched for.

Exit codes:

- `0` :: found
- `1` :: not found
- `255` :: error

| Option | Meaning |
|--------|---------|
| `-f <name>` | Rule file to locate. |

### `list_fields` — the fields a rule file can emit

> List the fields a rule file can produce (a schema hint).

Statically analyzes a rule file and lists what its patterns can emit: the named-capture
fields, the pattern-decompose fields, the dynamic kv-decompose prefixes (with the source
field), and the geoip fields. Output is grouped into `fields:`, `kv-decompose (dynamic
keys):`, and `geoip:` sections.

| Option | Meaning |
|--------|---------|
| `-f <name>` | Rule file to inspect. |

### `dump_rule_file` — dump a rule file (fully templated)

> Dump a rule file as loaded, with includes merged and vars resolved.

Loads a rule file the way the engine does, resolving `includes` and the Template Toolkit
`vars_templated`, then dumps the result as YAML. With `--var` it prints only that one
var's resolved value, which is how to see the regexp a primitive actually compiles to.

| Option | Meaning |
|--------|---------|
| `-f <name>` | Rule file to read. |
| `--var <name>` | Dump only the resolved value of this one var, not the whole file. (Use the long form: the `-v` short alias is shadowed by the global `--version`.) |

```sh
log_munger dump_rule_file -f base --var TIMESTAMP_ISO8601
```

### `rule_file_template_order` — templating dependency order

> Show the order a rule file's templated vars get resolved in.

Prints the order `vars_templated` entries are resolved in, topologically sorted by their
`[% VAR %]` references. With `-d` it prints the dependency map that order was worked out
from, which is what to look at when a var is not resolving.

| Option | Meaning |
|--------|---------|
| `-f <name>` | Rule file to read. Default: `base`. |
| `-d` | Print dependency info instead of the flat order. |

---

## Testing rule files

### `test_rule_file` — test one rule file

> Run the built-in tests for one rule file.

Runs [`Log::Munger::RulesTest`](api.md#logmungerrulestest) over one rule file and dumps
the whole result as YAML: a fatal load error if it would not load, then every error and
warning found.

| Option | Meaning |
|--------|---------|
| `-f <name>` | Rule file to read. Default: `base`. |

### `test_all` — test every rule file

> Run the built-in tests for every discoverable rule file.

Runs `RulesTest` over every rule file on the search path and prints a pass/fail summary
(name, error count, warning count). Exits non-zero if any file has errors or fails to
load. This is what CI should run.

| Option | Meaning |
|--------|---------|
| `--verbose`, `-v` | Print each error and warning, not just the counts. |

```sh
log_munger test_all -v
```

---

## Converting grok patterns

See [grok migration](grok.md) for the full workflow.

### `degrok` — convert grok templating

> Rewrite grok templating into the Log::Munger form.

Rewrites grok's `%{TEMPLATE}` as `[% TEMPLATE %]` and `%{TEMPLATE:VAR}` as
`(?<VAR>[% TEMPLATE %])`. Give exactly one of `-s` for a string or `-f` for a file. Adding
`-r` to `-f` emits a rules-file skeleton instead, the same as `grok2rules`.

| Option | Meaning |
|--------|---------|
| `-s <str>` | A string to convert. |
| `-f <file>` | A file to convert. |
| `-r` | Convert to a rules file (skeleton). |
| `-i <name>` | Include to use (repeatable). |
| `-o <policy>` | Overwrite policy: `yes` \| `no_silent` \| `no_warn` \| `no_die`. |

### `grok2rules` — grok patterns file → rules YAML skeleton

> Convert a grok patterns file into a Log::Munger rules YAML skeleton.

Runs a grok *patterns* file (lines of `NAME regexp`) through
`Log::Munger::Degrok->grok2rules`, splitting plain lines into `vars:` and grok-referencing
lines into `vars_templated:` (after degrokking), and prints the resulting YAML to stdout.

| Option | Meaning |
|--------|---------|
| `-f <file>` | Grok patterns file to convert. |
| `--includes`, `-i <name>` | Rule file to treat as an include when resolving/overwriting names (repeatable). |
| `--overwrite`, `-o <policy>` | Policy for a name already defined by an include: `yes` \| `no_silent` \| `no_warn` \| `no_die`. Default: `no_warn`. |

```sh
log_munger grok2rules -f /path/to/grok-patterns -i base > mystuff.yaml
```
