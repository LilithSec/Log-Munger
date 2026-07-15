# Architecture

How a rule file becomes a matcher, and how a record becomes fields.

## Modules

| Module | Role |
|--------|------|
| `Log::Munger` | Public façade. Holds the list of loaded rule files and a compiled `LogProcessor`; rebuilds it when you `load` more. |
| `Log::Munger::LogProcessor` | Compiles rule files into runtime rules and runs records against them. The engine. |
| `Log::Munger::RuleFileParser` | Loads one file: resolve → read YAML → merge includes → normalize vars → template `vars_templated`. |
| `Log::Munger::WhichRuleFile` | Name → path resolution across the search path. |
| `Log::Munger::RulesTemplateOrder` | Topologically sorts `vars_templated` by their `[% VAR %]` dependencies. |
| `Log::Munger::RulesUsable` | Fast structural sanity check of a rules hash. |
| `Log::Munger::RulesTest` | Full test harness (vars tests, rule tests, decompose tests, var linting). |
| `Log::Munger::Degrok` | grok `%{...}` → Log-Munger `[% ... %]` conversion. |
| `Log::Munger::App` + `App::Command::*` | The `log_munger` CLI (App::Cmd). |

## Loading and compiling a rule file

```
name ──WhichRuleFile──► path ──read_file──► YAML text ──YAML::XS::Load──► hash
                                                                            │
                              includes merged (Hash::Merge, RIGHT_PRECEDENT)│
                                                                            ▼
                                       vars normalized (lists joined, newlines trimmed)
                                                                            │
                         vars_templated resolved in dependency order        │
                        (RulesTemplateOrder → Template Toolkit)             ▼
                                                                       rules hash
                                                                            │
                                     LogProcessor->_compile_rule per rule    ▼
                                        compiled rules (qr// patterns, gates,
                                        decompose/geoip/convert structures)
```

Key points:

- **Includes** are merged first, with **right precedence** — the current file wins on a
  conflict, so a consumer can override a base primitive. Includes are de-duplicated.
- **Templating order matters.** Because `vars_templated` entries reference each other,
  `RulesTemplateOrder` computes a dependency order (via `Algorithm::Dependency::Ordered`)
  so a var is resolved only after everything it references. Trailing newlines are stripped
  at every step so a YAML `|` block scalar can't leak a newline into the middle of a
  composed pattern. Inspect the order with `log_munger rule_file_template_order -f <file>`.
- **Compilation is where errors surface.** `LogProcessor->new` compiles each rule to real
  `qr//` objects and dies on a malformed rule, a leftover un-degrokked `%{...}`, or a
  pattern that won't compile (including an illegal capture name like one containing `-`).
  This means a bad rule file fails loudly at load, not silently at match time.
- A file with **no `rules:`** (a primitive library like `base`) is accepted and simply
  contributes no runtime rules.

## Matching a record

`LogProcessor->_run` (shared by `process_item` and `explain_item`):

1. If the item is a bare string, wrap it as `{ MESSAGE => $string }`. A non-hash,
   non-string item yields no match.
2. Walk the compiled rules **in load order**. For each rule:
   - **Gates** (ANDed): every gate's field value must hit one of the gate's literals or
     regexps. An absent/undef/non-scalar field fails the gate. Any failing gate skips the
     rule.
   - **Target field**: `rule.field` (default `MESSAGE`) must be a defined scalar.
   - **Patterns** (first-match-wins): try each compiled pattern against the target.
3. On the first pattern that matches, snapshot `%+` (the named captures) immediately, then
   enrich in order: **decompose → geoip → convert**. Return the match and stop
   (first-rule-wins across the whole set).

The whole match runs inside an `eval`; any exception yields "no match" so a single bad log
line can never take down a stream.

### Why the enrichment order is fixed

- **decompose** first, because it can *produce* fields (e.g. split `k=v` into `SRC=...`)
  that a later step needs.
- **geoip** next, so it can look up an address a decompose step just produced — while the
  value is still the original string.
- **convert** last, so numeric coercion happens after geoip has seen the string form of an
  address/port.

No enrichment step ever overwrites an existing capture; new keys are only added if absent.

## Testing

`RulesTest` (via `test_all` / `test_rule_file`) validates a file without running live
logs: it checks each primitive against its `vars_tests`, compiles and exercises each rule
against its `tests`, runs each `decompose` entry's isolated `tests`, and lints vars for
grok remnants, bad capture names, embedded newlines, and compile failures. `test_all`
exits non-zero if anything fails — wire it into CI.
