# Architecture

How a rule file becomes a matcher, and how a record becomes fields.

## Modules

| Module | Role |
|--------|------|
| `Log::Munger` | Public façade. Holds the list of loaded rule files and a compiled `LogProcessor`, and rebuilds it when you `load` more. |
| `Log::Munger::LogProcessor` | Compiles rule files into runtime rules and runs records against them. The engine. |
| `Log::Munger::RuleFileParser` | Loads one file: resolve → read YAML → merge includes → normalize vars → template `vars_templated`. |
| `Log::Munger::WhichRuleFile` | Name → path resolution across the search path. |
| `Log::Munger::RulesTemplateOrder` | Topologically sorts `vars_templated` by their `[% VAR %]` dependencies. |
| `Log::Munger::RulesUsable` | Fast structural sanity check of a rules hash. |
| `Log::Munger::RulesTest` | Full test harness: vars tests, rule tests, decompose tests, and var linting. |
| `Log::Munger::Degrok` | grok `%{...}` → Log-Munger `[% ... %]` conversion. |
| `Log::Munger::App` + `App::Command::*` | The `log_munger` CLI, built on App::Cmd. |

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

- Includes are merged first :: With right precedence, so the current file wins on a
  conflict and a consumer can override a base primitive. Includes are de-duplicated.
- Templating order matters :: Because `vars_templated` entries reference each other,
  `RulesTemplateOrder` works out a dependency order via `Algorithm::Dependency::Ordered`
  so a var is resolved only once everything it references already is. Trailing newlines
  are stripped at every step, since a YAML `|` block scalar leaking its terminator into
  the middle of a composed pattern would leave it unable to match a single-line log while
  looking perfectly fine in the file. Inspect the order with
  `log_munger rule_file_template_order -f <file>`.
- Compilation is where errors surface :: `LogProcessor->new` compiles each rule to real
  `qr//` objects and dies on a malformed rule, a leftover un-degrokked `%{...}`, or a
  pattern that will not compile, which includes an illegal capture name such as one
  containing `-`. A bad rule file therefore fails loudly at load rather than silently at
  match time.
- A file with no `rules:` is fine :: A primitive library such as `base` is accepted and
  simply contributes no runtime rules.

## Matching a record

`LogProcessor->_run` (shared by `process_item` and `explain_item`):

1. If the item is a bare string, wrap it as `{ MESSAGE => $string }`. A non-hash,
   non-string item yields no match.
2. Walk the compiled rules **in load order**. For each rule:
   - Gates, ANDed :: Every gate's field value must hit one of the gate's literals or
     regexps. An absent, undef, or non-scalar field fails the gate, and any failing gate
     skips the rule.
   - Target field :: `rule.field`, `MESSAGE` unless told otherwise, must be a defined
     scalar.
   - Patterns, first-match-wins :: Each compiled pattern is tried against the target.
3. On the first pattern that matches, snapshot `%+` (the named captures) immediately, then
   enrich in order: **decompose → geoip → convert**. Return the match and stop —
   first-rule-wins across the whole set.

The whole match runs inside an `eval`, so any exception yields "no match" and a single bad
log line can never take down a stream.

### Why the enrichment order is fixed

- decompose first :: It can *produce* fields, such as splitting a `k=v` blob into
  `SRC=...`, that a later step then needs.
- geoip next :: So it can look up an address a decompose step just produced, while the
  value is still the original string.
- convert last :: So coercion happens after geoip has seen the string form of an address
  or port.

No enrichment step ever overwrites an existing capture; new keys are only added if absent.

## Testing

`RulesTest`, via `test_all` and `test_rule_file`, validates a file without needing live
logs. It checks each primitive against its `vars_tests`, compiles and exercises each rule
against its `tests`, runs each `decompose` entry's `tests` in isolation, and lints vars for
grok remnants, bad capture names, embedded newlines, and compile failures. `test_all` exits
non-zero if anything fails, so it is worth wiring into CI.
