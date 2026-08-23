# Architecture

How a rule file becomes a matcher, and how a record becomes fields.

## Modules

| Module                                 | Role                                                                                                                    |
|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `Log::Munger`                          | Public facade. Holds the list of loaded rule files and a compiled `LogProcessor`, and rebuilds it when you `load` more. |
| `Log::Munger::LogProcessor`            | Compiles rule files into runtime rules and runs records against them. The engine.                                       |
| `Log::Munger::RuleFileParser`          | Loads one file: resolve → read YAML → merge includes → normalize vars → template `vars_templated`.                      |
| `Log::Munger::WhichRuleFile`           | Name → path resolution across the search path.                                                                          |
| `Log::Munger::RulesTemplateOrder`      | Topologically sorts `vars_templated` by their `[% VAR %]` dependencies.                                                 |
| `Log::Munger::RulesUsable`             | Fast structural sanity check of a rules hash.                                                                           |
| `Log::Munger::RulesTest`               | Full test harness: vars tests, rule tests, decompose tests, and var linting.                                            |
| `Log::Munger::Degrok`                  | grok `%{...}` → Log-Munger `[% ... %]` conversion.                                                                      |
| `Log::Munger::App` + `App::Command::*` | The `log_munger` CLI, built on App::Cmd.                                                                                |

## Loading and compiling a rule file

```
name ──WhichRuleFile──► path ──read_file──► YAML text ──YAML::XS::Load──► hash
                                                                            │
                               includes merged (Hash::Merge, LEFT_PRECEDENT)│
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

- Includes are merged first :: The current file wins on a conflict, so a consumer can
  override a base primitive, and an earlier include wins over a later one. Includes are
  de-duplicated.
- Templating order matters :: `vars_templated` entries reference each other, so
  `RulesTemplateOrder` works out a dependency order via `Algorithm::Dependency::Ordered`
  and a var is resolved only once everything it references already is. See the order with
  `log_munger rule_file_template_order -f <file>`.
- Trailing newlines are stripped at every step :: A YAML `|` block scalar keeps its
  terminating newline, and one of those landing in the middle of a composed pattern leaves
  it unable to match a single-line log while looking perfectly fine in the file.
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
2. Walk the compiled rules in load order. For each rule:
   - Gates, ANDed :: Every gate's field value must hit one of the gate's literals or
     regexps. An absent, undef, or non-scalar field fails the gate, and any failing gate
     skips the rule.
   - Target field :: `rule.field`, `MESSAGE` unless told otherwise, must be a defined
     scalar.
   - Patterns, first-match-wins :: Each compiled pattern is tried against the target.
3. On the first pattern that matches, snapshot `%+` (the named captures) immediately, then
   enrich in order: decompose → geoip → convert. Return the match and stop —
   first-rule-wins across the whole set.

The whole match runs inside an `eval`, so any exception yields "no match" rather than
taking down a stream. That bounds failures, not runtime: a pattern prone to catastrophic
backtracking can still burn CPU on a hostile line, which is one of the reasons to keep
patterns anchored and tested.

### Why the enrichment order is fixed

- decompose first :: It produces fields, such as the `SRC=...` split out of a `k=v`
  blob, that the later steps then work on.
- geoip next :: So it can look up an address decompose just produced, and it sees
  that address while the value is still the original string.
- convert last :: So it can look up an address decompose just produced. No specific reason
  this is ordered post geoip.

Decompose and geoip only add keys that are absent, never overwriting an existing capture,
with one exception: a `nested: true` json decompose with no prefix replaces its own source
field with the decoded structure. `convert` is the step that changes existing values, and
only for the fields it names.

## Testing

`RulesTest`, via `test_all` and `test_rule_file`, validates a file without needing live
logs. It checks each primitive against its `vars_tests`, compiles and exercises each rule
against its `tests`, runs each `decompose` entry's `tests` in isolation, and lints vars for
grok remnants, bad capture names, embedded newlines, and compile failures. `test_all` exits
non-zero if anything fails, so it is worth wiring into CI.
