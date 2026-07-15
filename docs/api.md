# Perl API

The public entry point is `Log::Munger`. The other modules are used internally but are
documented here because tooling and tests reach for them.

## `Log::Munger`

A thin, stateful façade over [`Log::Munger::LogProcessor`](#logmungerlogprocessor). Load
rule files, then push records through.

### `new`

```perl
my $munger = Log::Munger->new( rules => [ 'base', 'postfix' ] );
my $munger = Log::Munger->new(
    rules => ['postfix'],
    geoip => '/path/to/GeoLite2-City.mmdb',
);
```

- `rules` — arrayref of rule-file names (or paths) to load. Optional at construction; you
  can add more later with `load`.
- `geoip` — path to a MaxMind `.mmdb` database. When set, rules that flag captured fields
  with `geoip:` have those looked up, stored under `result -> {geoip}{$field}`. Requires
  [`IP::Geolocation::MMDB`](geoip.md), loaded only when this option is used.

### `load`

Load an additional rule file and rebuild the processor.

```perl
$munger->load( file => 'sshd' );   # 'file' is required
```

### `process_item`

Run a record through the rules; return the first matching rule's named captures, or
`undef` if nothing matched (or no rules are loaded).

```perl
my $fields = $munger->process_item( item => $decoded_hashref );
my $fields = $munger->process_item( item => $raw_log_line );   # bare string => { MESSAGE => ... }
```

- `item` — a decoded record (hashref) or a bare string. A bare string is matched as the
  `MESSAGE` field, so whole log lines need not be wrapped.

Never dies: a bad item or a pathological pattern yields `undef`.

### `explain_item`

Like `process_item`, but returns match metadata instead of just the fields:

```perl
my $why = $munger->explain_item( item => $record );
# { matched => 0 }                       # nothing matched (or no rules)
# { matched => 1, rule => 'sshd', pattern => 1, field => 'MESSAGE', fields => { ... } }
```

## `Log::Munger::LogProcessor`

Does the real work: loads and compiles rule files, then matches. `Log::Munger` delegates
to it; use it directly if you don't need the add-a-file-later convenience.

```perl
use Log::Munger::LogProcessor;
my $p = Log::Munger::LogProcessor->new( rules => [ 'base', 'postfix' ], geoip => $db );
my $fields = $p->process_item( item => $record );   # same contract as above
my $meta   = $p->explain_item( item => $record );
```

`new` requires a non-empty `rules` arrayref and **dies** on a load/compile error (a
malformed rule, an un-degrokked `%{...}`, a pattern that won't compile). A rule file with
no `rules:` section (a primitive library like `base`) is accepted and contributes no
rules.

Matching semantics: rules are tried in load order; a rule fires when **all** its gates
pass **and** one of its patterns matches the target field (both first-match-wins). On a
match it runs **decompose → geoip → convert** and returns the captures. `process_item` /
`explain_item` never die.

## `Log::Munger::RuleFileParser`

Loads and parses a single rule file into a hash: resolves the name via
[`WhichRuleFile`](#logmungerwhichrulefile), reads the YAML, merges `includes`
(right-precedence via `Hash::Merge`), normalizes `vars`, and expands `vars_templated` with
Template Toolkit in dependency order.

- `load( file => $name )` — full parse, including templating. Returns the rules hashref.
- `load_no_templating( file => $name )` — parse and merge includes but leave
  `vars_templated` unexpanded (used by the template-order tooling).

## `Log::Munger::WhichRuleFile`

Resolves a rule-file name to a path.

- `rule_file_location( file => $name )` — returns the resolved path, or `undef` if not
  found. Search order (first match wins):
  1. an explicit path (starts with `/`, `./`, `../`) — the file, then `name.yaml`;
  2. `/etc/log_munger/rules/` — `name`, then `name.yaml`;
  3. `/usr/local/etc/log_munger/rules/` — `name`, then `name.yaml`;
  4. the dist share dir (`File::ShareDir::dist_dir('Log-Munger')`) — `name`, then `name.yaml`.

## `Log::Munger::RulesUsable`

A fast structural sanity check (not a full test).

- `usable( rules => \%rules_hash )` — returns `1`, or **dies** if `rules` is missing, not a
  hash, or its `rules` key is missing/not an array/empty.

## `Log::Munger::RulesTest`

The full test harness behind `log_munger test_all` / `test_rule_file`.

- `test( file => $path )` **or** `test( hash => \%rules_hash )` — returns
  `{ fatal => <load-error-or-undef>, errors => [...], warnings => [...] }`.

It checks: `vars_tests` positive/negative cases; each rule compiles and its positive
strings match with the expected captures while its negative strings do not; each
`decompose` entry's isolated `tests`; and lints vars for un-degrokked `%{...}`, illegal
capture names, embedded newlines, and non-compiling regexps.

## `Log::Munger::RulesTemplateOrder`

Computes the dependency order for `vars_templated` (a topological sort over `[% VAR %]`
references, via `Algorithm::Dependency::Ordered`).

- `order_for_rules_hash( rules => \%hash )` / `order_for_rules_file( file => $path )` —
  arrayref of var names in resolution order.
- `depends_for_rules_hash( rules => \%hash )` / `depends_for_rules_file( file => $path )` —
  the raw `{ var => [deps] }` map.

## `Log::Munger::Degrok`

Converts grok templating to Log-Munger templating. See [grok.md](grok.md).

- `string( string => $s )` — `%{TOKEN}` → `[% TOKEN %]`, `%{TOKEN:name}` →
  `(?<name>[% TOKEN %])`.
- `file( file => $path )` — the same, applied to a whole file.
- `grok2rules( file => $path, includes => [...], overwrite => ... )` — turn a grok patterns
  file into a rules-YAML skeleton.
