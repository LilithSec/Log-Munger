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

- `rules` :: Arrayref of rule-file names or paths to load. Optional at construction; you
  can add more later with `load`.
- `geoip` :: Path to a MaxMind `.mmdb` database. When set, rules that flag captured fields
  with `geoip:` have those looked up and stored under `result -> {geoip}{$field}`. Needs
  [`IP::Geolocation::MMDB`](geoip.md), which is loaded only when this option is used.

A rule file that will not load or compile is fatal here, so a broken file is caught at
construction rather than silently matching nothing later on.

### `load`

Load an additional rule file and rebuild the processor. Rules from files loaded later are
tried after rules from files loaded earlier, so load order is match priority.

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

- `item` :: A decoded record (hashref) or a bare string. A bare string is matched as the
  `MESSAGE` field, so whole log lines need not be wrapped. Takes precedence over the
  field args below.

If you are coming from a syslog reader that has already split the fields out, hand them
over directly instead of building the record hash yourself:

```perl
my $fields = $munger->process_item(
    message  => $message,
    program  => $program,
    priority => $priority,
    facility => $facility,
);
```

- `message` :: The raw log message, assembled into `{ MESSAGE => ... }`.
- `program` :: Adds a `PROGRAM` field, which is what most daemon rule files gate on.
- `priority` :: Adds a `PRIORITY` field.
- `facility` :: Adds a `FACILITY` field.

Only `message` is needed; the other three are added when given. The keys are the
upper-case syslog-ng-style names that rule gates match on.

Never dies: an exception during matching comes back as `undef`. That bounds failures, not
runtime — a pattern prone to catastrophic backtracking can still burn CPU on a hostile
line.

### `explain_item`

Like `process_item`, and takes the same arguments, but returns match metadata instead of
just the fields:

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
(via `Hash::Merge`; the including file wins on a conflict), normalizes `vars`, and expands `vars_templated` with
Template Toolkit in dependency order.

- `load( file => $name )` :: Full parse, including templating. Returns the rules hashref.
  Every resolved `vars_templated` entry is written back into `vars`, so afterwards there
  is one flat namespace of named regexps.
- `load_no_templating( file => $name )` :: Parse and merge includes but leave
  `vars_templated` unexpanded. This is what the template-order tooling uses, since working
  out which var depends on which means reading the `[% VAR %]` references before they are
  substituted away.

## `Log::Munger::WhichRuleFile`

Resolves a rule-file name to a path.

- `rule_file_location( file => $name )` :: Returns the resolved path, or `undef` if the
  name turned up nothing. Search order, first match wins:
  1. an explicit path (starts with `/`, `./`, `../`) — the file, then `name.yaml`;
  2. `$ENV{LOG_MUNGER_RULES_DIR}`, when set — `name`, then `name.yaml`;
  3. `/etc/log_munger/rules/` — `name`, then `name.yaml`;
  4. `/usr/local/etc/log_munger/rules/` — `name`, then `name.yaml`;
  5. the dist share dir (`File::ShareDir::dist_dir('Log-Munger')`) — `name`, then `name.yaml`
     (skipped when the distribution is not installed).

That ordering is what lets a local file shadow one shipped with the distribution: drop
your own `sshd.yaml` into `/etc/log_munger/rules/` and every reference to `sshd` picks it
up instead.

## `Log::Munger::RulesUsable`

A fast structural sanity check, not a full test. Meant for something starting up that
wants a cheap look at a file it is about to load.

- `usable( rules => \%rules_hash )` :: Returns `1`, or **dies** if `rules` is missing, is
  not a hash, or its `rules` key is missing, not an array, or empty.

## `Log::Munger::RulesTest`

The full test harness behind `log_munger test_all` / `test_rule_file`.

- `test( file => $path )` **or** `test( hash => \%rules_hash )` :: Returns
  `{ fatal => <load-error-or-undef>, errors => [...], warnings => [...] }`.

It runs every `vars_tests` case, compiles each rule exactly as the engine does and runs it
against its `tests`, applies each `decompose` entry to its own `tests` in isolation, and
lints every resolved var for un-degrokked `%{...}`, illegal capture names, embedded
newlines, and regexps that will not compile. Nothing that would produce wrong output is a
warning; things merely worth knowing, such as a rule with no tests at all, are.

Every message names where the problem is as a path into the rule file, so
`.rules.3.tests.positive.0` is the first positive test of the fourth rule.

## `Log::Munger::RulesTemplateOrder`

Computes the dependency order for `vars_templated` (a topological sort over `[% VAR %]`
references, via `Algorithm::Dependency::Ordered`).

- `order_for_rules_hash( rules => \%hash )` / `order_for_rules_file( file => $path )` ::
  Arrayref of var names in resolution order.
- `depends_for_rules_hash( rules => \%hash )` / `depends_for_rules_file( file => $path )`
  :: The raw `{ var => [deps] }` map.

The hash forms want a hash from `load_no_templating`. Once `load` has run the templating
is already done and the `[% VAR %]` references these read have been substituted away.

## `Log::Munger::Degrok`

Converts grok templating to Log-Munger templating. See [grok.md](grok.md).

- `string( string => $s )` :: `%{TOKEN}` becomes `[% TOKEN %]`, and `%{TOKEN:name}`
  becomes `(?<name>[% TOKEN %])`.
- `file( file => $path )` :: The same, applied to a whole file a line at a time.
- `grok2rules( file => $path, includes => [...], overwrite => ... )` :: Turns a grok
  patterns file into a rules-YAML skeleton.
