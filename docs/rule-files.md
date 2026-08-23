# Rule-file format

A rule file is a YAML document. There are two kinds:

- Primitive library :: Defines reusable named patterns (`vars` / `vars_templated`) and
  their tests, but no `rules:`. [`base`](primitives.md) is the canonical example. Loading
  one directly is legal, it just contributes no matching rules; other files pull it in
  with `includes:`.
- Consumer :: Has a `rules:` section that actually matches log records. It usually
  `includes: [base]` so it can reference `[% IP %]`, `[% WORD %]`, and the rest.

## Top-level keys

| Key              | In       | Purpose                                                                                                                        |
|------------------|----------|--------------------------------------------------------------------------------------------------------------------------------|
| `includes`       | both     | List of other rule files to merge in first. The current file wins on a conflict, and an earlier include wins over a later one. |
| `vars`           | both     | Plain named regexps — no templating.                                                                                           |
| `vars_templated` | both     | Named regexps that use `[% VAR %]` Template Toolkit references, resolved in dependency order.                                  |
| `vars_tests`     | both     | Positive/negative tests for individual `vars` / `vars_templated`.                                                              |
| `rules`          | consumer | Ordered list of match rules (see below).                                                                                       |
| `geoip`          | consumer | File-level default list of captured fields to GeoIP-look-up.                                                                   |
| `decompose`      | consumer | File-level default list of post-match field breakdowns.                                                                        |
| `convert`        | consumer | File-level default map of `field: type` coercions.                                                                             |

The file-level `geoip` / `decompose` / `convert` act as **defaults**: a rule uses them
only if it does not carry its own equivalent key. A rule-level `geoip`/`decompose`/`convert`
replaces (does not merge with) the file-level default for that rule.

## `vars` and `vars_templated`

`vars` are plain regexp strings. A value may also be a YAML list, in which case the items
are concatenated (a convenience for splitting a long regexp across lines). Trailing
newlines are stripped so a `|` block scalar cannot leak a newline into the middle of a
composed pattern.

```yaml
vars:
  HTTPD_QS: '[^"]*'          # contents of a "double quoted" field
```

`vars_templated` values are run through [Template Toolkit](https://metacpan.org/pod/Template),
so they can reference any other var as `[% NAME %]`:

```yaml
vars_templated:
  SSH_INVALID_USER: 'Invalid user (?<ssh_user>[% USERNAME %]) from (?<ssh_src_ip>[% IP %])(?: port (?<ssh_src_port>[% INT %]))?(?: [% GREEDYDATA %])?'
```

Templating happens in **dependency order** (see [architecture](architecture.md)): if
`A` references `[% B %]`, `B` is resolved first. `log_munger rule_file_template_order -f <file>`
shows that order. Use `(?<name>...)` for named captures — those names become the field
names in the output. Names must match `[A-Za-z_]\w*` (a `-` in a capture name is a compile
error, caught at load time).

## The `rules:` section

`rules:` is an ordered list. Each rule is tried in turn; the **first** rule whose gates
all pass and one of whose patterns matches the target field wins. Its named captures are
returned (then enriched). Within a rule, patterns are also first-match-wins.

A single rule entry:

```yaml
- name: sshd                 # optional; diagnostics/explain only
  gate:                      # optional; ALL gates must pass (ANDed)
    - field: PROGRAM
      values:
        - '//^sshd(?:-session)?$//'
  field: MESSAGE             # target field to match; defaults to MESSAGE
  anchored: true             # wrap each pattern as \A(?:...)\z
  patterns:                  # required; first match wins
    - SSH_ACCEPTED
    - SSH_FAILED
  geoip:      [ ssh_src_ip ]         # optional rule-level enrichment (see below)
  convert:    { ssh_src_port: int }  # optional
  decompose:  [ ... ]                # optional
  tests:                             # optional; checked by test_all
    positive:
      - string: 'Accepted password for alice from 198.51.100.9 port 40000 ssh2'
        result:
          ssh_method: password
          ssh_user: alice
          ssh_src_ip: 198.51.100.9
          ssh_src_port: '40000'
    negative:
      - 'this is not an sshd line at all'
```

### `name`

Optional label. Shown by `explain` and used in error messages. Has no effect on matching.

### `field`

The record field the patterns run against. Defaults to `MESSAGE`. An absent, undef, or
non-scalar target field makes the rule skip.

### `gate`

A list of preconditions. **Every** gate must pass for the rule to be considered (logical
AND). Each gate names a `field` and a list of `values`; the gate passes if the field's
value matches **any** value (logical OR). A value is one of:

- literal :: Matched exactly, as in `kernel` or `sshd`.
- regexp :: Wrapped in `//…//`, as in `'//^postfix.*/smtpd$//'`. The outer slashes are
  stripped strictly, so an interior `//` such as the one in `http://` survives.

An absent, undef, or non-scalar gate field fails the gate. Gates are how you keep many
rule files loaded together from colliding — typically gating on `PROGRAM`.

```yaml
gate:
  - field: PROGRAM
    values:
      - '//^postfix.*/smtpd$//'
```

A rule with no `gate:` is *gateless* and is considered for every record (subject to its
patterns matching). `http_access_logs` is gateless so it works on raw access-log lines.

### `anchored`

When `true`, each pattern is wrapped as `\A(?:...)\z` so it must match the **whole** target
field — the equivalent of a Logstash `^...$` grok. Without it, patterns match any
substring.

### `patterns`

Required, non-empty, ordered. Each entry is one of:

- bare var name :: Resolves to a compiled `vars` / `vars_templated` value.
- inline regexp :: Used as written.

A name that matches no var is silently treated as an inline regexp, so a typo'd
reference becomes a pattern that never matches. `test_all` flags any all-caps pattern
that names no existing var, which catches the common case.

The named captures (`(?<field>...)`) of the first matching pattern become the result. A
pattern that still contains an un-degrokked `%{...}` is a load error; a pattern that will
not compile is a load error (this is where an illegal capture name is caught).

## Enrichment

After a pattern matches, three optional steps run against the captured fields, always in
this order: **decompose → geoip → convert**. Each may be set per-rule or once at file
level as a default. A new field never clobbers an existing capture; the values that do
change in place are the fields a `convert` names and the source field of a `nested: true`
json decompose with no prefix.

### `decompose` — break captured fields down further

`decompose:` is an ordered list of entries, each breaking one captured `field` into more
fields. Because it is ordered, a later entry can operate on fields an earlier one produced.
Three `type`s:

**`type: kv`** — split a `k=v k=v` blob.

| Option        | Default       | Meaning                                                                                                                |
|---------------|---------------|------------------------------------------------------------------------------------------------------------------------|
| `field_split` | `' '` (space) | Separator between pairs.                                                                                               |
| `value_split` | `'='`         | Separator between key and value.                                                                                       |
| `prefix`      | `''`          | Prepended to each produced key name.                                                                                   |
| `trim`        | *(none)*      | Characters stripped from each end of a value.                                                                          |
| `quoted`      | `false`       | Quote-aware mode: a value may be `"double"` or `'single'` quoted (quotes stripped, the separator allowed inside them). |
| `remove`      | `false`       | Delete the source field afterwards.                                                                                    |

```yaml
decompose:
  - field: nf_kv
    type: kv
    prefix: 'nf_'
    remove: true
```

This turns `nf_kv = "IN=eth0 SRC=203.0.113.7 DST=192.0.2.1 SPT=44444 DPT=22"` into
`nf_IN`, `nf_SRC`, `nf_DST`, `nf_SPT`, `nf_DPT`.

**`type: pattern`** — re-match the field against a named var (or inline regexp), anchored,
and merge its named captures.

| Option    | Meaning                                                |
|-----------|--------------------------------------------------------|
| `pattern` | A var name or inline regexp; applied as `\A(?:...)\z`. |
| `remove`  | Delete the source field afterwards.                    |

```yaml
decompose:
  - field: postfix_relay
    type: pattern
    pattern: POSTFIX_RELAY_INFO
    remove: true
    # 'mx.example.com[1.2.3.4]:25' -> postfix_relay_hostname / _ip / _port
```

**`type: json`** - JSON-decode the field, for the daemons that write a whole JSON
document into `MESSAGE`. MongoDB is the bundled example.

| Option      | Default | Meaning                                                                   |
|-------------|---------|---------------------------------------------------------------------------|
| `prefix`    | `''`    | Prepended to each produced key name.                                      |
| `separator` | `'_'`   | Joins the path segments of a nested key.                                  |
| `nested`    | `false` | Store the decoded structure whole under one key instead of flattening it. |
| `remove`    | `false` | Delete the source field afterwards.                                       |

By default the decoded structure is flattened, so each leaf becomes
`prefix + path` with the path segments joined by `separator`. Object keys and array
indices both count as segments, so `{"attr":{"remote":"1.2.3.4"}}` with `prefix: mongo_`
gives `mongo_attr_remote`. A payload of any shape therefore needs no pattern written
for it.

Some values are normalized on the way through. A MongoDB extended-JSON wrapper, a
single-key object such as `{"$date":...}`, `{"$oid":...}`, or `{"$numberLong":...}`, collapses
to the scalar inside it. Booleans become `1` and `0`. JSON null is skipped rather than
stored. A field whose value is not valid JSON or is JSON for a bare scalar rather than
an object or array is left exactly as it was.

```yaml
decompose:
  - field: mongo_json
    type: json
    prefix: 'mongo_'
    remove: true
    # {"t":{"$date":"..."},"s":"I","c":"NETWORK",...}
    #   -> mongo_t / mongo_s / mongo_c / mongo_attr_remote / ...
```

With `nested: true` the decoded structure is stored whole instead, under `prefix` (minus
a trailing separator) or, if there is no prefix, under the source field's own name —
replacing the raw string, in which case `remove:` is ignored.

Each decompose entry may have its own `tests: [ { input, result }, … ]` list, applied in
isolation by `test_all` (the `result` reflects the entry's `remove:` setting). `tests` is
ignored at runtime.

```yaml
decompose:
  - field: mongo_json
    type: json
    prefix: 'mongo_'
    remove: true
    tests:
      - input: '{"t":{"$date":"2026-07-27T02:49:30.131+00:00"},"s":"I","c":"WTCHKPT","id":22430,"ctx":"Checkpointer","msg":"WiredTiger message","attr":{"message":{"category":"WT_VERB_CHECKPOINT_PROGRESS","verbose_level_id":1,"debug":true,"note":null}}}'
        result:
          mongo_t: '2026-07-27T02:49:30.131+00:00'
          mongo_s: 'I'
          mongo_c: 'WTCHKPT'
          mongo_id: 22430
          mongo_ctx: 'Checkpointer'
          mongo_msg: 'WiredTiger message'
          mongo_attr_message_category: 'WT_VERB_CHECKPOINT_PROGRESS'
          mongo_attr_message_verbose_level_id: 1
          mongo_attr_message_debug: 1
```

### `geoip` — enrich captured addresses

A list of captured field names to look up in a MaxMind database. Only active when the
munger was built with a `geoip` database path (`--geoip` on the CLI, or the `geoip`
constructor option). The record for each field is stored under
`result -> {geoip}{$field}`. A value that is undef, empty, or not an address is silently
skipped. See [geoip.md](geoip.md).

```yaml
geoip:
  - ssh_src_ip
```

### `convert` — coerce captured fields

A map of `field: type`. Everything a regexp captures is a string; this is how one stops
being one. Five types, each with a few accepted spellings:

- `int` :: Coerce to an integer, so it serializes as a JSON number rather than a
  string. Alias is `integer`.
- `float` :: Coerce to a floating-point number. Aliases are `num` or `number`.
- `lc` :: Lowercase the value. Aliases `lower` or `lowercase`.
- `uc` :: Uppercase the value. Aliases `upper` or `uppercase`.
- `mac` :: Rewrite a MAC address into lowercase colon-separated form. Aliases are
  `macaddr` or `mac_address`.

The case folds exist for tokens whose case varies between the sources that write them.
SELinux logs `avc: denied` and AppArmor logs `apparmor="DENIED"` for the same verdict, so
`auditd.yaml` captures both into `mac_result` and lowercases it. Whatever uses the
field then does not have to care which LSM produced the line.

`mac` exists for the same reason one layer down. The four spellings in the wild,
`C4:D8:D5:3B:8C:4B`, `C4-D8-D5-3B-8C-4B`, `c4d8.d53b.8c4b` and the kernel's space-separated
`c4 d8 d5 3b 8c 4b`, all normalize to `c4:d8:d5:3b:8c:4b`, so an address from a
`ll header` dump compares directly against one from an ARP line. A value that is not
twelve hex digits once the separators are stripped is left as it was.

A field that was not captured is left alone, as is a numeric conversion of something that
does not look like a number. `convert` runs last, so GeoIP still sees the original string
form of an address.

```yaml
convert:
  ssh_src_port: int
  nf_LEN: int
  mac_result: lc
  kernel_ll_src_mac: mac
```

## `vars_tests` and rule `tests`

Both are exercised by `log_munger test_all` (and `Log::Munger::RulesTest`).

`vars_tests` validate a single primitive. Each entry has a `test_template` (a small regexp
with a `TEST` capture and a `[% TEST_VAR %]` slot the var is spliced into), a `positive`
list of `{ string, result }` cases (the string must match and `TEST` must equal `result`),
and a `negative` list of strings that must **not** match.

```yaml
vars_tests:
  IPv4:
    test_template: '(?<TEST>[% TEST_VAR %])'
    positive:
      - string: '  a b c 127.0.0.1 d'
        result: '127.0.0.1'
    negative:
      - '  a b c ::1 d'
```

Rule `tests` validate a rule's patterns: each `positive` string must match one of the
rule's patterns and its raw named captures must equal `result`; each `negative` string must
match none of them. The captures are compared before enrichment with `decompose`, `geoip`,
and `convert` are not being applied here. Those are covered separately: each `decompose`
entry has its own `tests`, and the `numeric` and `enriched` keys described below put
`convert` and `decompose` under test as the rule uses them; `geoip` needs a database and
stays a runtime concern. So a rule test's `result` lists the
`(?<...>)` captures only, and numbers appear as strings (e.g. `ssh_src_port: '54321'`) even
when a `convert:` coerces them at runtime. See the bundled `sshd.yaml` / `netfilter.yaml`
for full worked examples, the rule tests expect the raw port string and the still-whole
`nf_kv` blob respectively.

A test case may also name the `program` the line arrived under, and that puts the rule's
`gate` under test alongside its patterns. On a `positive` case the gate must accept the
program before the patterns are tried. On a `negative` case — written as
`{ string, program }` rather than a bare string — the case passes if the gate refuses the
program *or* no pattern matches, which is how a gate that reaches too far is caught: the
line is one the rule handles perfectly well, and the point is that it arrived under a
program the rule has no business claiming.

```yaml
tests:
  positive:
    - string: 'DHCPACK(eth0) 192.0.2.50 aa:bb:cc:dd:ee:ff myhost'
      program: 'dnsmasq-dhcp'
      result:
        dnsmasq_dhcp_type: 'DHCPACK'
        dnsmasq_dhcp_iface: 'eth0'
        dnsmasq_dhcp_ip: '192.0.2.50'
        dnsmasq_dhcp_mac: 'aa:bb:cc:dd:ee:ff'
        dnsmasq_dhcp_hostname: 'myhost'
  negative:
    - 'this is not a dnsmasq line at all'
    - string: 'DHCPACK(eth0) 192.0.2.50 aa:bb:cc:dd:ee:ff myhost'
      program: 'dhcpd'
```

Naming a program is worth the line it costs. A wrong pattern loses one message type; a wrong gate loses the
whole daemon, and every pattern test still passes while it does. A gated rule no case names
a program for is reported as a warning. Gates are checked against a record holding nothing
but `PROGRAM`, which is what every gate in every bundled file keys on — see the bundled
`dnsmasq.yaml`, whose gate has to cover `dnsmasq`, `dnsmasq-dhcp` and `dnsmasq-tftp`.

A case may also carry a `numeric` list, naming the fields the `convert` map has to have
turned into numbers:

```yaml
- string: 'Maximum number of concurrent DNS queries reached (max: 150)'
  program: 'dnsmasq'
  numeric:
    - dnsmasq_max_queries
  result:
    # captures are compared as the strings they are, before any conversion
    dnsmasq_max_queries: '150'
```

`result` and `numeric` ask different questions of the same case, which is why both can name
the same field. `result` compares the raw capture — the string `'150'`. `numeric` runs
`decompose` and then `convert` over a *copy* of those captures and asks what `'150'` became,
so a field a decompose produced can be listed too. That is the case worth covering most: a
kv blob split into fields, one of which a convert then coerces.

What it checks is how perl is holding the value, not what the value looks like. Asking
`looks_like_number` would pass on the captured string whether the convert ran or not, which
is the one thing the case was written to find out. A rule that converts a field to a number
and lists none is reported as a warning; `lc`, `uc` and `mac` are not numeric conversions
and are not warned about.

An `enriched` map says what the whole field set looks like at that same point, which is what
puts a `decompose` under test as the rule really uses it:

```yaml
- string: 'neti : TTY=pts/0 ; PWD=/home/neti ; USER=root ; COMMAND=/bin/ls -la'
  program: 'sudo'
  result:
    # the raw captures: one blob, not yet split
    sudo_user: 'neti'
    sudo_kv: 'TTY=pts/0 ; PWD=/home/neti ; USER=root ; COMMAND=/bin/ls -la'
  enriched:
    # and what a consumer receives
    sudo_user: 'neti'
    sudo_TTY: 'pts/0'
    sudo_PWD: '/home/neti'
    sudo_USER: 'root'
    sudo_COMMAND: '/bin/ls -la'
```

A decompose entry's own `tests` feed it a hand-written input, which says the entry works but
not that anything is wired to it — rename the capture it reads and those tests still pass
while the rule quietly stops splitting. `enriched` is compared exactly in both directions,
so the missing fields are caught, and so is one that turns up unasked for. A rule whose
decompose fires for one of its own tests and says nothing about the result is reported as a
warning.

## Complete minimal example

```yaml
---
includes:
  - base
vars_templated:
  MYAPP_LOGIN: 'user (?<app_user>[% USERNAME %]) logged in from (?<app_ip>[% IP %])'
vars_tests:
  MYAPP_LOGIN:
    test_template: '^(?<TEST>[% TEST_VAR %])$'
    positive:
      - string: 'user alice logged in from 192.0.2.9'
        result: 'user alice logged in from 192.0.2.9'
    negative:
      - 'nope'
geoip:
  - app_ip
rules:
  - name: myapp
    gate:
      - field: PROGRAM
        values: [ myapp ]
    field: MESSAGE
    anchored: true
    patterns:
      - MYAPP_LOGIN
    tests:
      positive:
        - string: 'user alice logged in from 192.0.2.9'
          result:
            app_user: alice
            app_ip: 192.0.2.9
      negative:
        - 'user alice logged out'
```

See [writing a rule file](writing-rules.md) for a step-by-step build.
