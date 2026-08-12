# Writing a rule file

This walks through building a rule file, from a raw log line to a tested, installable
result. For the full schema see [rule-files.md](rule-files.md); for the available
primitives see [primitives.md](primitives.md).

We'll parse a made-up application log:

```
Jul 15 09:14:22 host1 myapp[3120]: login ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"
```

Assume your syslog shipper has already split this into a record with `PROGRAM => 'myapp'`
and `MESSAGE => 'login ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"'`.

## 1. Start the file

Every consumer file includes `base` so it can use the primitive library.

```yaml
---
includes:
  - base
```

## 2. Write the pattern

The message is a status word followed by a `k=v` blob. Rather than name every key in the
regexp, capture the status and the blob, then let `decompose` split it. Add a templated
var:

```yaml
vars_templated:
  MYAPP_EVENT: '(?<app_status>[% STATUS_WORD %]) (?<app_kv>[% GREEDYDATA %])'
```

`[% STATUS_WORD %]` and `[% GREEDYDATA %]` come from `base`. Use `(?<name>...)` for each
field you want in the output.

## 3. Test the pattern in isolation

Add a `vars_tests` entry so `test_all` checks the primitive by itself. `test_template`
splices your var into `[% TEST_VAR %]` and captures the whole match as `TEST`:

```yaml
vars_tests:
  MYAPP_EVENT:
    test_template: '^(?<TEST>[% TEST_VAR %])$'
    positive:
      - string: 'login ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"'
        result: 'login ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"'
    negative:
      - ''
```

## 4. Write the rule

Gate on `PROGRAM` so this rule only fires for `myapp`, anchor it, and point it at the
pattern:

```yaml
rules:
  - name: myapp
    gate:
      - field: PROGRAM
        values: [ myapp ]
    field: MESSAGE
    anchored: true
    patterns:
      - MYAPP_EVENT
```

`STATUS_WORD` is `[\w-]*`, which stops at the first space, so `app_status` captures
`login` and `app_kv` gets the rest: `ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"`.
The leading `ok` has no `=`, so the kv step in the next section ignores it. Use
`log_munger explain` to see what a pattern produces as you adjust the captures.

## 5. Break the blob down with `decompose`

The blob has a quoted value (`tags="beta user"`), so use quote-aware kv. Put it at file
level (it becomes the default for the rule):

```yaml
decompose:
  - field: app_kv
    type: kv
    quoted: true
    prefix: 'app_'
    remove: true
    tests:
      - input: 'user=alice ip=192.0.2.9 dur=0.42 tags="beta user"'
        result:
          app_user: alice
          app_ip: 192.0.2.9
          app_dur: '0.42'
          app_tags: 'beta user'
```

`prefix: app_` namespaces the produced keys; `remove: true` drops the raw `app_kv`. The
`tests` here are checked by `test_all` in isolation.

## 6. Enrich: geoip and numeric coercion

Look up the client IP and coerce the duration to a float. Both are file-level defaults:

```yaml
geoip:
  - app_ip
convert:
  app_dur: float
```

`geoip` only fires when a database is supplied via `--geoip`. `convert` makes `app_dur`
serialize as a JSON number rather than the string the regexp captured. The other types
are `int`, the case folds `lc` and `uc`, and `mac`; see
[rule-files.md](rule-files.md#convert--coerce-captured-fields) for what each does.

## 7. Add a rule test

A rule's `tests` assert the **raw pattern captures**: what the winning pattern's
`(?<...>)` groups produce, *before* `decompose`, `geoip` or `convert` run. Those steps are
validated separately — `decompose` by its own entry-level `tests` from step 5, and
`convert` and `geoip` at runtime. So the expected `result` here is `app_status` and the
still-whole `app_kv`:

```yaml
rules:
  - name: myapp
    gate:
      - field: PROGRAM
        values: [ myapp ]
    field: MESSAGE
    anchored: true
    patterns:
      - MYAPP_EVENT
    tests:
      positive:
        - string: 'login ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"'
          result:
            app_status: login
            app_kv: 'ok user=alice ip=192.0.2.9 dur=0.42 tags="beta user"'
      negative:
        - 'nospacehere'
```

A negative case has to be a string the pattern genuinely does not match. `MYAPP_EVENT` is
loose — a word, a space, then anything — so a good negative contains no space, which is
why `nospacehere` works. Something merely unrelated, such as `some unrelated line`, does
match, with `app_status=some`.

Running the item through `munge` for real lets `decompose` and `convert` finish the job:
`app_kv` becomes `app_user`, `app_ip`, `app_dur` and `app_tags`, and `app_dur` is coerced
to the number `0.42`. Step 8 shows how to check that.

## 8. Test and iterate

Drop the file somewhere on the [search path](index.md#rule-file-search-path) — e.g.
`/etc/log_munger/rules/myapp.yaml` — and run:

```sh
log_munger test_all -v                 # run every file's tests, verbosely
log_munger which_rule_file -f myapp    # confirm resolution
log_munger explain -r myapp -s '{"PROGRAM":"myapp","MESSAGE":"login ok user=alice ip=192.0.2.9 dur=0.42 tags=\"beta user\""}'
log_munger list_fields -f myapp        # what fields can this file emit?
```

Iterate with `explain` until the captures are what you want, then rely on `test_all` to
keep them that way.

## Tips

- Anchor :: Rules that consume the whole message want `anchored: true`. Reserve gateless,
  anchored rules like `http_access_logs` for whole-line formats fed in raw.
- Namespace :: Give every capture a short prefix — `ssh_`, `postfix_`, `app_` — so fields
  from different rule files never collide in a merged record.
- Prefer decompose over giant regexps :: For `k=v` payloads it is easier to read, and the
  dynamic keys survive format drift that would break a pattern naming each key.
- Order matters inside `decompose` :: A `kv` step can produce a field that a later
  `pattern` step then splits.
- When a pattern is not matching :: `log_munger dump_rule_file -f <file> --var <VAR>` shows
  a primitive's fully resolved regexp, which is usually where the problem is.
