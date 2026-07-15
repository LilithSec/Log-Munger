#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);

BEGIN {
	use_ok('Log::Munger')                 || print "Bail out!\n";
	use_ok('Log::Munger::LogProcessor')   || print "Bail out!\n";
}

#
# A self-contained rule file exercising gates, patterns, and edge cases with
# inline regexps (no base include needed).
#
my $yaml = <<'YAML';
---
rules:
  - name: web_url
    gate:
      - field: PROGRAM
        values: ['//^web//', 'exactweb']
    field: URL
    patterns:
      - '(?<proto>https?)://(?<host>[^/ ]+)'
    tests:
      positive:
        - string: 'http://example.com/x'
          result: { proto: http, host: example.com }
      negative:
        - 'ftp://nope'
  - name: nocap
    gate:
      - field: PROGRAM
        values: ['nocap']
    field: MESSAGE
    patterns:
      - 'ping'
    tests:
      positive:
        - string: 'ping'
          result: {}
      negative:
        - 'pong'
  - name: order_a
    gate:
      - field: PROGRAM
        values: ['dup']
    field: MESSAGE
    patterns:
      - '(?<who>alpha)'
    tests:
      positive:
        - string: 'alpha'
          result: { who: alpha }
      negative:
        - 'zzz'
  - name: order_b
    gate:
      - field: PROGRAM
        values: ['dup']
    field: MESSAGE
    patterns:
      - '(?<who>alpha|beta)'
    tests:
      positive:
        - string: 'beta'
          result: { who: beta }
      negative:
        - 'zzz'
YAML

my ( $fh, $filename ) = tempfile( 'log_munger_rules_XXXXXX', SUFFIX => '.yaml', TMPDIR => 1, UNLINK => 1 );
print {$fh} $yaml;
close($fh);

my $m = Log::Munger->new( 'rules' => [$filename] );
isa_ok( $m, 'Log::Munger', 'new with a rule file' );

# literal + //regexp// gate, interior // in the target survives
my $r = $m->process_item( 'item' => { PROGRAM => 'web1', URL => 'http://example.com/x' } );
is_deeply( $r, { proto => 'http', host => 'example.com' }, '//regexp// gate + interior // in target' );

# exact-string gate value also passes
$r = $m->process_item( 'item' => { PROGRAM => 'exactweb', URL => 'https://foo.bar/baz' } );
is_deeply( $r, { proto => 'https', host => 'foo.bar' }, 'literal gate value' );

# gate passes, pattern does not match => undef
$r = $m->process_item( 'item' => { PROGRAM => 'web1', URL => 'ftp://nope' } );
is( $r, undef, 'gate pass but no pattern match => undef' );

# a matching pattern with no named captures => {} (matched, no fields)
$r = $m->process_item( 'item' => { PROGRAM => 'nocap', MESSAGE => 'ping' } );
is_deeply( $r, {}, 'zero-capture match returns empty hashref, not undef' );

# first-match-wins ACROSS rules: order_a gate-passes but its pattern misses
# 'beta', so order_b wins
$r = $m->process_item( 'item' => { PROGRAM => 'dup', MESSAGE => 'beta' } );
is_deeply( $r, { who => 'beta' }, 'first-match-wins falls through to next rule when pattern misses' );

# order_a wins for 'alpha' (declared first)
$r = $m->process_item( 'item' => { PROGRAM => 'dup', MESSAGE => 'alpha' } );
is_deeply( $r, { who => 'alpha' }, 'earlier rule wins when it matches' );

# gate field absent from the item => no rule fires
$r = $m->process_item( 'item' => { MESSAGE => 'ping' } );
is( $r, undef, 'absent gate field => undef' );

# target field absent => no match
$r = $m->process_item( 'item' => { PROGRAM => 'web1' } );
is( $r, undef, 'absent target field => undef' );

# never dies on bad input
$r = $m->process_item( 'item' => 'not a hashref' );
is( $r, undef, 'non-hashref item => undef (no die)' );

$r = $m->process_item( 'item' => undef );
is( $r, undef, 'undef item => undef (no die)' );

#
# Integration against the shipped base + postfix rule files.
#
my $pm = Log::Munger->new( 'rules' => [ 'base', 'postfix' ] );
isa_ok( $pm, 'Log::Munger', 'new with shipped base + postfix' );

$r = $pm->process_item(
	'item' => { 'PROGRAM' => 'postfix/smtpd', 'MESSAGE' => 'connect from mail.example.com[192.0.2.5]' } );
is_deeply(
	$r,
	{ 'postfix_client_hostname' => 'mail.example.com', 'postfix_client_ip' => '192.0.2.5' },
	'shipped postfix/smtpd connect enrichment'
);

$r = $pm->process_item( 'item' => { 'PROGRAM' => 'postfix/qmgr', 'MESSAGE' => 'ABCDEF123456: removed' } );
is_deeply( $r, { 'postfix_queueid' => 'ABCDEF123456' }, 'shipped postfix/qmgr removed enrichment' );

# program that no rule gates on => undef (never mutate/consume a line)
$r = $pm->process_item( 'item' => { 'PROGRAM' => 'cron', 'MESSAGE' => 'ABCDEF123456: removed' } );
is( $r, undef, 'un-gated program => undef' );

# another shipped daemon (anvil) enriches via its anchored rule
$r = $pm->process_item(
	'item' => {
		'PROGRAM' => 'postfix/anvil',
		'MESSAGE' => 'statistics: max connection rate 3/60s for (smtp:192.0.2.5) at Jul 15 10:00:00'
	}
);
is_deeply(
	$r,
	{   'postfix_anvil_conn_period' => '60s',
		'postfix_anvil_conn_rate'   => '3',
		'postfix_anvil_timestamp'   => 'Jul 15 10:00:00',
		'postfix_client_ip'         => '192.0.2.5',
		'postfix_service'           => 'smtp',
	},
	'shipped postfix/anvil enrichment'
);

# a multi-instance postfix program name still matches the ^postfix.*/<daemon>$ gate
$r = $pm->process_item(
	'item' => {
		'PROGRAM' => 'postfix-mx/postscreen',
		'MESSAGE' => 'CONNECT from [192.0.2.5]:26 to [198.51.100.2]:25'
	}
);
is_deeply(
	$r,
	{   'postfix_client_ip'   => '192.0.2.5',
		'postfix_client_port' => '26',
		'postfix_server_ip'   => '198.51.100.2',
		'postfix_server_port' => '25',
	},
	'multi-instance program gate + postscreen enrichment'
);

# anchored rules reject a message with trailing content the pattern cannot consume
$r = $pm->process_item(
	'item' => {
		'PROGRAM' => 'postfix/anvil',
		'MESSAGE' => 'statistics: max connection rate 3/60s for (smtp:192.0.2.5) at Jul 15 10:00:00 TRAILING'
	}
);
is( $r, undef, 'anchored rule rejects a message with trailing garbage' );

done_testing();
