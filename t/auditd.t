#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Scalar::Util qw(looks_like_number);

BEGIN {
	use_ok('Log::Munger')              || print "Bail out!\n";
	use_ok('Log::Munger::LogProcessor') || print "Bail out!\n";
	use_ok('Log::Munger::RulesTest')    || print "Bail out!\n";
}

# ---- the quote-aware kv mechanism in isolation (both quote styles, spaces) ----
my $c = Log::Munger::LogProcessor->_compile_decompose(
	[ { field => 'blob', type => 'kv', quoted => 1, prefix => 'k_', remove => 1 } ], {} );
my %caps = (
	blob => q{a="two words" b='single spaced' c=bare:word d="" e=} . q{'x'} . q{ f=203.0.113.7} );
Log::Munger::LogProcessor->_decompose( { decompose => $c }, \%caps );
is( $caps{'k_a'}, 'two words',     'quoted kv: double quotes keep the space' );
is( $caps{'k_b'}, 'single spaced', 'quoted kv: single quotes keep the space' );
is( $caps{'k_c'}, 'bare:word',     'quoted kv: bareword' );
is( $caps{'k_d'}, '',              'quoted kv: empty quoted value' );
is( $caps{'k_e'}, 'x',             'quoted kv: single-quoted short value' );
is( $caps{'k_f'}, '203.0.113.7',   'quoted kv: bareword ip' );
ok( !exists( $caps{'blob'} ), 'quoted kv: source removed' );

# ---- the shipped auditd file ----
my $res = Log::Munger::RulesTest->test( 'file' => 'auditd' );
is( $res->{'fatal'}, undef, 'auditd: no fatal' );
is( scalar( @{ $res->{'errors'} } ), 0, 'auditd: no errors' )
	or diag( join( "\n", @{ $res->{'errors'} } ) );
is( scalar( grep {/lacks any tests/} @{ $res->{'warnings'} } ), 0, 'auditd: full coverage' );

my $m = Log::Munger->new( 'rules' => ['auditd'] );

# SYSCALL: outer quoted kv (incl. key="watch exec" with a space) + convert
my $s = $m->process_item(
	'item' => 'type=SYSCALL msg=audit(1626345600.123:456): arch=c000003e syscall=59 exit=0 '
		. 'pid=5678 uid=0 ses=3 comm="ls" exe="/usr/bin/ls" key="watch exec"' );
is( $s->{'audit_type'}, 'SYSCALL',     'auditd: type' );
is( $s->{'audit_comm'}, 'ls',          'auditd: comm from quoted kv' );
is( $s->{'audit_key'},  'watch exec',  'auditd: quoted value with a space kept intact' );
ok( looks_like_number( $s->{'audit_pid'} ),   'auditd: pid is numeric' );
ok( looks_like_number( $s->{'audit_serial'} ), 'auditd: serial is numeric' );
ok( looks_like_number( $s->{'audit_epoch'} ),  'auditd: epoch is numeric (float)' );
ok( !exists( $s->{'audit_fields'} ), 'auditd: outer blob removed' );

# USER_AUTH: nested single-quoted msg with double-quoted values inside
my $u = $m->process_item(
	'item' => q{type=USER_AUTH msg=audit(1626345600.123:457): pid=1234 uid=0 ses=3 }
		. q{msg='op=PAM:authentication acct="root" exe="/usr/sbin/sshd" hostname=h addr=203.0.113.7 terminal=ssh res=failed'} );
is( $u->{'audit_type'},        'USER_AUTH',          'auditd: user_auth type' );
is( $u->{'audit_msg_op'},      'PAM:authentication', 'auditd: nested op' );
is( $u->{'audit_msg_acct'},    'root',               'auditd: nested acct (double-quoted inside single-quoted)' );
is( $u->{'audit_msg_addr'},    '203.0.113.7',        'auditd: nested addr' );
is( $u->{'audit_msg_res'},     'failed',             'auditd: nested res' );
ok( !exists( $u->{'audit_msg'} ),    'auditd: nested blob removed' );
ok( !exists( $u->{'audit_fields'} ), 'auditd: outer blob removed on user record' );

# non-auditd line
is( $m->process_item( 'item' => 'not an audit record' ), undef, 'auditd: non-record => undef' );

# geoip on the nested addr
SKIP: {
	my $mmdb = 't/mmdb/GeoLite2-Country-Test.mmdb';
	skip 'IP::Geolocation::MMDB not installed', 1 unless eval { require IP::Geolocation::MMDB; 1; };
	skip "test db $mmdb not found",             1 unless -f $mmdb;
	my $g = Log::Munger->new( 'rules' => ['auditd'], 'geoip' => $mmdb )->process_item(
		'item' => q{type=USER_AUTH msg=audit(1:2): pid=1 msg='op=login acct="root" addr=81.2.69.142 res=success'} );
	is( $g->{'geoip'}{'audit_msg_addr'}{'country'}{'iso_code'}, 'GB', 'auditd: geoip on nested addr' );
}

done_testing();
