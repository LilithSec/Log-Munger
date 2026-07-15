#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Scalar::Util qw(looks_like_number);

BEGIN {
	use_ok('Log::Munger')            || print "Bail out!\n";
	use_ok('Log::Munger::RulesTest') || print "Bail out!\n";
}

# every shipped file tests clean (no errors, full coverage)
foreach my $file (qw(named unbound dnsmasq squid cron pam su)) {
	my $res = Log::Munger::RulesTest->test( 'file' => $file );
	is( $res->{'fatal'}, undef, "$file: no fatal" );
	is( scalar( @{ $res->{'errors'} } ), 0, "$file: no errors" )
		or diag( join( "\n", @{ $res->{'errors'} } ) );
	is( scalar( grep {/lacks any tests/} @{ $res->{'warnings'} } ), 0, "$file: full coverage" );
}

# named: capture + int port
my $n = Log::Munger->new( 'rules' => ['named'] )->process_item(
	'item' => { PROGRAM => 'named', MESSAGE => 'client @0x7f 192.0.2.5#54321 (example.com): query: example.com IN A + (192.0.2.1)' } );
is( $n->{'dns_client_ip'},  '192.0.2.5',   'named: client ip' );
is( $n->{'dns_query_name'}, 'example.com', 'named: query name' );
is( $n->{'dns_query_type'}, 'A',           'named: query type' );
ok( looks_like_number( $n->{'dns_client_port'} ), 'named: port is numeric' );

# unbound
my $u = Log::Munger->new( 'rules' => ['unbound'] )->process_item(
	'item' => { PROGRAM => 'unbound', MESSAGE => 'info: 192.0.2.5 example.com. A IN' } );
is( $u->{'unbound_client_ip'},  '192.0.2.5',    'unbound: client ip' );
is( $u->{'unbound_query_name'}, 'example.com.', 'unbound: query name' );

# dnsmasq (several shapes)
my $dq = Log::Munger->new( 'rules' => ['dnsmasq'] );
is( $dq->process_item( 'item' => { PROGRAM => 'dnsmasq', MESSAGE => 'query[A] example.com from 192.0.2.5' } )->{'dnsmasq_client_ip'},
	'192.0.2.5', 'dnsmasq: query client ip' );
is( $dq->process_item( 'item' => { PROGRAM => 'dnsmasq', MESSAGE => 'reply example.com is 93.184.216.34' } )->{'dnsmasq_result'},
	'93.184.216.34', 'dnsmasq: reply result' );

# squid: raw line, int coercion
my $s = Log::Munger->new( 'rules' => ['squid'] )->process_item(
	'item' => '1626345600.123 234 192.0.2.5 TCP_MISS/200 1234 GET http://example.com/ - DIRECT/93.184.216.34 text/html' );
is( $s->{'squid_client_ip'}, '192.0.2.5', 'squid: client ip (raw line)' );
is( $s->{'squid_method'},    'GET',       'squid: method' );
ok( looks_like_number( $s->{'squid_bytes'} ),  'squid: bytes numeric' );
ok( looks_like_number( $s->{'squid_status'} ), 'squid: status numeric' );

# cron
my $c = Log::Munger->new( 'rules' => ['cron'] )->process_item(
	'item' => { PROGRAM => 'CRON', MESSAGE => '(root) CMD (/usr/bin/foo --flag)' } );
is( $c->{'cron_user'},    'root',              'cron: user' );
is( $c->{'cron_command'}, '/usr/bin/foo --flag', 'cron: command' );

# pam: gateless, kv-decomposed, int uid
my $p = Log::Munger->new( 'rules' => ['pam'] )->process_item(
	'item' => { PROGRAM => 'sshd',
		MESSAGE => 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7 user=root' } );
is( $p->{'pam_service'}, 'sshd',        'pam: service' );
is( $p->{'pam_user'},    'root',        'pam: user (from kv)' );
is( $p->{'pam_rhost'},   '203.0.113.7', 'pam: rhost (from kv)' );
ok( looks_like_number( $p->{'pam_uid'} ), 'pam: uid numeric' );
ok( !exists( $p->{'pam_kv'} ), 'pam: kv blob removed' );

# su
my $su = Log::Munger->new( 'rules' => ['su'] )->process_item(
	'item' => { PROGRAM => 'su', MESSAGE => 'FAILED SU (to root) kitsune on pts/0' } );
is( $su->{'su_result'},      'FAILED',  'su: result' );
is( $su->{'su_target_user'}, 'root',    'su: target user' );
is( $su->{'su_by_user'},     'kitsune', 'su: invoking user' );

# geoip on the flagged source fields
SKIP: {
	my $mmdb = 't/mmdb/GeoLite2-Country-Test.mmdb';
	skip 'IP::Geolocation::MMDB not installed', 3 unless eval { require IP::Geolocation::MMDB; 1; };
	skip "test db $mmdb not found",             3 unless -f $mmdb;

	my $gn = Log::Munger->new( 'rules' => ['named'], 'geoip' => $mmdb )->process_item(
		'item' => { PROGRAM => 'named', MESSAGE => 'client 81.2.69.142#5 (x): query: x IN A + (192.0.2.1)' } );
	is( $gn->{'geoip'}{'dns_client_ip'}{'country'}{'iso_code'}, 'GB', 'named: geoip on dns_client_ip' );

	my $gsq = Log::Munger->new( 'rules' => ['squid'], 'geoip' => $mmdb )->process_item(
		'item' => '1.0 1 81.2.69.142 TCP_MISS/200 1 GET http://x/ - DIRECT/1.2.3.4 text/html' );
	is( $gsq->{'geoip'}{'squid_client_ip'}{'country'}{'iso_code'}, 'GB', 'squid: geoip on squid_client_ip' );

	my $gp = Log::Munger->new( 'rules' => ['pam'], 'geoip' => $mmdb )->process_item(
		'item' => { PROGRAM => 'sshd',
			MESSAGE => 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=81.2.69.142 user=root' } );
	is( $gp->{'geoip'}{'pam_rhost'}{'country'}{'iso_code'}, 'GB', 'pam: geoip on pam_rhost' );
}

done_testing();
