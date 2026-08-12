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

#
# named resolver failures.
#
# These all used to land on the catch-all or, in the RCODE case, on
# NAMED_NET_ERROR with the RCODE buried inside the free-text dns_error. On a
# busy resolver they are the overwhelming majority of the log, so what is
# asserted here is that each one now reaches the pattern that owns it and that
# the shared fields come out the same way across all of them.
#
my $nr = Log::Munger->new( 'rules' => ['named'] );

# an error RCODE is split off ahead of NAMED_NET_ERROR, and dns_error is left
# holding the rest of the phrase so anything keying off it still works
my $rcode = $nr->process_item(
	'item' => { PROGRAM => 'named', MESSAGE => q{REFUSED unexpected RCODE resolving 'example.com/A/IN': 192.0.2.2#53} } );
is( $rcode->{'dns_rcode'},       'REFUSED',          'named: RCODE split out of the error phrase' );
is( $rcode->{'dns_error'},       'unexpected RCODE', 'named: dns_error keeps the rest of the phrase' );
is( $rcode->{'dns_query_name'},  'example.com',      'named: RCODE error query name' );
is( $rcode->{'dns_query_class'}, 'IN',               'named: RCODE error query class' );
is( $rcode->{'dns_src_ip'},      '192.0.2.2',        'named: RCODE error server' );
ok( looks_like_number( $rcode->{'dns_src_port'} ), 'named: RCODE error port is numeric' );

# an error with no RCODE on the front must still reach NAMED_NET_ERROR
my $neterr = $nr->process_item(
	'item' => { PROGRAM => 'named', MESSAGE => q{connection refused resolving 'example.com/A/IN': 192.0.2.2#53} } );
is( $neterr->{'dns_error'}, 'connection refused', 'named: a plain network error still lands on NAMED_NET_ERROR' );
ok( !exists( $neterr->{'dns_rcode'} ), 'named: a plain network error sets no dns_rcode' );

# DNSSEC validation, which carries a view prefix and padding when views are in use
my $dnssec = $nr->process_item(
	'item' => { PROGRAM => 'named', MESSAGE => 'view internal-view:   validating example.com/SOA: no valid signature found' } );
is( $dnssec->{'dns_view'},          'internal-view',            'named: DNSSEC view prefix' );
is( $dnssec->{'dns_query_name'},    'example.com',              'named: DNSSEC query name past the padding' );
is( $dnssec->{'dns_query_type'},    'SOA',                      'named: DNSSEC query type' );
is( $dnssec->{'dns_dnssec_result'}, 'no valid signature found', 'named: DNSSEC result' );

# the viewless wording still works
is( $nr->process_item( 'item' => { PROGRAM => 'named', MESSAGE => 'validating example.com/A: insecurity proof failed' } )->{'dns_dnssec_result'},
	'insecurity proof failed', 'named: DNSSEC without a view prefix' );

# qname minimisation fallback
my $qmin = $nr->process_item( 'item' =>
		{ PROGRAM => 'named', MESSAGE => q{success resolving 'example.com/A' after disabling qname minimization due to 'ncache nxdomain'} } );
is( $qmin->{'dns_qname_min_result'}, 'success',         'named: qname minimisation outcome' );
is( $qmin->{'dns_qname_min_reason'}, 'ncache nxdomain', 'named: qname minimisation reason' );
is( $qmin->{'dns_query_name'},       'example.com',     'named: qname minimisation query name' );

# the remaining resolver failures, each of which sets dns_error to its own phrase
my %error_phrase = (
	q{loop detected resolving 'ns1.example.com/A'}       => 'loop detected',
	q{shut down hung fetch while resolving 'example.com/A'} => 'shut down hung fetch',
);
foreach my $message ( sort keys %error_phrase ) {
	my $got = $nr->process_item( 'item' => { PROGRAM => 'named', MESSAGE => $message } );
	is( $got->{'dns_error'}, $error_phrase{$message}, "named: dns_error for '$error_phrase{$message}'" );
	ok( defined( $got->{'dns_query_name'} ) && defined( $got->{'dns_query_type'} ),
		"named: '$error_phrase{$message}' still names the query" );
}

# DNS cookie trouble, which is the only one of these that names a server
# without naming a query
my $cookie = $nr->process_item( 'item' => { PROGRAM => 'named', MESSAGE => 'missing expected cookie from 192.0.2.2#53' } );
is( $cookie->{'dns_cookie_problem'}, 'missing expected', 'named: cookie problem' );
is( $cookie->{'dns_src_ip'},         '192.0.2.2',        'named: cookie server' );

# interface scanning, whose port is converted like every other port
my $listen = $nr->process_item( 'item' => { PROGRAM => 'named', MESSAGE => 'listening on IPv4 interface em0, 192.0.2.1#53' } );
is( $listen->{'dns_listen_iface'}, 'em0',  'named: listening interface' );
is( $listen->{'dns_listen_family'}, 'IPv4', 'named: listening address family' );
ok( looks_like_number( $listen->{'dns_listen_port'} ), 'named: listening port is numeric' );

# the catch-all is still there for the startup banner
is( $nr->process_item( 'item' => { PROGRAM => 'named', MESSAGE => 'linked to libuv version: 1.52.1' } )->{'dns_message'},
	'linked to libuv version: 1.52.1', 'named: unstructured banner text still kept whole' );

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
	'item' => { PROGRAM => 'su', MESSAGE => 'FAILED SU (to root) neti on pts/0' } );
is( $su->{'su_result'},      'FAILED',  'su: result' );
is( $su->{'su_target_user'}, 'root',    'su: target user' );
is( $su->{'su_by_user'},     'neti', 'su: invoking user' );

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
