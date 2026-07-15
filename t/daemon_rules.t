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

# every shipped daemon rule file must test clean (no errors, full test coverage)
foreach my $file (qw(sshd netfilter dovecot sudo)) {
	my $res = Log::Munger::RulesTest->test( 'file' => $file );
	is( $res->{'fatal'}, undef, "$file: no fatal" );
	is( scalar( @{ $res->{'errors'} } ), 0, "$file: no errors" )
		or diag( join( "\n", @{ $res->{'errors'} } ) );
	is( scalar( grep {/lacks any tests/} @{ $res->{'warnings'} } ), 0, "$file: full test coverage" );
}

# sshd: gate + capture + int coercion
my $sshd = Log::Munger->new( 'rules' => ['sshd'] );
my $s    = $sshd->process_item(
	'item' => { PROGRAM => 'sshd-session', MESSAGE => 'Failed password for invalid user admin from 203.0.113.7 port 44444 ssh2' } );
is( $s->{'ssh_user'},   'admin',       'sshd: user' );
is( $s->{'ssh_method'}, 'password',    'sshd: method' );
is( $s->{'ssh_src_ip'}, '203.0.113.7', 'sshd: src ip' );
cmp_ok( $s->{'ssh_src_port'}, '==', 44444, 'sshd: port value' );
ok( looks_like_number( $s->{'ssh_src_port'} ), 'sshd: port is numeric (convert)' );
is( $sshd->process_item( 'item' => { PROGRAM => 'cron', MESSAGE => 'anything' } ), undef, 'sshd: un-gated program => undef' );

# netfilter: kv decompose + int coercion
my $nf = Log::Munger->new( 'rules' => ['netfilter'] );
my $n  = $nf->process_item(
	'item' => { PROGRAM => 'kernel',
		MESSAGE => '[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=192.0.2.1 LEN=60 TTL=54 ID=1234 PROTO=TCP SPT=44444 DPT=22' } );
is( $n->{'nf_SRC'},    '203.0.113.7', 'netfilter: SRC from kv' );
is( $n->{'nf_PROTO'},  'TCP',         'netfilter: PROTO from kv' );
cmp_ok( $n->{'nf_DPT'}, '==', 22, 'netfilter: DPT value' );
ok( looks_like_number( $n->{'nf_SPT'} ), 'netfilter: SPT is numeric (convert)' );
ok( !exists( $n->{'nf_kv'} ), 'netfilter: kv blob removed' );

# dovecot: kv decompose (comma sep, <> trim) + int coercion
my $dc = Log::Munger->new( 'rules' => ['dovecot'] );
my $d  = $dc->process_item(
	'item' => { PROGRAM => 'dovecot',
		MESSAGE => 'imap-login: Login: user=<kitsune>, method=PLAIN, rip=203.0.113.7, lip=192.0.2.1, mpid=1234, TLS, session=<AbC123>' } );
is( $d->{'dovecot_user'},   'kitsune',     'dovecot: user unwrapped from <>' );
is( $d->{'dovecot_rip'},    '203.0.113.7', 'dovecot: remote ip' );
is( $d->{'dovecot_service'}, 'imap',       'dovecot: service' );
ok( looks_like_number( $d->{'dovecot_mpid'} ), 'dovecot: mpid is numeric (convert)' );

# sudo: kv decompose with a " ; " field split
my $su = Log::Munger->new( 'rules' => ['sudo'] );
my $u  = $su->process_item(
	'item' => { PROGRAM => 'sudo', MESSAGE => 'kitsune : TTY=pts/0 ; PWD=/home/kitsune ; USER=root ; COMMAND=/bin/ls -la' } );
is( $u->{'sudo_user'},    'kitsune',     'sudo: invoking user' );
is( $u->{'sudo_USER'},    'root',        'sudo: target user from kv' );
is( $u->{'sudo_TTY'},     'pts/0',       'sudo: tty from kv' );
is( $u->{'sudo_COMMAND'}, '/bin/ls -la', 'sudo: command from kv' );

# geoip on the flagged source fields (skipped without the reader/db)
SKIP: {
	my $mmdb = 't/mmdb/GeoLite2-Country-Test.mmdb';
	skip 'IP::Geolocation::MMDB not installed', 3 unless eval { require IP::Geolocation::MMDB; 1; };
	skip "test db $mmdb not found",             3 unless -f $mmdb;

	my $line = 'Failed password for root from 81.2.69.142 port 22 ssh2';
	my $gs   = Log::Munger->new( 'rules' => ['sshd'], 'geoip' => $mmdb )->process_item( 'item' => { PROGRAM => 'sshd', MESSAGE => $line } );
	is( $gs->{'geoip'}{'ssh_src_ip'}{'country'}{'iso_code'}, 'GB', 'sshd: geoip on ssh_src_ip' );

	my $gn = Log::Munger->new( 'rules' => ['netfilter'], 'geoip' => $mmdb )->process_item(
		'item' => { PROGRAM => 'kernel', MESSAGE => '[UFW BLOCK] IN=eth0 OUT= SRC=81.2.69.142 DST=192.0.2.1 PROTO=TCP SPT=1 DPT=22' } );
	is( $gn->{'geoip'}{'nf_SRC'}{'country'}{'iso_code'}, 'GB', 'netfilter: geoip on nf_SRC' );

	my $gd = Log::Munger->new( 'rules' => ['dovecot'], 'geoip' => $mmdb )->process_item(
		'item' => { PROGRAM => 'dovecot', MESSAGE => 'imap-login: Login: user=<x>, method=PLAIN, rip=81.2.69.142, lip=192.0.2.1, session=<s>' } );
	is( $gd->{'geoip'}{'dovecot_rip'}{'country'}{'iso_code'}, 'GB', 'dovecot: geoip on dovecot_rip' );
}

done_testing();
