#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

my $mmdb = 't/mmdb/GeoLite2-Country-Test.mmdb';

plan skip_all => 'IP::Geolocation::MMDB is not installed'
	unless eval { require IP::Geolocation::MMDB; 1; };
plan skip_all => "test database $mmdb not found"
	unless -f $mmdb;

use_ok('Log::Munger') || print "Bail out!\n";

# geoip enrichment on a flagged field (http_clientip) using a known test IP
my $m = Log::Munger->new( 'rules' => ['http_access_logs'], 'geoip' => $mmdb );
my $line = '81.2.69.142 - - [15/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8"';
my $r    = $m->process_item( 'item' => $line );

ok( defined($r), 'access line matched' );
is( $r->{'http_clientip'}, '81.2.69.142', 'client ip captured' );
ok( exists( $r->{'geoip'} ), 'geoip key present in result' );
is( ref( $r->{'geoip'} ), 'HASH', 'geoip is a hash keyed by field name' );
is( $r->{'geoip'}{'http_clientip'}{'country'}{'iso_code'},
	'GB', 'geoip goes under .geoip.$field and resolves the country' );

# a private / absent address yields no geoip entry (and never dies)
my $priv = $m->process_item(
	'item' => '10.0.0.1 - - [15/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8"' );
ok( defined($priv), 'private-ip line still matched' );
ok( !exists( $priv->{'geoip'} ), 'private/absent ip => no geoip entry' );

# without a geoip database, no geoip enrichment happens at all
my $nodb = Log::Munger->new( 'rules' => ['http_access_logs'] );
my $r2   = $nodb->process_item( 'item' => $line );
ok( defined($r2) && !exists( $r2->{'geoip'} ), 'no geoip database => no geoip key' );

# the error-log file's flagged nginx client_ip is enriched too
my $me = Log::Munger->new( 'rules' => ['http_error_logs'], 'geoip' => $mmdb );
my $re = $me->process_item( 'item' =>
		'2026/07/15 09:01:02 [error] 42#0: *5 boom, client: 81.2.69.142, server: x, request: "GET / HTTP/1.1", host: "x"'
);
is( $re->{'geoip'}{'http_error_client_ip'}{'country'}{'iso_code'},
	'GB', 'nginx error client_ip enriched under .geoip' );

# postfix file-level geoip default flags postfix_client_ip
my $mp = Log::Munger->new( 'rules' => [ 'base', 'postfix' ], 'geoip' => $mmdb );
my $rp = $mp->process_item( 'item' => { PROGRAM => 'postfix/smtpd', MESSAGE => 'connect from mail.example.com[81.2.69.142]' } );
is( $rp->{'geoip'}{'postfix_client_ip'}{'country'}{'iso_code'},
	'GB', 'postfix file-level geoip default enriches postfix_client_ip' );

done_testing();
