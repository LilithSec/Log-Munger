#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Log::Munger')            || print "Bail out!\n";
	use_ok('Log::Munger::RulesTest') || print "Bail out!\n";
}

# the shipped rule file must test clean
my $res = Log::Munger::RulesTest->test( 'file' => 'http_access_logs' );
is( $res->{'fatal'}, undef, 'http_access_logs: no fatal' );
is( scalar( @{ $res->{'errors'} } ), 0, 'http_access_logs: no errors' )
	or diag( join( "\n", @{ $res->{'errors'} } ) );
my @lacks = grep {/lacks any tests/} @{ $res->{'warnings'} };
is( scalar(@lacks), 0, 'http_access_logs: full coverage' ) or diag( join( "\n", @lacks ) );

my $m = Log::Munger->new( 'rules' => ['http_access_logs'] );
isa_ok( $m, 'Log::Munger' );

# a raw combined line fed straight in as a string (no wrapping hash)
my $combined
	= '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 '
	. '"http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"';
is_deeply(
	$m->process_item( 'item' => $combined ),
	{   http_clientip   => '127.0.0.1',
		http_ident      => '-',
		http_auth       => 'frank',
		http_timestamp  => '10/Oct/2000:13:55:36 -0700',
		http_verb       => 'GET',
		http_request    => '/apache_pb.gif',
		http_httpversion => '1.0',
		http_response   => '200',
		http_bytes      => '2326',
		http_referrer   => 'http://www.example.com/start.html',
		http_agent      => 'Mozilla/4.08 [en] (Win98; I ;Nav)',
	},
	'raw combined access line enriches (string item)'
);

# a plain Common Log Format line via a MESSAGE hash (syslog-style delivery)
is_deeply(
	$m->process_item( 'item' => { MESSAGE => '192.168.1.1 - - [12/Jul/2026:08:15:50 +0000] "GET / HTTP/1.1" 304 -' } ),
	{   http_clientip   => '192.168.1.1',
		http_ident      => '-',
		http_auth       => '-',
		http_timestamp  => '12/Jul/2026:08:15:50 +0000',
		http_verb       => 'GET',
		http_request    => '/',
		http_httpversion => '1.1',
		http_response   => '304',
	},
	'common log format via MESSAGE hash ("-" bytes omitted)'
);

# non-access text does not match
is( $m->process_item( 'item' => 'just some noise' ), undef, 'non-access line => undef' );

done_testing();
