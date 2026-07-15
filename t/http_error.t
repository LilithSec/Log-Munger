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
my $res = Log::Munger::RulesTest->test( 'file' => 'http_error_logs' );
is( $res->{'fatal'}, undef, 'http_error_logs: no fatal' );
is( scalar( @{ $res->{'errors'} } ), 0, 'http_error_logs: no errors' )
	or diag( join( "\n", @{ $res->{'errors'} } ) );
my @lacks = grep {/lacks any tests/} @{ $res->{'warnings'} };
is( scalar(@lacks), 0, 'http_error_logs: full coverage' ) or diag( join( "\n", @lacks ) );

my $m = Log::Munger->new( 'rules' => ['http_error_logs'] );
isa_ok( $m, 'Log::Munger' );

# apache 2.4 error line fed straight in as a raw string
is_deeply(
	$m->process_item(
		'item' => '[Wed Oct 11 14:32:52.123456 2000] [core:error] [pid 12345:tid 140234] '
			. '[client 192.168.1.1:1234] AH00128: File does not exist: /var/www/html/favicon.ico'
	),
	{   http_error_timestamp   => 'Wed Oct 11 14:32:52.123456 2000',
		http_error_module      => 'core',
		http_error_loglevel    => 'error',
		http_error_pid         => '12345',
		http_error_tid         => '140234',
		http_error_client_ip   => '192.168.1.1',
		http_error_client_port => '1234',
		http_error_code        => 'AH00128',
		http_error_message     => 'File does not exist: /var/www/html/favicon.ico',
	},
	'apache 2.4 error line enriches (raw string)'
);

# nginx error with the structured tail, via a MESSAGE hash
is_deeply(
	$m->process_item(
		'item' => {
			MESSAGE => '2000/10/11 14:32:52 [error] 12345#0: *67 open() "/x" failed (2: No such file or directory)'
				. ', client: 192.168.1.1, server: example.com, request: "GET /favicon.ico HTTP/1.1", host: "example.com"'
		}
	),
	{   http_error_timestamp    => '2000/10/11 14:32:52',
		http_error_loglevel     => 'error',
		http_error_pid          => '12345',
		http_error_tid          => '0',
		http_error_connectionid => '67',
		http_error_message      => 'open() "/x" failed (2: No such file or directory)',
		http_error_client_ip    => '192.168.1.1',
		http_error_server       => 'example.com',
		http_error_request      => 'GET /favicon.ico HTTP/1.1',
		http_error_host         => 'example.com',
	},
	'nginx error line enriches with structured tail'
);

# an access-log line is not an error line
is( $m->process_item( 'item' => '127.0.0.1 - - [12/Jul/2026:08:15:50 +0000] "GET / HTTP/1.1" 200 12' ),
	undef, 'access line => undef under error rules' );

done_testing();
