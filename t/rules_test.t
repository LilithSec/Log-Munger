#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Log::Munger::RulesTest')       || print "Bail out!\n";
	use_ok('Log::Munger::RuleFileParser')   || print "Bail out!\n";
}

# the shipped postfix rule file dispatches every postfix daemon (23 in the
# canonical logstash set); guard against accidental rule loss
my $pf_rules = Log::Munger::RuleFileParser->new->load( 'file' => 'postfix' );
ok( scalar( @{ $pf_rules->{'rules'} } ) >= 23, 'postfix ships >= 23 dispatch rules' )
	or diag( 'only ' . scalar( @{ $pf_rules->{'rules'} } ) . ' rules' );

#
# The shipped postfix rule file must test clean (no fatal, no errors). Its
# embedded rule tests and the lint both run here.
#
my $res = Log::Munger::RulesTest->test( 'file' => 'postfix' );
is( $res->{'fatal'}, undef, 'postfix: no fatal' );
is( scalar( @{ $res->{'errors'} } ), 0, 'postfix: no errors' )
	or diag( "errors:\n" . join( "\n", @{ $res->{'errors'} } ) );

# full vars_tests coverage: every postfix var must carry tests
my @lacks = grep {/lacks any tests/} @{ $res->{'warnings'} };
is( scalar(@lacks), 0, 'postfix: every var has tests (full coverage)' )
	or diag( "untested:\n" . join( "\n", @lacks ) );

#
# Fatal-path: a missing file returns a results hash with fatal set, not a die.
#
my $missing = Log::Munger::RulesTest->test( 'file' => 'this_rule_file_does_not_exist_xyz' );
ok( defined( $missing->{'fatal'} ), 'missing file yields fatal, not a die' );

#
# A clean synthetic rules hash produces no errors.
#
my $good = {
	'vars'  => { 'GOOD' => '(?<good>\\d+)' },
	'rules' => [
		{   'name'  => 'g',
			'gate'  => [ { 'field' => 'PROGRAM', 'values' => ['x'] } ],
			'field' => 'MESSAGE',
			'patterns' => ['GOOD'],
			'tests'    => {
				'positive' => [ { 'string' => 'abc 123', 'result' => { 'good' => '123' } } ],
				'negative' => ['no digits here'],
			},
		},
	],
};
my $gres = Log::Munger::RulesTest->test( 'hash' => $good );
is( scalar( @{ $gres->{'errors'} } ), 0, 'clean synthetic rules: no errors' )
	or diag( "errors:\n" . join( "\n", @{ $gres->{'errors'} } ) );

#
# The lint must catch: un-degrokked grok, an illegal named capture, a missing
# var reference in patterns, and a positive test that fails to match.
#
my $bad = {
	'vars'  => {
		'BADGROK' => '%{FOO:bar}',
		'BADCAP'  => '(?<has-dash>\\d+)',
	},
	'rules' => [
		{   'name'     => 'r1',
			'gate'     => [ { 'field' => 'PROGRAM', 'values' => ['x'] } ],
			'patterns' => ['MISSINGVAR'],
			'tests'    => {
				'positive' => [ { 'string' => '123', 'result' => { 'good' => '123' } } ],
				'negative' => ['abc'],
			},
		},
	],
};
my $bres  = Log::Munger::RulesTest->test( 'hash' => $bad );
my $joined = join( "\n", @{ $bres->{'errors'} } );
ok( scalar( @{ $bres->{'errors'} } ) > 0, 'bad synthetic rules: errors present' );
like( $joined, qr/un-degrokked grok/,        'lint catches leftover grok' );
like( $joined, qr/illegal named-capture/,    'lint catches illegal capture name' );
like( $joined, qr/looks like a var reference/, 'lint catches missing var reference' );
like( $joined, qr/did not match any pattern/,  'positive test failure reported' );

#
# decompose entries carry their own tests (input -> expected produced fields);
# RulesTest runs them, passing when correct and reporting when wrong.
#
my $dgood = {
	'decompose' => [
		{   'field' => 'kv', 'type' => 'kv', 'prefix' => 'x_', 'trim' => '<>,', 'remove' => 1,
			'tests' => [ { 'input' => 'a=1, b=<two>,', 'result' => { 'x_a' => '1', 'x_b' => 'two' } } ],
		},
	],
};
is( scalar( @{ Log::Munger::RulesTest->test( 'hash' => $dgood )->{'errors'} } ),
	0, 'correct decompose test passes' );

my $dbad = {
	'decompose' => [
		{   'field' => 'kv', 'type' => 'kv', 'prefix' => 'x_', 'remove' => 1,
			'tests' => [ { 'input' => 'a=1', 'result' => { 'x_a' => 'WRONG' } } ],
		},
	],
};
like(
	join( "\n", @{ Log::Munger::RulesTest->test( 'hash' => $dbad )->{'errors'} } ),
	qr/decompose output differs/,
	'wrong decompose test is caught'
);

done_testing();
