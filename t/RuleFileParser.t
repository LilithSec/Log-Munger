#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Log::Munger::RuleFileParser') || print "Bail out!\n";
}

my $tests = 3;

my $worked = 0;
my $parser;
eval {
	$parser=Log::Munger::RuleFileParser->new;
	if (!defined($parser)){
		die ('Log::Munger::RuleFileParser->new returned undef');
	}
	if (ref($parser) ne 'Log::Munger::RuleFileParser'){
		die('returned ref was not "Log::Munger::RuleFileParser" but "'.ref($parser).'"');
	}
	
	$worked = 1;
};
ok( $worked eq '1', 'RulesFileParser new' ) or diag( "Log::Munger::RuleFileParser->new failed ... " . $@ );

$worked = 0;
eval {
	my $rules = $parser->load('file' =>'base');
	
	$worked = 1;
};
ok( $worked eq '1', 'RulesFileParser parse' ) or diag( "Log::Munger::RuleFileParser->parse failed ... " . $@ );

done_testing($tests);
