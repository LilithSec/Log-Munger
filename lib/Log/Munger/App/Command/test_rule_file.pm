package Log::Munger::App::Command::test_rule_file;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::RulesTest;
use YAML::XS qw(Dump);

sub opt_spec {
	return ( [ 'f=s', 'Rule file to read.', { 'default' => 'base' } ], );
}

sub abstract { "Reads in the specified rule file and dumps it to stdout" }

sub description { "Reads in the specified rule file and dumps it to stdout" }

sub validate { return 1 }

sub execute {
	my ( $self, $opts, $args ) = @_;

	my $rules  = Log::Munger::RulesTest->test( 'file' => $opts->{'f'} );

	print Dump($rules);

}

1;
