package Log::Munger::App::Command::which_rule_file;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::WhichRuleFile;

sub opt_spec {
	return ( [ 'f=s', 'Rule file to locate.' ], );
}

sub abstract { "Returns the path to the specified rule file." }

sub description {
	"Returns the path to the specified rule file.

exit
255, error
1, not found
0, found
";
}

sub validate { return 1 }

sub execute {
	my ( $self, $opts, $args ) = @_;

	if ( !defined( $opts->{'f'} ) ) {
		die('Nothing specified for -f');
	}

	my $file_location = Log::Munger::WhichRuleFile->rule_file_location( 'file' => $opts->{'f'} );

	if ( !defined($file_location) ) {
		exit 1;
	}

	print $file_location. "\n";

	exit 0;
} ## end sub execute

1;
