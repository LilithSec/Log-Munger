package Log::Munger::App::Command::grok2rules;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::Degrok ();

sub opt_spec {
	return (
		[ 'f=s',           'Grok patterns file to convert.' ],
		[ 'includes|i=s@', 'Rule file to treat as an include when resolving/overwriting (repeatable).' ],
		[ 'overwrite|o=s', 'Overwrite policy for names already in an include: yes|no_silent|no_warn|no_die.',
			{ default => 'no_warn' } ],
	);
}

sub abstract { "Convert a grok patterns file into a Log::Munger rules YAML skeleton" }

sub description {
	"Runs a grok patterns file through Log::Munger::Degrok->grok2rules (converting %{TOKEN} / "
		. "%{TOKEN:name} to the [% TOKEN %] / (?<name>[% TOKEN %]) forms) and prints the resulting "
		. "rules YAML to stdout.";
}

sub validate { return 1 }

sub execute {
	my ( $self, $opts, $args ) = @_;

	if ( !defined( $opts->{'f'} ) ) {
		die('No grok file specified via -f');
	}

	my %pass = ( 'file' => $opts->{'f'}, 'overwrite' => $opts->{'overwrite'} );
	$pass{'includes'} = $opts->{'includes'} if ( defined( $opts->{'includes'} ) );

	my $yaml;
	eval { $yaml = Log::Munger::Degrok->grok2rules(%pass); };
	if ($@) {
		die( 'Failed to convert "' . $opts->{'f'} . '"... ' . $@ );
	}

	print $yaml;

	return;
} ## end sub execute

1;
