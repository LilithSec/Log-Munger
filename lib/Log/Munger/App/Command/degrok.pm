package Log::Munger::App::Command::degrok;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::Degrok;

sub opt_spec {
	return (
		[ 's=s',  'A string to convert' ],
		[ 'f=s',  'File to convert' ],
		[ 'r',    'Convert to a rules file.' ],
		[ 'i=s@', 'Includes to use.' ],
		[ 'o=s',  'Overwrite setting.' ],
	);
}

sub abstract { "Converts grok style regexp template to perl." }

sub description {
	'Converts grok style regexp template to perl.

Grok uses templating in the form of "%{TEMPLATE}" and capturing templating stuff in the form
of "%{TEMPLATE:VAR}". This is not usable with Log::Munger. This takes that and translates it
"[% TEMPLATE %]" and "(?<VAR>[% TEMPLATE %])" respectively.
';
}

sub validate { return 1 }

sub execute {
	my ( $self, $opts, $args ) = @_;

	if ( !defined( $opts->{'s'} ) && !defined( $opts->{'f'} ) ) {
		die('Either -s or -f need specified');
	} elsif ( defined( $opts->{'s'} ) && defined( $opts->{'f'} ) ) {
		die('-s and -f can not be used together');
	}

	if ( defined( $opts->{'s'} ) ) {
		print Log::Munger::Degrok->string( 'string' => $opts->{'s'} ) . "\n";
	} elsif ( defined( $opts->{'f'} ) ) {
		if ( !-f $opts->{'f'} ) {
			die( '"' . $opts->{'f'} . '" is not a file' );
		} elsif ( !-r $opts->{'f'} ) {
			die( '"' . $opts->{'f'} . '" is not readable' );
		}

		my $results;
		if ( $opts->{'r'} ) {
			$results = Log::Munger::Degrok->grok2rules(
				'file'      => $opts->{'f'},
				'includes'  => $opts->{'i'},
				'overwrite' => $opts->{'o'}
			) . "\n";
		} else {
			$results = Log::Munger::Degrok->file( 'file' => $opts->{'f'} ) . "\n";
		}
		print $results;
	} ## end elsif ( defined( $opts->{'f'} ) )
} ## end sub execute

1;
