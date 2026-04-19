package Log::Munger::Degrok;

use 5.006;
use strict;
use warnings;
use Scalar::Util qw(looks_like_number);
use File::Slurp  qw(read_file);

=head1 NAME

Log::Munger::Degrok - Converts grok style regexp template stuff to template stuff usable with Log::Munger

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::Degrok;



Grok uses templating in the form of "%{TEMPLATE}" and capturing templating stuff in the form
of "%{TEMPLATE:VAR}". This is not usable with Log::Munger. This takes that and translates it
"[% TEMPLATE %]" and "(?<VAR>[% TEMPLATE %])" respectively.

=head1 METHODS

=head2 string

Takes a string to process and returns the translated results.

    

=cut

sub string {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'string'} ) ) {
		die('$opts{string} is undef');
	}
	my $string = $opts{'string'};

	if ( !defined( $opts{'max_loops'} ) ) {
		$opts{'max_loops'} = 3000;
	} elsif ( !looks_like_number( $opts{'max_loops'} ) ) {
		die( '$opts{max_loops} is defined, but does not look like a number... value is "' . $opts{'max_loops'} . '"' );
	} elsif ( $opts{'max_loops'} < 1 ) {
		die( '$opts{max_loops} is defined, but is less than 1... value is "' . $opts{'max_loops'} . '"' );
	}

	my $loop_counter  = 1;
	my $loop_continue = 1;
	while ( $loop_continue && ( $loop_counter < $opts{'max_loops'} ) ) {
		if ( $string =~ /(?<GROK>\%\{(?<VAR>[A-Za-z0-9\_]+)(\:(?<CAPTURE>[A-Za-z0-9\_]+))?\})/ ) {
			my %found_items = %+;
			my $replacement_string;
			if ( defined( $found_items{'CAPTURE'} ) ) {
				$replacement_string = '(?<' . $found_items{'CAPTURE'} . '>[% ' . $found_items{'VAR'} . ' %])';
			} else {
				$replacement_string = '[% ' . $found_items{'VAR'} . ' %]';
			}
			my $replacement_regexp = quotemeta( $found_items{'GROK'} );
			$string =~ s/$replacement_regexp/$replacement_string/g;
		} else {
			$loop_continue = 0;
		}

		$loop_counter++;
	} ## end while ( $loop_continue && ( $loop_counter < $opts...))
	if ( $loop_counter > $opts{'max_loops'} ) {
		die(      'Hit max_loops, '
				. $opts{'max_loops'}
				. ', when processing string "'
				. $opts{'string'}
				. '"... either number of replacements exceed '
				. $opts{'max_loops'}
				. ' or there is some sort of problem' );
	}

	return $string;
} ## end sub string

=head2 file

Takes a string to process and returns the translated results.

    

=cut

sub file {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	}

	if ( !defined( $opts{'max_loops'} ) ) {
		$opts{'max_loops'} = 3000;
	} elsif ( !looks_like_number( $opts{'max_loops'} ) ) {
		die( '$opts{max_loops} is defined, but does not look like a number... value is "' . $opts{'max_loops'} . '"' );
	} elsif ( $opts{'max_loops'} < 1 ) {
		die( '$opts{max_loops} is defined, but is less than 1... value is "' . $opts{'max_loops'} . '"' );
	}

	my @lines;
	eval { @lines = read_file( $opts{'file'} ); };
	if ($@) {
		die( 'Failed to read "' . $opts{'file'} . '"... ' . $@ );
	}

	my @processed_lines;
	foreach my $line (@lines){
		$line = Log::Munger::Degrok->string('string' => $line, 'max_loops' => $opts{'max_loops'});
		push(@processed_lines, $line);
	}
	
	return join('', @processed_lines);
} ## end sub file
