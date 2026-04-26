package Log::Munger::Degrok;

use 5.006;
use strict;
use warnings;
use Scalar::Util qw(looks_like_number);
use File::Slurp  qw(read_file);
use Hash::Merge  ();
use YAML::XS qw(Dump);

=head1 NAME

Log::Munger::Degrok - Converts grok style regexp template stuff to template stuff usable with Log::Munger

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::Degrok;

    if ( defined( $opts->{'s'} ) ) {
        print Log::Munger::Degrok->string( 'string' => $opts->{'s'} ) . "\n";
    } elsif ( defined( $opts->{'f'} ) ) {
        if (! -f $opts->{'f'} ){
            die('"'.$opts->{'f'}.'" is not a file');
        }elsif(! -r $opts->{'f'} ){
            die('"'.$opts->{'f'}.'" is not readable');
        }

        print Log::Munger::Degrok->file( 'file' => $opts->{'f'} ) . "\n";
    }

Grok uses templating in the form of "%{TEMPLATE}" and capturing templating stuff in the form
of "%{TEMPLATE:VAR}". This is not usable with Log::Munger. This takes that and translates it
"[% TEMPLATE %]" and "(?<VAR>[% TEMPLATE %])" respectively.

=head1 METHODS

=head2 string

Takes a string to process and returns the translated results.

    - string :: The string to convert.
        default :: undef

    my $results;
    eval {
        my $results = Log::Munger::Degrok->string( 'file' => $some_string ) . "\n";
    };
    if ($@){
        die('Failed to process the string "'.$some_string.'"... '.$@);
    }
    print $results."\n";

=cut

sub string {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'string'} ) ) {
		die('$opts{string} is undef');
	}
	my $string = $opts{'string'};

	my $loop_continue = 1;
	while ($loop_continue) {
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
	} ## end while ($loop_continue)

	return $string;
} ## end sub string

=head2 file

Takes a file to process and returns the translated results.

    - file :: The file to convert.
        default :: undef

    my $results;
    my $file = '/tmp/some_file';
    eval {
        Log::Munger::Degrok->file( 'file' => $file ) . "\n";
    };
    if ($@){
        die('Failed to process "'.$file.'"... '.$@);
    }
    print $results."\n";

=cut

sub file {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	}

	my @lines;
	eval { @lines = read_file( $opts{'file'} ); };
	if ($@) {
		die( 'Failed to read "' . $opts{'file'} . '"... ' . $@ );
	}

	my @processed_lines;
	foreach my $line (@lines) {
		$line = Log::Munger::Degrok->string( 'string' => $line, 'max_loops' => $opts{'max_loops'} );
		push( @processed_lines, $line );
	}

	return join( '', @processed_lines );
} ## end sub file

=head2 grok2rules

Takes a file to process and returns the translated results.

    - file :: The file to convert.
        default :: undef

    - includes :: Rules includes to include to use. The taken value is a array.
        default :: []

    - overwrite :: Overwrite value for if something is already defined by a include.
        values :: ...
            - yes :: Always overwrite.
            - no_silent :: Silently ignore overwrites.
            - no_warn ::  Warn on overwrites.
            - no_die :: Die on overwrites.
        default :: no_warn

    - overwrite_ignore_if_same :: If the warn/die should trigger if overwrite is set to no_warn or no_die.
        default :: 1

    use YAML::XS;
    my $results;
    my $file = '/tmp/some_file';
    eval {
        $results = Log::Munger::Degrok->string( 'file' => $file, incldues=>['base'], ) . "\n";
    };
    if ($@){
        die('Failed to process "'.$file.'"... '.$@);
    }
    print Dumper($results);

=cut

sub grok2rules {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	}

	my $overwrite_types = {
		'yes'       => 1,
		'no_die'    => 1,
		'no_warn'   => 1,
		'no_wilent' => 1,
	};

	if ( !defined( $opts{'overwrite'} ) ) {
		$opts{'overwrite'} = 'no_warn';
	} elsif ( ref( $opts{'overwrite'} ) ne '' ) {
		die( '$opts{overwrite} is specified but has a ref of "' . ref( $opts{'overwrite'} ) . '" instead of ""' );
	} elsif ( !$overwrite_types->{ $opts{'overwrite'} } ) {
		die(      '$opts{overwrite} has a value of "'
				. $opts{'overwrite'}
				. '"... expected values: '
				. join( ', ', sort( keys( %{$overwrite_types} ) ) ) );
	}

	# the rules file being generated
	my $rules = {};

	my $includes = { 'vars' => {}, 'vars_templated' => {} };
	if ( defined( $opts{'includes'} )
		&& ( ref( $opts{'includes'} ) ne 'ARRAY' ) )
	{
		die( '$opts{includes} is specified but has a ref of "' . ref( $opts{'includes'} ) . '" instead of "ARRAY"' );
	} else {
		if ( defined( $opts{'includes'}[0] ) ) {
			$rules->{'includes'} = [];

			my $merger = Hash::Merge->new('RIGHT_PRECEDENT');
			my $parser = Log::Munger::RuleFileParser->new;

			# use a while loop instead of foreach for basically simplifying display of errors
			my $include_int = 0;
			while ( defined( $opts{'includes'}[$include_int] ) ) {
				my $include = $opts{'includes'}[$include_int];
				if ( ref($include) ne '' ) {
					die( '$opts{includes}[' . $include_int . '] has a ref of "' . ref($include) . '" and not ""' );
				}

				push( @{ $rules->{'includes'} }, $include );

				my $include_rules;
				eval { $include_rules = $parser->load( 'file' => $include ); };
				if ($@) {
					die( '$opts{includes}[' . $include_int . '], "' . $include . '", could not be loaded... ' . $@ );
				}

				$includes = $merger->merge( $includes, $include_rules );

				$include_int++;
			} ## end while ( defined( $opts{'includes'}[$include_int...]))
		} ## end if ( defined( $opts{'includes'}[0] ) )
	} ## end else [ if ( defined( $opts{'includes'} ) && ( ref...))]

	my @lines;
	eval { @lines = grep( !/(^#|^\w*$)/, read_file( $opts{'file'} ) ); };
	if ($@) {
		die( 'Failed to read "' . $opts{'file'} . '"... ' . $@ );
	}

	foreach my $line (@lines) {
		my ( $var, $regexp ) = split( /[\ \t]+/, $line, 2 );
		# If we don't have $regexp, there is almost certainly something wrong with that line
		# It is not useful and likely should be removed.
		if ( !defined($regexp) ) {
			die(      'The line "'
					. $line
					. '" could not be split via /\w+/ meaning there is likely something wrong with this line as there is no regexp for the variable'
			);
		}

		my $process_line = 1;
		if (   ( ( $opts{'overwrite'} ne 'yes' ) && ( $opts{'overwrite'} ne 'no_silent' ) )
			&& ( defined( $includes->{'vars'}{$var} ) || defined( $includes->{'vars_templated'}{$var} ) ) )
		{
			if ( defined( $includes->{'vars'}{$var} ) ) {
				if ( $opts{'overwrite'} eq 'no_warn' ) {
					warn( '".var.' . $var . '" is already defined in one of the includes... skipping...' );
					$process_line = 0;
				} elsif ( $opts{'overwrite'} eq 'no_die' ) {
					die( '".var.' . $var . '" is already defined in one of the includes' );
				}
			} elsif ( defined( $includes->{'vars_templated'}{$var} ) ) {
				if ( $opts{'overwrite'} eq 'no_warn' ) {
					warn( '".var_templated.' . $var . '" is already defined in one of the includes... skipping...' );
					$process_line = 0;
				} elsif ( $opts{'overwrite'} eq 'no_die' ) {
					die( '".var_templated.' . $var . '" is already defined in one of the includes' );
				}
			}
		} elsif ( ( $opts{'overwrite'} eq 'no_silent' )
			&& ( defined( $includes->{'vars'}{$var} ) || defined( $includes->{'vars_templated'}{$var} ) ) )
		{
			$process_line = 0;
		}

		if ($process_line){
			if ( $regexp =~ /(?<GROK>\%\{(?<VAR>[A-Za-z0-9\_]+)(\:(?<CAPTURE>[A-Za-z0-9\_]+))?\})/ ) {
				eval {
					$regexp = Log::Munger::Degrok->string('string' => $regexp);
				};
				if ($@) {
					die( 'Failed to process line "' . $line . '"... ' . $@ );
				}
				$rules->{'vars_templated'}{$var} = $regexp;
			}else{
				$rules->{'vars'}{$var} = $regexp;
			}
		}

	} ## end foreach my $line (@lines)

	return Dump($rules);
} ## end sub grok2rules
