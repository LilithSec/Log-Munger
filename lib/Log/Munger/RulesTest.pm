package Log::Munger::RulesTest;

use 5.006;
use strict;
use warnings;
use Template;
use Log::Munger::RuleFileParser;

=head1 NAME

Log::Munger::RulesTest - 

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::WhichRuleFile;

    my $file_location = Log::Munger::WhichRuleFile->rule_file_location('file'=>'postfix');
    if (!defined($file_location)) {
        print "Not found.\n";
    } else {
        print 'File Location: ' . $file_location . "\n";
    }

=head1 METHODS

=head2 test

Test a rules file using the built in tests for the rules file and check for
possible errors.

Either the arg file or hash need to be specified. As long as those are, this
should not die.

    - file :: The file to locate and load for testing.
        Default :: undef

    - hash :: A rules file hash to test.
        Default :: undef

    my $results = Log::Munger::WhichRuleFile->('file'=>'postfix');
    if (defined($results->{'fatal'})) {
        print "File could not be loaded... ".$results->{'fatal'}
    }else{
        if (defined($results->{'errors'}[0])) {
            print "Errors:\n".join("\n", @{ $results->{'errors'}[0] })."\n\n";
        }
        if (defined($results->{'warnings'}[0])) {
            print "Warnings:\n".join("\n", @{ $results->{'Warnings'}[0] })."\n\n";
        }
    }

=cut

sub test {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'hash'} ) && !defined( $opts{'file'} ) ) {
		die('$opts{hash} and $opts{hash} is undef and one needs to be');
	} elsif ( defined( $opts{'hash'} ) && defined( $opts{'file'} ) ) {
		die('$opts{hash} and $opts{hash} is both defined and only one should be');
	} elsif ( defined( $opts{'hash'} ) && ref( $opts{'hash'} ) ne 'HASH' ) {
		die( '$opts{hash} has a ref of "' . ref( $opts{'hash'} ) . '" and not "HASH"' );
	} elsif ( defined( $opts{'file'} ) && ref( $opts{'file'} ) ne '' ) {
		die( '$opts{file} has a ref of "' . ref( $opts{'file'} ) . '" and not ""' );
	}

	if ( defined( $opts{'file'} ) ) {
		eval {
			my $parser = Log::Munger::RuleFileParser->new;
			$opts{'hash'} = $parser->load( 'file' => $opts{'file'} );
		};
		if ($@) {
			my $results = {
				'fatal'    => '"' . $opts{'file'} . '" could not be loaded... ' . $@,
				'errors'   => [],
				'warnings' => [],
			};
		}
	} ## end if ( defined( $opts{'file'} ) )

	my $rules = $opts{'hash'};

	my @errors;
	my @warnings;

	my $vars_testable = 0;
	if ( defined( $rules->{'vars'} ) ) {
		if ( ref( $rules->{'vars'} ) eq 'HASH' ) {
			$vars_testable = 1;
		} else {
			push( @errors, '.vars has a ref of "' . ref( $rules->{'vars'} ) . '" and not "HASH"' );
		}
	} else {
		push( @warnings, '.vars is undef' );
	}

	my $has_var_tests = 0;
	if ( defined( $rules->{'vars_tests'} ) ) {
		if ( ref( $rules->{'vars_tests'} ) eq 'HASH' ) {
			$has_var_tests = 1;
		} else {
			push( @errors, '.vars_tests has a ref of "' . ref( $rules->{'vars_tests'} ) . '" and not "HASH"' );
		}
	} elsif ( defined( $rules->{'vars'} ) ) {
		push( @warnings, '.vars_tests is undef even through .vars exists, meaning there are no tests for it' );
	}

	##
	## process everything under .vars_tests
	##
	if ( $has_var_tests && $vars_testable ) {
		# used for later checking for vars with out tests
		my %tested_vars;
		my $tt = Template->new();
		foreach my $var ( keys( %{ $rules->{'vars_tests'} } ) ) {
			$tested_vars{$var} = 1;

			if (   ( ref( $rules->{'vars_tests'}{$var} ) eq 'HASH' )
				&& defined( $rules->{'vars'}{$var} )
				&& ( ref( $rules->{'vars'}{$var} ) eq '' ) )
			{
				my $test_regex;
				if ( defined( $rules->{'vars_tests'}{$var}{'test_template'} )
					&& ( ref( $rules->{'vars_tests'}{$var}{'test_template'} ) eq '' ) )
				{
					#
					# if .vars_tests.$var.text_template exists, attempt to template it and proceed with tests
					#
					eval {
						$tt->process(
							\$rules->{'vars_tests'}{$var}{'test_template'},
							{ 'TEST_VAR' => $rules->{'vars'}{$var} },
							\$test_regex
						) || die( $tt->error() );
					};
					if ($@) {
						push( @errors, '.vars_tests.' . $var . 'test_template could not be templated...' . $@ );
					} else {
						#
						# handle positive tests
						# lack of positive tests should be considered an error as
						#
						if ( !defined( $rules->{'vars_tests'}{$var}{'positive'} ) ) {
							push( @errors, '.vars_tests.' . $var . '.positive is undef' );
						} elsif ( defined( $rules->{'vars_tests'}{$var}{'positive'} )
							&& ( ref( $rules->{'vars_tests'}{$var}{'positive'} ) ne 'ARRAY' ) )
						{
							push( @errors,
									  '.vars_tests.'
									. $var
									. '.positive has a ref of "'
									. ref( $rules->{'vars_tests'}{$var}{'positive'} )
									. '" and not "ARRAY"' );
						} elsif ( defined( $rules->{'vars_tests'}{$var}{'positive'} )
							&& ( ref( $rules->{'vars_tests'}{$var}{'positive'} ) ne 'ARRAY' )
							&& defined( $rules->{'vars_tests'}{$var}{'positive'}[0] ) )
						{
							push( @errors,
									  '.vars_tests.'
									. $var
									. '.positive has a ref of "'
									. ref( $rules->{'vars_tests'}{$var}{'positive'} )
									. '" and not "ARRAY"' );
						} else {
							# any tests that prevent the positive section from being processed should come before now
							#
							# actually process the tests now
							#
							my $test_int = 0;
							while ( defined( $rules->{'vars_tests'}{$var}{'positive'}[$test_int] ) ) {
								if ( ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int] ) ne 'HASH' ) {
									push( @errors,
											  '.vars_tests.'
											. $var
											. 'positive.'
											. $test_int
											. ' has a ref of "'
											. ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int] )
											. '" and not "HASH"' );
								} elsif ( !defined( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'} ) ) {
									push( @errors,
										'.vars_tests.' . $var . 'positive.' . $test_int . '.string is undef' );
								} elsif ( ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'} ) ne '' ) {
									push( @errors,
											  '.vars_tests.'
											. $var
											. 'positive.'
											. $test_int
											. '.string has a ref of "'
											. ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'} )
											. '" and not ""' );
								} elsif ( !defined( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'} ) ) {
									push( @errors,
										'.vars_tests.' . $var . 'positive.' . $test_int . '.result is undef' );
								} elsif ( ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'} ) ne '' ) {
									push( @errors,
											  '.vars_tests.'
											. $var
											. '.positive.'
											. $test_int
											. '.result has a ref of "'
											. ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'} )
											. '" and not ""' );
								} else {
									if ( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'}
										=~ /$test_regex/ )
									{
										my %found_items = %+;
										if ( !defined( $found_items{'TEST'} ) ) {
											push( @errors,
													  '.var_tests.'
													. $var
													. '.positive.'
													. $test_int
													. ' did but "TEST" not found... test_regex="'
													. $test_regex
													. '" string="'
													. $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'}
													. '" expected result="'
													. $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'}
													. '"' );
										} elsif ( $found_items{'TEST'} ne
											$rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'} )
										{
											push( @errors,
													  '.var_tests.'
													. $var
													. '.positive.'
													. $test_int
													. ' did but "TEST" found a incorrect result of "'
													. $found_items{'TEST'}
													. '"... test_regex="'
													. $test_regex
													. '" string="'
													. $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'}
													. '" expected result="'
													. $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'}
													. '"' );
										} ## end elsif ( $found_items{'TEST'} ne $rules->{'vars_tests'...})
									} ## end if ( $rules->{'vars_tests'}{$var}{'positive'...})
								} ## end else [ if ( ref( $rules->{'vars_tests'}{$var}{'positive'...}))]

								$test_int++;
							} ## end while ( defined( $rules->{'vars_tests'}{$var}...))

						} ## end else [ if ( !defined( $rules->{'vars_tests'}{$var...}))]

						#
						# handle negative tests
						#
						if ( !defined( $rules->{'vars_tests'}{$var}{'negative'} ) ) {
							push( @errors, '.vars_tests.' . $var . '.negative is undef' );
						} elsif ( ref( $rules->{'vars_tests'}{$var}{'negative'} ) ne 'ARRAY' ) {
							push( @errors,
									  '.vars_tests.'
									. $var
									. '.negative is has a ref of "'
									. ref( $rules->{'vars_tests'}{$var}{'negative'} )
									. '" and not "ARRAY"' );
						} else {
							# any tests that prevent the negative section from being processed should come before now
							#
							# actually process the tests now
							#
							my $test_int = 0;
							while ( defined( $rules->{'vars_tests'}{$var}{'negative'}[$test_int] ) ) {
								if ( ref( $rules->{'vars_tests'}{$var}{'negative'}[$test_int] ) ne '' ) {
									push( @errors,
											  '.vars_tests.'
											. $var
											. '.negative.'
											. $test_int
											. ' is has a ref of "'
											. ref( $rules->{'vars_tests'}{$var}{'negative'}[$test_int] )
										  . '" and not ""' );
								} else {
									if ( $rules->{'vars_tests'}{$var}{'negative'}[$test_int]
										=~ /$test_regex/ )
									{
										my %found_items = %+;
										if ( !defined( $found_items{'TEST'} ) ) {
											push( @warnings,
													  '.var_tests.'
													. $var
													. '.negative.'
													. $test_int
													. ' matched but TEST was not found... possible error... test_regex="'
													. $test_regex
													. '" string="'
													. $rules->{'vars_tests'}{$var}{'negative'}[$test_int]
													. '"' );
										} else {
											push( @errors,
													  '.var_tests.'
													. $var
													. '.negative.'
													. $test_int
													. ' matched with TEST having a value of "'
													. $found_items{'TEST'}
													. '"... test_regex="'
													. $test_regex
													. '" string="'
													. $rules->{'vars_tests'}{$var}{'negative'}[$test_int]
													. '"' );
										} ## end else [ if ( !defined( $found_items{'TEST'} ) ) ]
									} ## end if ( $rules->{'vars_tests'}{$var}{'negative'...})
								} ## end else [ if ( ref( $rules->{'vars_tests'}{$var}{'negative'...}))]

								$test_int++;
							} ## end while ( defined( $rules->{'vars_tests'}{$var}...))
						} ## end else [ if ( !defined( $rules->{'vars_tests'}{$var...}))]
					} ## end else [ if ($@) ]
				} elsif ( defined( $rules->{'vars_tests'}{$var}{'test_template'} )
					&& ( ref( $rules->{'vars_tests'}{$var}{'test_template'} ) eq '' ) )
				{
					push( @errors,
							  '.vars_tests.'
							. $var
							. '.test_template has a ref of "'
							. ref( $rules->{'vars_tests'}{$var}{'test_template'} )
							. '" and not ""' );
				} else {
					push( @errors, '.vars_tests.' . $var . '.test_template is undef' );
				}
			} elsif ( ( ref( $rules->{'vars_tests'}{$var} ) eq 'HASH' )
				&& defined( $rules->{'vars'}{$var} )
				&& ( ref( $rules->{'vars'}{$var} ) ne '' ) )
			{
				push( @errors, '.vars.' . $var . ' has a ref of "' . ref( $rules->{'vars'}{$var} ) . '" and not ""' );
			} elsif ( ( ref( $rules->{'vars_tests'}{$var} ) eq 'HASH' )
				&& !defined( $rules->{'vars'}{$var} ) )
			{
				push( @errors, '.vars.' . $var . ' has tests for it but it is undefined' );
			} else {
				push( @errors,
						  '.vars_tests.'
						. $var
						. ' has a ref of "'
						. ref( $rules->{'vars_tests'}{$var} )
						. '" and not "HASH"' );
			}
		} ## end foreach my $var ( keys( %{ $rules->{'vars_tests'...}}))
	} ## end if ( $has_var_tests && $vars_testable )

	my $results = {
		'fatal'    => undef,
		'errors'   => \@errors,
		'warnings' => \@warnings,
	};

	return $results;
} ## end sub test
