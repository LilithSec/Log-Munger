package Log::Munger::RulesTest;

use 5.006;
use strict;
use warnings;
use Template;
use Log::Munger::RuleFileParser;
use Log::Munger::LogProcessor ();

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
            print "Warnings:\n".join("\n", @{ $results->{'warnings'}[0] })."\n\n";
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
			return {
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
						push( @errors, '.vars_tests.' . $var . '.test_template could not be templated...' . $@ );
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
						} elsif ( ( ref( $rules->{'vars_tests'}{$var}{'positive'} ) eq 'ARRAY' )
							&& !defined( $rules->{'vars_tests'}{$var}{'positive'}[0] ) )
						{
							push( @errors, '.vars_tests.' . $var . '.positive is empty and has no tests' );
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
											. '.positive.'
											. $test_int
											. ' has a ref of "'
											. ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int] )
											. '" and not "HASH"' );
								} elsif ( !defined( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'} ) ) {
									push( @errors,
										'.vars_tests.' . $var . '.positive.' . $test_int . '.string is undef' );
								} elsif ( ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'} ) ne '' ) {
									push( @errors,
											  '.vars_tests.'
											. $var
											. '.positive.'
											. $test_int
											. '.string has a ref of "'
											. ref( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'} )
											. '" and not ""' );
								} elsif ( !defined( $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'} ) ) {
									push( @errors,
										'.vars_tests.' . $var . '.positive.' . $test_int . '.result is undef' );
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
													  '.vars_tests.'
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
													  '.vars_tests.'
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
									} else {
										push( @errors,
												  '.vars_tests.'
												. $var
												. '.positive.'
												. $test_int
												. ' did not match but was expected to found... test_regex="'
												. $test_regex
												. '" string="'
												. $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'string'}
												. '" expected result="'
												. $rules->{'vars_tests'}{$var}{'positive'}[$test_int]{'result'}
												. '"' );
									} ## end else [ if ( $rules->{'vars_tests'}{$var}{'positive'...})]
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
									if ( $rules->{'vars_tests'}{$var}{'negative'}[$test_int] =~ /$test_regex/ ) {
										my %found_items = %+;
										if ( !defined( $found_items{'TEST'} ) ) {
											push( @warnings,
													  '.vars_tests.'
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
													  '.vars_tests.'
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
			} elsif ( !defined( $rules->{'vars'}{$var} ) )
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

		#
		# since we are done with var tests, look for any vars we've not done any tests for
		#
		foreach my $var (keys( %{$rules->{'vars'}})) {
			if (!$tested_vars{$var}){
				push(@warnings, '.vars.'.$var.' lacks any tests');
			}
		}
	} ## end if ( $has_var_tests && $vars_testable )

	##
	## lint every resolved var value for problems that break matching
	##
	if ( $vars_testable ) {
		foreach my $var ( sort keys( %{ $rules->{'vars'} } ) ) {
			my $value = $rules->{'vars'}{$var};
			next if ( ref($value) ne '' );    # ref problems already reported above
			push( @errors, __lint_regexp_string( '.vars.' . $var, $value ) );
		}
	}

	##
	## process everything under .rules
	##
	if ( defined( $rules->{'rules'} ) ) {
		if ( ref( $rules->{'rules'} ) ne 'ARRAY' ) {
			push( @errors, '.rules has a ref of "' . ref( $rules->{'rules'} ) . '" and not "ARRAY"' );
		} else {
			my $vars = ( ref( $rules->{'vars'} ) eq 'HASH' ) ? $rules->{'vars'} : {};

			my $rule_int = 0;
			foreach my $rule ( @{ $rules->{'rules'} } ) {
				my $where = '.rules.' . $rule_int;
				if ( ref($rule) ne 'HASH' ) {
					push( @errors, $where . ' has a ref of "' . ref($rule) . '" and not "HASH"' );
					$rule_int++;
					next;
				}

				# a pattern that references a name absent from vars is silently
				# treated as an inline regexp by the engine; an all-caps name is
				# almost certainly a typo'd var reference, so flag it loudly
				if ( ref( $rule->{'patterns'} ) eq 'ARRAY' ) {
					my $pattern_int = 0;
					foreach my $pattern ( @{ $rule->{'patterns'} } ) {
						if (   ( ref($pattern) eq '' )
							&& ( $pattern =~ /^[A-Z][A-Z0-9_]*\z/ )
							&& ( !exists( $vars->{$pattern} ) ) )
						{
							push( @errors,
									  $where
									. '.patterns.'
									. $pattern_int
									. ' looks like a var reference ("'
									. $pattern
									. '") but no such var exists' );
						}
						$pattern_int++;
					}
				} ## end if ( ref( $rule->{'patterns'...}))

				# compile the rule exactly as the engine does; a failure here is
				# what surfaces un-degrokked grok and illegal capture names
				my $compiled;
				eval { $compiled = Log::Munger::LogProcessor->_compile_rule( 'rule' => $rule, 'vars' => $vars ); };
				if ($@) {
					push( @errors, $where . ' failed to compile... ' . $@ );
					$rule_int++;
					next;
				}

				#
				# run the rule's embedded tests
				#
				if ( !defined( $rule->{'tests'} ) ) {
					push( @warnings, $where . ' lacks any tests' );
				} elsif ( ref( $rule->{'tests'} ) ne 'HASH' ) {
					push( @errors,
						$where . '.tests has a ref of "' . ref( $rule->{'tests'} ) . '" and not "HASH"' );
				} else {
					__test_rule_positive( $where, $rule, $compiled, \@errors );
					__test_rule_negative( $where, $rule, $compiled, \@errors );
				}

				# a rule may carry its own decompose entries
				if ( defined( $rule->{'decompose'} ) ) {
					__test_decompose( $rule->{'decompose'}, $vars, \@errors, \@warnings, $where . '.decompose' );
				}

				$rule_int++;
			} ## end foreach my $rule ( @{ $rules->{'rules'} } )
		} ## end else [ if ( ref( $rules->{'rules'...}))]
	} ## end if ( defined( $rules->{'rules'} ) )

	##
	## a file-level decompose is shared by every rule, so test it once here
	##
	if ( defined( $rules->{'decompose'} ) ) {
		my $vars = ( ref( $rules->{'vars'} ) eq 'HASH' ) ? $rules->{'vars'} : {};
		__test_decompose( $rules->{'decompose'}, $vars, \@errors, \@warnings, '.decompose' );
	}

	##
	## validate a file-level convert map (bad types are a load-time error)
	##
	if ( defined( $rules->{'convert'} ) ) {
		eval { Log::Munger::LogProcessor->_compile_convert( $rules->{'convert'} ); };
		if ($@) {
			push( @errors, '.convert is invalid... ' . $@ );
		}
	}

	my $results = {
		'fatal'    => undef,
		'errors'   => \@errors,
		'warnings' => \@warnings,
	};

	return $results;
} ## end sub test

# Lint one resolved regexp string (a var value or pattern). Returns a list of
# error strings (possibly empty). Checks for leftover grok, illegal named
# captures, interior newlines, and qr// compile failures.
sub __lint_regexp_string {
	my ( $where, $value ) = @_;

	my @errors;

	if ( $value =~ /%\{[^}]*\}/ ) {
		push( @errors, $where . ' contains un-degrokked grok "%{...}"' );
	}

	# validate every (?<name> ... capture name; Perl allows [A-Za-z_]\w* only.
	# the (?![=!]) guard skips lookbehind assertions (?<= and (?<!
	while ( $value =~ /\(\?<(?![=!])([^>]*)>/g ) {
		my $name = $1;
		if ( $name !~ /^[A-Za-z_]\w*\z/ ) {
			push( @errors, $where . ' has an illegal named-capture "' . $name . '" (must match [A-Za-z_]\\w*)' );
		}
	}

	if ( $value =~ /\n/ ) {
		push( @errors, $where . ' contains an embedded newline and cannot match a single-line log' );
	}

	my $compiled;
	eval {
		# this is a deliberate trial compile of possibly-bad input; keep any
		# regexp warnings out of the caller's stderr
		local $SIG{'__WARN__'} = sub { };
		$compiled = qr/$value/;
	};
	if ($@) {
		push( @errors, $where . ' does not compile as a regexp... ' . $@ );
	}

	return @errors;
} ## end sub __lint_regexp_string

# Run a rule's positive tests: each {string, result} must match a pattern and
# the captured named groups must deep-equal result.
sub __test_rule_positive {
	my ( $where, $rule, $compiled, $errors ) = @_;

	my $positive = $rule->{'tests'}{'positive'};
	if ( !defined($positive) ) {
		push( @{$errors}, $where . '.tests.positive is undef' );
		return;
	} elsif ( ref($positive) ne 'ARRAY' ) {
		push( @{$errors}, $where . '.tests.positive has a ref of "' . ref($positive) . '" and not "ARRAY"' );
		return;
	}

	my $test_int = 0;
	foreach my $test ( @{$positive} ) {
		my $twhere = $where . '.tests.positive.' . $test_int;
		if ( ref($test) ne 'HASH' ) {
			push( @{$errors}, $twhere . ' has a ref of "' . ref($test) . '" and not "HASH"' );
			$test_int++;
			next;
		}
		if ( !defined( $test->{'string'} ) || ref( $test->{'string'} ) ne '' ) {
			push( @{$errors}, $twhere . '.string is undef or not a string' );
			$test_int++;
			next;
		}
		my $expected = defined( $test->{'result'} ) ? $test->{'result'} : {};
		if ( ref($expected) ne 'HASH' ) {
			push( @{$errors}, $twhere . '.result has a ref of "' . ref($expected) . '" and not "HASH"' );
			$test_int++;
			next;
		}

		my $got;
		foreach my $pattern ( @{ $compiled->{'patterns'} } ) {
			if ( $test->{'string'} =~ $pattern ) {
				my %captures = %+;
				$got = \%captures;
				last;
			}
		}

		if ( !defined($got) ) {
			push( @{$errors}, $twhere . ' did not match any pattern... string="' . $test->{'string'} . '"' );
		} else {
			my $diff = __capture_diff( $expected, $got );
			if ( defined($diff) ) {
				push( @{$errors}, $twhere . ' captures differ from expected: ' . $diff . ' string="' . $test->{'string'} . '"' );
			}
		}

		$test_int++;
	} ## end foreach my $test ( @{$positive} )

	return;
} ## end sub __test_rule_positive

# Run a rule's negative tests: each string must NOT match any pattern.
sub __test_rule_negative {
	my ( $where, $rule, $compiled, $errors ) = @_;

	my $negative = $rule->{'tests'}{'negative'};
	if ( !defined($negative) ) {
		push( @{$errors}, $where . '.tests.negative is undef' );
		return;
	} elsif ( ref($negative) ne 'ARRAY' ) {
		push( @{$errors}, $where . '.tests.negative has a ref of "' . ref($negative) . '" and not "ARRAY"' );
		return;
	}

	my $test_int = 0;
	foreach my $test ( @{$negative} ) {
		my $twhere = $where . '.tests.negative.' . $test_int;
		if ( ref($test) ne '' ) {
			push( @{$errors}, $twhere . ' has a ref of "' . ref($test) . '" and not ""' );
			$test_int++;
			next;
		}
		foreach my $pattern ( @{ $compiled->{'patterns'} } ) {
			if ( $test =~ $pattern ) {
				push( @{$errors}, $twhere . ' matched a pattern but should not have... string="' . $test . '"' );
				last;
			}
		}
		$test_int++;
	} ## end foreach my $test ( @{$negative} )

	return;
} ## end sub __test_rule_negative

# Compare expected vs got flat capture hashes. Returns undef if equal, else a
# human-readable description of the first difference found.
sub __capture_diff {
	my ( $expected, $got ) = @_;

	foreach my $key ( sort keys( %{$expected} ) ) {
		if ( !exists( $got->{$key} ) ) {
			return 'expected key "' . $key . '" not captured';
		}
		if ( $expected->{$key} ne $got->{$key} ) {
			return 'key "' . $key . '" expected "' . $expected->{$key} . '" but got "' . $got->{$key} . '"';
		}
	}
	foreach my $key ( sort keys( %{$got} ) ) {
		if ( !exists( $expected->{$key} ) ) {
			return 'unexpected key "' . $key . '" captured as "' . $got->{$key} . '"';
		}
	}

	return undef;
} ## end sub __capture_diff

# Test a decompose list (file-level or rule-level). Each entry may carry a
# `tests: [{input, result}]` block; the entry is applied on its own to the
# captures hash { field => input } and the resulting captures must equal result
# (which reflects the entry's remove: setting).
sub __test_decompose {
	my ( $list, $vars, $errors, $warnings, $where ) = @_;

	if ( ref($list) ne 'ARRAY' ) {
		push( @{$errors}, $where . ' has a ref of "' . ref($list) . '" and not "ARRAY"' );
		return;
	}

	my $int = 0;
	foreach my $entry ( @{$list} ) {
		my $ewhere = $where . '.' . $int;

		# compile just this entry (surfaces bad type / grok / regexp)
		my $compiled;
		eval { $compiled = Log::Munger::LogProcessor->_compile_decompose( [$entry], $vars ); };
		if ($@) {
			push( @{$errors}, $ewhere . ' failed to compile... ' . $@ );
			$int++;
			next;
		}

		if ( !defined( $entry->{'tests'} ) ) {
			push( @{$warnings}, $ewhere . ' lacks any tests' );
			$int++;
			next;
		} elsif ( ref( $entry->{'tests'} ) ne 'ARRAY' ) {
			push( @{$errors}, $ewhere . '.tests has a ref of "' . ref( $entry->{'tests'} ) . '" and not "ARRAY"' );
			$int++;
			next;
		}

		my $rule = { 'decompose' => $compiled };
		my $test_int = 0;
		foreach my $test ( @{ $entry->{'tests'} } ) {
			my $twhere = $ewhere . '.tests.' . $test_int;
			if ( ref($test) ne 'HASH' ) {
				push( @{$errors}, $twhere . ' has a ref of "' . ref($test) . '" and not "HASH"' );
				$test_int++;
				next;
			}
			if ( !defined( $test->{'input'} ) || ref( $test->{'input'} ) ne '' ) {
				push( @{$errors}, $twhere . '.input is undef or not a string' );
				$test_int++;
				next;
			}
			my $expected = defined( $test->{'result'} ) ? $test->{'result'} : {};
			if ( ref($expected) ne 'HASH' ) {
				push( @{$errors}, $twhere . '.result has a ref of "' . ref($expected) . '" and not "HASH"' );
				$test_int++;
				next;
			}

			my %captures = ( $entry->{'field'} => $test->{'input'} );
			Log::Munger::LogProcessor->_decompose( $rule, \%captures );

			my $diff = __capture_diff( $expected, \%captures );
			if ( defined($diff) ) {
				push( @{$errors},
					$twhere . ' decompose output differs: ' . $diff . ' input="' . $test->{'input'} . '"' );
			}

			$test_int++;
		} ## end foreach my $test ( @{ $entry->{'tests'} } )

		$int++;
	} ## end foreach my $entry ( @{$list} )

	return;
} ## end sub __test_decompose
