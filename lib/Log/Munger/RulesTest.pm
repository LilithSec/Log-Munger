package Log::Munger::RulesTest;

use 5.006;
use strict;
use warnings;
use Template;
use Log::Munger::RuleFileParser;
use Log::Munger::LogProcessor ();

=head1 NAME

Log::Munger::RulesTest - Runs a rule file's own tests and lints it for the usual mistakes.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::RulesTest;

    my $results = Log::Munger::RulesTest->test( 'file' => 'postfix' );

    if ( defined( $results->{'fatal'} ) ) {
        print 'File could not be loaded... ' . $results->{'fatal'} . "\n";
    } else {
        print 'Errors:'   . "\n" . join( "\n", @{ $results->{'errors'} } )   . "\n\n";
        print 'Warnings:' . "\n" . join( "\n", @{ $results->{'warnings'} } ) . "\n\n";
    }

A rule file carries its own tests. Each primitive under C<vars> has positive and
negative cases under C<vars_tests>, each rule has a C<tests> block naming strings
that should and should not match, and each C<decompose> entry has its own
C<tests>. This module is what runs all of that, along with a lint pass over every
resolved var.

Nothing here needs live log data or a running system, so it is cheap enough to
wire into CI. That is what C<log_munger test_all> does, and it exits non-zero if
any file reports an error. C<log_munger test_rule_file -f E<lt>fileE<gt>> does the
same thing for one file and dumps the whole result as YAML.

=head1 METHODS

=head2 test

Runs a rule file's tests and lints it, gathering everything that went wrong rather
than stopping at the first problem.

Give it either C<file> or C<hash>, not both and not neither. Beyond that, it
reports rather than dies: a rule file bad enough that it will not even load comes
back as a C<fatal>, not an exception.

The checks are:

=over 4

=item * Every C<vars_tests> entry. The var is spliced into the entry's
C<test_template>, then each positive case has to match with C<TEST> capturing the
expected result, and each negative case has to not match.

=item * Every resolved var, linted for leftover grok C<%{...}>, named captures
Perl will not accept, embedded newlines, and anything that will not compile.

=item * Every rule, compiled exactly as L<Log::Munger::LogProcessor> compiles it,
then run against its C<tests>. Positive strings have to match with the expected
captures and negative strings have to match nothing. A pattern that looks like a
var reference but names no existing var is flagged, since the engine would
silently treat it as an inline regexp.

=item * Every C<decompose> entry, rule level and file level, applied on its own to
its C<tests> input and checked against the expected output.

=item * A file level C<convert> map, for types that are not recognised.

=back

Anything that would produce wrong output is an error. Anything merely worth
knowing, such as a var or rule with no tests at all, is a warning.

    - file :: The file to load and test. Either a bare name resolved through the
        search path, such as "postfix", or a path.
        Default :: undef

    - hash :: An already loaded rules hash ref to test instead of a file.
        Default :: undef

Returns a hash ref:

    - fatal :: The reason the file could not be loaded, or undef if it loaded.
        When this is set the other two are empty, since nothing could be tested.

    - errors :: Array ref of strings, each naming a problem that would produce
        wrong output. Empty if there were none.

    - warnings :: Array ref of strings, each naming something worth knowing that
        is not itself a failure. Empty if there were none.

Every message is prefixed with where the problem is, written as a path into the
rule file, so C<.rules.3.tests.positive.0> is the first positive test of the
fourth rule.

Dies only if neither C<file> nor C<hash> was given, if both were, or if either is
of the wrong type.

    my $results = Log::Munger::RulesTest->test( 'file' => 'postfix' );
    my $results = Log::Munger::RulesTest->test( 'hash' => $rules_hash );

=cut

sub test {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'hash'} ) && !defined( $opts{'file'} ) ) {
		die('$opts{hash} and $opts{file} are both undef and one needs to be defined');
	} elsif ( defined( $opts{'hash'} ) && defined( $opts{'file'} ) ) {
		die('$opts{hash} and $opts{file} are both defined and only one should be');
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
		push( @warnings, '.vars_tests is undef even though .vars exists, meaning there are no tests for it' );
	}

	##
	## process everything under .vars_tests
	##
	if ( $has_var_tests && $vars_testable ) {
		# tracked so that, once the tests are done, any var that never showed up
		# here can be reported as untested
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
					# splice the var into its test_template. everything below
					# needs the resulting regexp, so a template that will not
					# process ends the testing of this var here.
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
						#
						# having none is an error rather than a warning. a var
						# with only negative tests has never been shown to match
						# anything, which is the same as not being tested at all.
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
													. ' matched but "TEST" was not captured... test_regex="'
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
													. ' matched but "TEST" captured the wrong result, "'
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
												. ' did not match but was expected to... test_regex="'
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
									. '.negative has a ref of "'
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
											. ' has a ref of "'
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

# Lints one fully resolved regexp string for the four things that go wrong often
# enough to be worth checking for by name.
#
# Leftover grok "%{...}" means a pattern was copied in from logstash and never run
# through Log::Munger::Degrok. An illegal named capture means a grok capture name
# came across as-is when Perl will not take it; grok is happy with "src-ip" and
# Perl only accepts [A-Za-z_]\w*. An embedded newline usually means a YAML "|"
# block scalar leaked its terminator into the middle of a pattern, which leaves it
# unable to match a single line log while looking perfectly fine in the file. And
# a string that will not compile at all is caught here rather than at match time.
#
# The capture name scan skips (?<= and (?<! since those are lookbehind assertions
# rather than named captures.
#
# Args:
#
#     - $where :: Where this string lives in the rule file, written as a path,
#         such as ".vars.SSH_FAILED". Prefixed onto every message so the caller
#         knows what to go look at.
#
#     - $value :: The resolved regexp string to lint. This wants to be the value
#         after templating, not the vars_templated source, since the whole point
#         is to check what the engine will actually compile.
#
# Returns a list of error strings, each already prefixed with $where. An empty
# list means the string is clean. Nothing is ever pushed to warnings from here;
# everything it looks for would produce wrong output.
#
#     my @errors = __lint_regexp_string( '.vars.SSH_FAILED', $rules->{'vars'}{'SSH_FAILED'} );
#     # ( '.vars.SSH_FAILED has an illegal named-capture "src-ip" (must match [A-Za-z_]\w*)' )
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

# Runs a rule's positive tests. Each case names a string that has to match one of
# the rule's patterns, along with the captures that match is expected to produce.
#
# The patterns are tried in order and the first to match wins, exactly as the
# engine does it, so a test also pins down which pattern is supposed to be
# handling a given line.
#
# What is compared is the raw named captures and nothing else. Decompose, geoip
# and convert do not run here, which is why a positive test's expected result
# lists a port as the string '54321' even though a convert: turns it into a number
# at runtime. Those steps have their own tests: decompose entries carry their own,
# and geoip and convert are runtime concerns.
#
# Args:
#
#     - $where :: Where this rule lives, written as a path, such as ".rules.3".
#         The per-test messages extend it, giving ".rules.3.tests.positive.0".
#
#     - $rule :: The raw rule hash ref, straight out of the rule file. Only its
#         tests.positive is read here.
#
#     - $compiled :: The same rule after Log::Munger::LogProcessor->_compile_rule,
#         which is where the qr// patterns to test against come from.
#
#     - $errors :: Array ref to push error strings onto. Appended to in place.
#
# Returns nothing. Everything it finds goes onto $errors, which is left untouched
# if all the positive tests pass.
#
#     __test_rule_positive( '.rules.0', $rule, $compiled, \@errors );
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

# Runs a rule's negative tests. Each case is a bare string that has to match none
# of the rule's patterns.
#
# This is what keeps a loose pattern honest. A pattern written as "a word, a
# space, then anything" will happily match most of a log file, and its positive
# tests will not notice. A good negative case is one that is genuinely outside
# what the pattern was written for, not merely unrelated in subject matter.
#
# Args:
#
#     - $where :: Where this rule lives, written as a path, such as ".rules.3".
#         The per-test messages extend it, giving ".rules.3.tests.negative.0".
#
#     - $rule :: The raw rule hash ref, straight out of the rule file. Only its
#         tests.negative is read here.
#
#     - $compiled :: The same rule after Log::Munger::LogProcessor->_compile_rule,
#         which is where the qr// patterns to test against come from.
#
#     - $errors :: Array ref to push error strings onto. Appended to in place.
#
# Returns nothing. Everything it finds goes onto $errors, which is left untouched
# if all the negative tests pass.
#
#     __test_rule_negative( '.rules.0', $rule, $compiled, \@errors );
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

# Compares two flat capture hashes and describes the first way they differ.
#
# Both directions are checked, so a capture that was expected and never appeared
# is caught, and so is one that appeared without being asked for. That second case
# matters more than it looks: an unexpected capture usually means a pattern picked
# up a group nobody meant to add, and without checking for it a test would pass
# while the rule quietly emitted a field consumers were not written for.
#
# Comparison is string comparison, which is what the rule files want. Everything
# coming out of a regexp capture is a string, and the expected results in YAML are
# written to match.
#
# Args:
#
#     - $expected :: Hash ref of the captures the test says there should be, as
#         written in the rule file. Values are compared as strings.
#
#     - $got :: Hash ref of the captures that actually came out, a copy of %+.
#
# Returns undef if the two agree, otherwise a string describing the first
# difference found, ready to be dropped into an error message. Only the first is
# reported, since a single wrong pattern usually throws off several keys at once
# and listing them all says no more than listing one.
#
#     my $diff = __capture_diff( { ssh_user => 'alice' }, { ssh_user => 'bob' } );
#     # 'key "ssh_user" expected "alice" but got "bob"'
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

# Tests a decompose list, either a rule's own or the file level default.
#
# Every entry is compiled on its own first, which is what surfaces an unknown
# type, leftover grok in a pattern entry, or a pattern that will not compile.
#
# An entry that carries tests is then exercised one entry at a time. The captures
# hash is built as nothing but { field => input }, the single entry is applied to
# it, and what comes out has to equal the expected result. Testing entries in
# isolation like this means a list of several does not have to be reasoned about
# as a whole, and it keeps a change to one entry from breaking the tests of the
# others.
#
# The expected result has to account for the entry's remove: setting. With remove
# set the source field is gone by the time the comparison happens, so listing it
# would fail; without it the source field is still there and leaving it out would
# fail as an unexpected capture.
#
# Args:
#
#     - $list :: The decompose list, as written in the rule file. An array ref of
#         { field, type, ... } hash refs.
#
#     - $vars :: The resolved vars hash ref, which a "type: pattern" entry
#         resolves its pattern name against. An empty hash ref is fine for a list
#         that only uses kv or json entries.
#
#     - $errors :: Array ref to push error strings onto. Appended to in place.
#
#     - $warnings :: Array ref to push warning strings onto. Appended to in
#         place. An entry with no tests at all lands here rather than in errors.
#
#     - $where :: Where this list lives, written as a path, such as ".decompose"
#         for the file level one or ".rules.3.decompose" for a rule's own. The
#         per-entry and per-test messages extend it.
#
# Returns nothing. Everything it finds goes onto $errors or $warnings.
#
#     __test_decompose( $rules->{'decompose'}, $vars, \@errors, \@warnings, '.decompose' );
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
