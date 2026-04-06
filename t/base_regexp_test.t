#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Log::Munger::RuleFileParser') || print "Bail out!\n";
}

my $tests = 13;

my $parser = Log::Munger::RuleFileParser->new;
my $rules  = $parser->load( 'file' => 'base' );

my $worked = 0;
eval {
	my $regexp  = '(?<TEST>' . $rules->{'vars'}{'IPv6'} . ')';
	my $to_test = {
		'  a b c ::1 d'                          => '::1',
		'  a b c=::1 d'                          => '::1',
		'  a b c=::1; d'                         => '::1',
		'  a b c=fc00:bbbb:dddd:ab01::9:faca; d' => 'fc00:bbbb:dddd:ab01::9:faca',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'IPv6 regexp' ) or diag( "testing IPv6 regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = '(?<TEST>' . $rules->{'vars'}{'IPv4'} . ')';
	my $to_test = {
		'  a b c 127.0.0.1 d'      => '127.0.0.1',
		'  a b c=127.0.0.1 d'      => '127.0.0.1',
		'  a b c=127.0.0.1; d'     => '127.0.0.1',
		'  a b c=192.168.1.155; d' => '192.168.1.155',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'IPv4 regexp' ) or diag( "testing IPv4 regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = '(?<TEST>' . $rules->{'vars'}{'IP'} . ')';
	my $to_test = {
		'  a b c 127.0.0.1 d'                    => '127.0.0.1',
		'  a b c=127.0.0.1 d'                    => '127.0.0.1',
		'  a b c=127.0.0.1; d'                   => '127.0.0.1',
		'  a b c=192.168.1.155; d'               => '192.168.1.155',
		'  a b c ::1 d'                          => '::1',
		'  a b c=::1 d'                          => '::1',
		'  a b c=::1; d'                         => '::1',
		'  a b c=fc00:bbbb:dddd:ab01::9:faca; d' => 'fc00:bbbb:dddd:ab01::9:faca',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'IP regexp' ) or diag( "testing IP regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'HOSTNAME'} . ')';
	my $to_test = {
		'  a b c=b.a.foo.bar d'  => 'b.a.foo.bar',
		'  a b c=b.a.foo.bar; d' => 'b.a.foo.bar',
		'  a b c=b.a.foo.bar; d' => 'b.a.foo.bar',
		'  a b c=a.foo.bar d'    => 'a.foo.bar',
		'  a b c=a.foo.bar; d'   => 'a.foo.bar',
		'  a b c=a.foo.bar; d'   => 'a.foo.bar',
		'  a b c=foo.bar d'      => 'foo.bar',
		'  a b c=foo.bar; d'     => 'foo.bar',
		'  a b c=foo.bar; d'     => 'foo.bar',
		'  a b c=bar d'          => 'bar',
		'  a b c=bar; d'         => 'bar',
		'  a b c=bar; d'         => 'bar',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'HOSTNAME regexp' ) or diag( "testing HOSTNAME regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'HOSTNAMEorIP'} . ')';
	my $to_test = {
		'  a b c=127.0.0.1 d'                    => '127.0.0.1',
		'  a b c=127.0.0.1 d'                    => '127.0.0.1',
		'  a b c=127.0.0.1; d'                   => '127.0.0.1',
		'  a b c=192.168.1.155; d'               => '192.168.1.155',
		'  a b c=::1 d'                          => '::1',
		'  a b c=::1 d'                          => '::1',
		'  a b c=::1; d'                         => '::1',
		'  a b c=fc00:bbbb:dddd:ab01::9:faca; d' => 'fc00:bbbb:dddd:ab01::9:faca',
		'  a b c=b.a.foo.bar d'                  => 'b.a.foo.bar',
		'  a b c=b.a.foo.bar; d'                 => 'b.a.foo.bar',
		'  a b c=b.a.foo.bar; d'                 => 'b.a.foo.bar',
		'  a b c=a.foo.bar d'                    => 'a.foo.bar',
		'  a b c=a.foo.bar; d'                   => 'a.foo.bar',
		'  a b c=a.foo.bar; d'                   => 'a.foo.bar',
		'  a b c=foo.bar d'                      => 'foo.bar',
		'  a b c=foo.bar; d'                     => 'foo.bar',
		'  a b c=foo.bar; d'                     => 'foo.bar',
		'  a b c=bar d'                          => 'bar',
		'  a b c=bar; d'                         => 'bar',
		'  a b c=bar; d'                         => 'bar',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'HOSTNAMEorIP regexp' ) or diag( "testing HOSTNAMEorIP regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'INT'} . ')';
	my $to_test = {
		'  a b c=1 d'      => '1',
		'  a b c=1 d'      => '1',
		'  a b c=1; d'     => '1',
		'  a b c=341; d'   => '341',
		'  a b c=341.2; d' => '341',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'INT regexp' ) or diag( "testing INT regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'FLOAT'} . ')';
	my $to_test = {
		'  a b c=1.99 d'        => '1.99',
		'  a b c=1.9 d'         => '1.9',
		'  a b c=1.3; d'        => '1.3',
		'  a b c=341.0; d'      => '341.0',
		'  a b c=341.2; d'      => '341.2',
		'  a b c=341.393914; d' => '341.393914',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'FLOAT regexp' ) or diag( "testing FLOAT regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'INTorFLOAT'} . ')';
	my $to_test = {
		'  a b c=1.99 d'        => '1.99',
		'  a b c=1.9 d'         => '1.9',
		'  a b c=1.3; d'        => '1.3',
		'  a b c=341.0; d'      => '341.0',
		'  a b c=341.2; d'      => '341.2',
		'  a b c=341.393914; d' => '341.393914',
		'  a b c=1 d'           => '1',
		'  a b c=1 d'           => '1',
		'  a b c=1; d'          => '1',
		'  a b c=341; d'        => '341',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'INTorFLOAT regexp' ) or diag( "testing INTorFLOAT regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'STATUS_WORD'} . ')';
	my $to_test = {
		'  a b c=1.99 d'        => '1',
		'  a b c=1-af d'        => '1-af',
		'  a b c=1af d'         => '1af',
		'  a b c=1.9 d'         => '1',
		'  a b c=1.3; d'        => '1',
		'  a b c=341.0; d'      => '341',
		'  a b c=341.2; d'      => '341',
		'  a b c=341.393914; d' => '341',
		'  a b c=ERROR12; d'    => 'ERROR12',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'STATUS_WORD regexp' ) or diag( "testing STATUS_WORD regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'GREEDYDATA_NO_COLON'} . ')';
	my $to_test = {
		'  a b c=1.99: d'       => '1.99',
		'  a b c=1-af: d'       => '1-af',
		'  a b c=1af: d'        => '1af',
		'  a b c=1.3: d'        => '1.3',
		'  a b c=1.3 : d'       => '1.3 ',
		'  a b c=341.0: d'      => '341.0',
		'  a b c=341.393914: d' => '341.393914',
		'  a b c=ERROR12: d'    => 'ERROR12',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'GREEDYDATA_NO_COLON regexp' ) or diag( "testing GREEDYDATA_NO_COLON regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'GREEDYDATA_NO_SEMICOLON'} . ')';
	my $to_test = {
		'  a b c=1.99; d'       => '1.99',
		'  a b c=1-af; d'       => '1-af',
		'  a b c=1af; d'        => '1af',
		'  a b c=1.3; d'        => '1.3',
		'  a b c=1.3 ; d'       => '1.3 ',
		'  a b c=341.0; d'      => '341.0',
		'  a b c=341.393914; d' => '341.393914',
		'  a b c=ERROR12; d'    => 'ERROR12',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'GREEDYDATA_NO_SEMICOLON regexp' )
	or diag( "testing GREEDYDATA_NO_SEMICOLON regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'GREEDYDATA_NO_BRACKET'} . ')';
	my $to_test = {
		'  a b c=1.99< d'        => '1.99',
		'  a b c=1-af> d'        => '1-af',
		'  a b c=1af< d'         => '1af',
		'  a b c=1.3>< d'        => '1.3',
		'  a b c=1.3 abc"<> d'       => '1.3 abc"',
		'  a b c=341.0<< d'      => '341.0',
		'  a b c=341.393914<> d' => '341.393914',
		'  a b <<c=ERROR12>> d'    => 'ERROR12',
	};
	my @test_strings = keys( %{$to_test} );

	foreach my $test_string (@test_strings) {
		if ( $test_string =~ /$regexp/ ) {
			my %found_items = %+;
			if ( !defined( $found_items{'TEST'} ) ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST, but test is undef' );
			} elsif ( $found_items{'TEST'} ne $to_test->{$test_string} ) {
				die(      '"'
						. $regexp
						. '" did not match "'
						. $test_string
						. '"... expected return was "'
						. $to_test->{$test_string}
						. '" for the var TEST but "'
						. $found_items{'TEST'}
						. '" was found instead' );
			} ## end elsif ( $found_items{'TEST'} ne $to_test->{$test_string...})
		} else {
			die(      '"'
					. $regexp
					. '" did not match "'
					. $test_string
					. '"... expected return was "'
					. $to_test->{$test_string}
					. '"' );
		}
	} ## end foreach my $test_string (@test_strings)

	$worked = 1;
};
ok( $worked eq '1', 'GREEDYDATA_NO_BRACKET regexp' ) or diag( "testing GREEDYDATA_NO_BRACKET regexp failed ... " . $@ );

done_testing($tests);
