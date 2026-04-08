#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Log::Munger::RuleFileParser') || print "Bail out!\n";
}

my $tests = 38;

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
		'  a b c=1.3 abc"<> d'   => '1.3 abc"',
		'  a b c=341.0<< d'      => '341.0',
		'  a b c=341.393914<> d' => '341.393914',
		'  a b <<c=ERROR12>> d'  => 'ERROR12',
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

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'USERNAME'} . ')';
	my $to_test = {
		'  a b c=1.99 d'   => '1.99',
		'  a b c=1-af d'   => '1-af',
		'  a b c=1+af d'   => '1',
		'  a b c=a1_3 d'   => 'a1_3',
		'  a b c=a130d8 d' => 'a130d8',
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
ok( $worked eq '1', 'USERNAME regexp' ) or diag( "testing USERNAME regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'EMAILLOCALPART'} . ')';
	my $to_test = {
		'  a b c=a.99 d'   => 'a.99',
		'  a b c=af d'     => 'af',
		'  a b c=a+af d'   => 'a+af',
		'  a b c=a1_3 d'   => 'a1_3',
		'  a b c=a130d8 d' => 'a130d8',
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
ok( $worked eq '1', 'EMAILLOCALPART regexp' ) or diag( "testing EMAILLOCALPART regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'EMAILADDRESS'} . ')';
	my $to_test = {
		'  a b c=a.99@foo.bar d'     => 'a.99@foo.bar',
		'  a b c=af@foo.bar d'       => 'af@foo.bar',
		'  a b c=a+af@foo.bar d'     => 'a+af@foo.bar',
		'  a b c=a1_3@foo.bar d'     => 'a1_3@foo.bar',
		'  a b c=a130d8@a.3.bar.a d' => 'a130d8@a.3.bar.a',
		'  a b c=a130d8@a.foo.bar d' => 'a130d8@a.foo.bar',
		'  a b c=a130d8@foo.bar d'   => 'a130d8@foo.bar',
		'  a b c=a130d8@foo d'       => 'a130d8@foo',
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
ok( $worked eq '1', 'EMAILADDRESS regexp' ) or diag( "testing EMAILADDRESS regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'QUOTEDSTRING'} . ')';
	my $to_test = {
		'  a b c="a.99@foo.bar" d'       => '"a.99@foo.bar"',
		'  a b c="af@foo.bar" d'         => '"af@foo.bar"',
		'  a b c="a+af@foo.bar " d'      => '"a+af@foo.bar "',
		'  a b c=`a1_3@foo.bar` d'       => '`a1_3@foo.bar`',
		'  a b c=`<a130d8@a.3.bar.a>` d' => '`<a130d8@a.3.bar.a>`',
		'  a b c="`a130d8@a.foo.bar`" d' => '"`a130d8@a.foo.bar`"',
		'  a b c="a130d8@foo" d'         => '"a130d8@foo"',
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
ok( $worked eq '1', 'QUOTEDSTRING regexp' ) or diag( "testing QUOTEDSTRING regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'UUID'} . ')';
	my $to_test = {
		'  a b c=d39696b8-67f3-4526-874a-8eb53c8f753e d' => 'd39696b8-67f3-4526-874a-8eb53c8f753e',
		'  a b c=77e44eb2-cb0e-41a2-b438-41821841b76c d' => '77e44eb2-cb0e-41a2-b438-41821841b76c',
		'  a b c=f2f1f636-f0e8-4bd6-a23b-cacc3f721276 d' => 'f2f1f636-f0e8-4bd6-a23b-cacc3f721276',
		'  a b c=23ab2b25-f04a-474c-92f4-f4c458d8ff78 d' => '23ab2b25-f04a-474c-92f4-f4c458d8ff78',
		'  a b c=f056e551-4ef2-4d0e-a4c8-d7146b7baebc d' => 'f056e551-4ef2-4d0e-a4c8-d7146b7baebc',
		'  a b c=fc4bb6d7-a37e-470a-aa2d-3002a47430d3 d' => 'fc4bb6d7-a37e-470a-aa2d-3002a47430d3',
		'  a b c=e810d5eb-4012-4709-8fff-4208a61c9f31 d' => 'e810d5eb-4012-4709-8fff-4208a61c9f31',
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
ok( $worked eq '1', 'UUID regexp' ) or diag( "testing UUID regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'URN'} . ')';
	my $to_test = {
		'  a b c=urn:isbn:0451450523 d'                           => 'urn:isbn:0451450523',
		'  a b c=urn:isan:0000-0000-2CEA-0000-1-0000-0000-Y d'    => 'urn:isan:0000-0000-2CEA-0000-1-0000-0000-Y',
		'  a b c=urn:ISSN:0167-6423 d'                            => 'urn:ISSN:0167-6423',
		'  a b c=urn:ietf:rfc:2648 d'                             => 'urn:ietf:rfc:2648',
		'  a b c=urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66 d' =>
			'urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66',
		'  a b c=urn:lex:eu:council:directive:2010-03-09;2010-19-UE d' =>
			'urn:lex:eu:council:directive:2010-03-09;2010-19-UE',
		'  a b c=urn:lsid:zoobank.org:pub:CDC8D258-8F57-41DC-B560-247E17D3DC8C d' =>
			'urn:lsid:zoobank.org:pub:CDC8D258-8F57-41DC-B560-247E17D3DC8C',
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
ok( $worked eq '1', 'URN regexp' ) or diag( "testing URN regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'CISCOMAC'} . ')';
	my $to_test = {
		'  a b c=AABC.D433.FF00 d' => 'AABC.D433.FF00',
		'  a b c=1234.5678.ABCD d' => '1234.5678.ABCD',
		'  a b c=AaBb.cDdE.eFf0 d' => 'AaBb.cDdE.eFf0',
		'  a b c=0124.FfEe.DdCc d' => '0124.FfEe.DdCc',
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
ok( $worked eq '1', 'CISCOMAC regexp' ) or diag( "testing CISCOMAC regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'WINDOWSMAC'} . ')';
	my $to_test = {
		'  a b c=AA-BC-D4-33-FF-00 d' => 'AA-BC-D4-33-FF-00',
		'  a b c=12-34-56-78-AB-CD d' => '12-34-56-78-AB-CD',
		'  a b c=Aa-Bb-cD-dE-eF-f0 d' => 'Aa-Bb-cD-dE-eF-f0',
		'  a b c=01-24-Ff-Ee-Dd-Cc d' => '01-24-Ff-Ee-Dd-Cc',
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
ok( $worked eq '1', 'WINDOWSMAC regexp' ) or diag( "testing WINDOWSMAC regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'COMMONMAC'} . ')';
	my $to_test = {
		'  a b c=AA:BC:D4:33:FF:00 d' => 'AA:BC:D4:33:FF:00',
		'  a b c=12:34:56:78:AB:CD d' => '12:34:56:78:AB:CD',
		'  a b c=Aa:Bb:cD:dE:eF:f0 d' => 'Aa:Bb:cD:dE:eF:f0',
		'  a b c=01:24:Ff:Ee:Dd:Cc d' => '01:24:Ff:Ee:Dd:Cc',
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
ok( $worked eq '1', 'COOMONMAC regexp' ) or diag( "testing COMMONMAC regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'TTY'} . ')';
	my $to_test = {
		'  a b c=/dev/pts/3 d' => '/dev/pts/3',
		'  a b c=/dev/pts33 d' => '/dev/pts33',
		'  a b c=/dev/tty0 d'  => '/dev/tty0',
		'  a b c=/dev/ttyp0 d' => '/dev/ttyp0',
		'  a b c=/dev/ttyq3 d' => '/dev/ttyq3',
		'  a b c=/dev/ttyv4 d' => '/dev/ttyv4',
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
ok( $worked eq '1', 'TTY regexp' ) or diag( "testing TTY regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'WINPATH'} . ')';
	my $to_test = {
		'  a b c=c:\\a\\bb\\ccc d' => 'c:\\a\\bb\\ccc d',
		'  a b c=D:\\aa33\\v d'    => 'D:\\aa33\\v d',
		'  a b c=D:\\aa33\\v (86)' => 'D:\\aa33\\v (86)',
		'  a b c=D:\\aa33\\v (86)' => 'D:\\aa33\\v (86)',
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
ok( $worked eq '1', 'WINPATH regexp' ) or diag( "testing WINPATH regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'UNIXPATH'} . ')';
	my $to_test = {
		'  a b c=/dev/pts/3 d'   => '/dev/pts/3 d',
		'  a b c=/dev/pts33 d'   => '/dev/pts33 d',
		'  a b c=/dev/tty0 d'    => '/dev/tty0 d',
		'  a b c=/dev/ttyp0 d'   => '/dev/ttyp0 d',
		'  a b c=./dev/ttyq3 d'  => './dev/ttyq3 d',
		'  a b c=../dev/ttyv4 d' => '../dev/ttyv4 d',
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
ok( $worked eq '1', 'UNIXPATH regexp' ) or diag( "testing UNIXPATH regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'URIPROTO'} . ')';
	my $to_test = {
		'  a b c=HTTP d'  => 'HTTP',
		'  a b c=HT-TP d' => 'HT-TP',
		'  a b c=HT.TP d' => 'HT.TP',
		'  a b c=SMTP d'  => 'SMTP',
		'  a b c=FTP d'   => 'FTP',
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
ok( $worked eq '1', 'URIPROTO regexp' ) or diag( "testing URIPROTO regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'URIPATH'} . ')';
	my $to_test = {
		'  a b c=/foo d'                    => '/foo',
		'  a b c=/foo/bar d'                => '/foo/bar',
		'  a b c=/a/foo.png d'              => '/a/foo.png',
		'  a b c=/a#()_-=&@$%:;/test.jpg d' => '/a#()_-=&@$%:;/test.jpg',
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
ok( $worked eq '1', 'URIPATH regexp' ) or diag( "testing URIPATH regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'MONTH'} . ')';
	my $to_test = {
		'  a b c=Jan d'     => 'Jan',
		'  a b c=jan d'     => 'jan',
		'  a b c=January d' => 'January',
		'  a b c=Sep d'     => 'Sep',
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
ok( $worked eq '1', 'MONTH regexp' ) or diag( "testing MONTH regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'MONTHNUM'} . ')';
	my $to_test = {
		'  a b c=1 d'  => '1',
		'  a b c=12 d' => '12',
		'  a b c=3 d'  => '3',
		'  a b c=04 d' => '04',
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
ok( $worked eq '1', 'MONTHNUM regexp' ) or diag( "testing MONTHNUM regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'MONTHNUM2'} . ')';
	my $to_test = {
		'  a b c=01 d' => '01',
		'  a b c=12 d' => '12',
		'  a b c=10 d' => '10',
		'  a b c=04 d' => '04',
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
ok( $worked eq '1', 'MONTHNUM2 regexp' ) or diag( "testing MONTHNUM2 regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'MONTHDAY'} . ')';
	my $to_test = {
		'  a b c=1 d'  => '1',
		'  a b c=12 d' => '12',
		'  a b c=22 d' => '22',
		'  a b c=04 d' => '04',
		'  a b c=31 d' => '31',
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
ok( $worked eq '1', 'MONTHDAY regexp' ) or diag( "testing MONTHDAY regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'DAY'} . ')';
	my $to_test = {
		'  a b c=Mon d'       => 'Mon',
		'  a b c=Monday d'    => 'Monday',
		'  a b c=Tue d'       => 'Tue',
		'  a b c=Tuesday d'   => 'Tuesday',
		'  a b c=Wed d'       => 'Wed',
		'  a b c=Wednesday d' => 'Wednesday',
		'  a b c=Thu d'       => 'Thu',
		'  a b c=Thursday d'  => 'Thursday',
		'  a b c=Fri d'       => 'Fri',
		'  a b c=Friday d'    => 'Friday',
		'  a b c=Sat d'       => 'Sat',
		'  a b c=Saturday d'  => 'Saturday',
		'  a b c=Sun d'       => 'Sun',
		'  a b c=Sunday d'    => 'Sunday',
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
ok( $worked eq '1', 'DAY regexp' ) or diag( "testing DAY regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'YEAR'} . ')';
	my $to_test = {
		'  a b c=11 d'   => '11',
		'  a b c=12 d'   => '12',
		'  a b c=22 d'   => '22',
		'  a b c=04 d'   => '04',
		'  a b c=31 d'   => '31',
		'  a b c=2031 d' => '2031',
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
ok( $worked eq '1', 'YEAR regexp' ) or diag( "testing YEAR regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'HOUR'} . ')';
	my $to_test = {
		'  a b c=1 d'  => '1',
		'  a b c=12 d' => '12',
		'  a b c=22 d' => '22',
		'  a b c=04 d' => '04',
		'  a b c=20 d' => '20',
		'  a b c=0 d'  => '0',
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
ok( $worked eq '1', 'HOUR regexp' ) or diag( "testing HOUR regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'MINUTE'} . ')';
	my $to_test = {
		'  a b c=01 d' => '01',
		'  a b c=12 d' => '12',
		'  a b c=59 d' => '59',
		'  a b c=04 d' => '04',
		'  a b c=20 d' => '20',
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
ok( $worked eq '1', 'MINUTE regexp' ) or diag( "testing MINUTE regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'SECOND'} . ')';
	my $to_test = {
		'  a b c=01 d' => '01',
		'  a b c=12 d' => '12',
		'  a b c=59,333333 d' => '59,333333',
		'  a b c=04:333333 d' => '04:333333',
		'  a b c=20.333333 d' => '20.333333',
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
ok( $worked eq '1', 'SECOND regexp' ) or diag( "testing SECOND regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'LOGLEVEL'} . ')';
	my $to_test = {
		'  a b c=Alert d' => 'Alert',
		'  a b c=alert d' => 'alert',
		'  a b c=ALERT d' => 'ALERT',
		'  a b c=FATAL d' => 'FATAL',
		'  a b c=Fatal d' => 'Fatal',
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
ok( $worked eq '1', 'LOGLEVEL regexp' ) or diag( "testing LOGLEVEL regexp failed ... " . $@ );

$worked = 0;
eval {
	my $regexp  = 'c=(?<TEST>' . $rules->{'vars'}{'TZ'} . ')';
	my $to_test = {
		'  a b c=CDT d' => 'CDT',
		'  a b c=UTC d' => 'UTC',
		'  a b c=EST d' => 'EST',
		'  a b c=CST d' => 'CST',
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
ok( $worked eq '1', 'TZ regexp' ) or diag( "testing TZ regexp failed ... " . $@ );

done_testing($tests);
