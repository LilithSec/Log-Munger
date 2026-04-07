#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN {
	use_ok('Log::Munger::RuleFileParser') || print "Bail out!\n";
}

my $tests = 19;

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

done_testing($tests);
