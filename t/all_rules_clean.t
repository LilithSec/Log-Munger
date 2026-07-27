#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::ShareDir ();

BEGIN {
	use_ok('Log::Munger::RulesTest') || print "Bail out!\n";
}

#
# Discover every shipped rule file (the dist share dir) and assert each one
# tests clean: no fatal, no errors, and full test coverage (no "lacks any
# tests" warnings). This single guard covers every current and future rule
# file so a newly added one cannot ship untested.
#
my $share;
eval { $share = File::ShareDir::dist_dir('Log-Munger'); };
if ( !defined($share) || !-d $share ) {
	plan skip_all => 'dist share dir not found (run make first)';
}

my @files = sort glob("$share/*.yaml");
ok( scalar(@files) > 0, "found rule files in $share" );

# base is a pure primitive library (no rules: section); it is exercised as an
# include by every other file, so testing it standalone is not meaningful.
foreach my $path (@files) {
	my ($name) = $path =~ m{([^/]+)\.yaml\z};
	next if ( $name eq 'base' );

	my $res = Log::Munger::RulesTest->test( 'file' => $name );

	is( $res->{'fatal'}, undef, "$name: no fatal" )
		or diag( $res->{'fatal'} );
	is( scalar( @{ $res->{'errors'} } ), 0, "$name: no errors" )
		or diag( "errors:\n" . join( "\n", @{ $res->{'errors'} } ) );

	my @lacks = grep {/lacks any tests/} @{ $res->{'warnings'} };
	is( scalar(@lacks), 0, "$name: full test coverage (no untested vars/rules)" )
		or diag( "untested:\n" . join( "\n", @lacks ) );
}

done_testing();
