package Log::Munger::App::Command::test_all;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::RulesTest ();
use File::ShareDir         ();

sub opt_spec {
	return ( [ 'verbose|v', 'Print each error and warning, not just counts.' ], );
}

sub abstract { "Run the built-in tests for every discoverable rule file" }

sub description {
	"Runs Log::Munger::RulesTest over every rule file found across the search path and prints a "
		. "pass/fail summary. Exits non-zero if any file has errors (or fails to load).";
}

sub validate { return 1 }

sub _names {
	my @dirs = ( '/etc/log_munger/rules', '/usr/local/etc/log_munger/rules' );
	my $share;
	eval { $share = File::ShareDir::dist_dir('Log-Munger'); };
	push( @dirs, $share ) if ( defined($share) );

	my %seen;
	foreach my $dir (@dirs) {
		next if ( !-d $dir );
		foreach my $file ( sort glob("$dir/*.yaml") ) {
			my ($name) = $file =~ m{([^/]+)\.yaml\z};
			$seen{$name} = 1 if ( defined($name) );
		}
	}
	my @names = sort keys %seen;
	return @names;
} ## end sub _names

sub execute {
	my ( $self, $opts, $args ) = @_;

	my @names = _names();
	if ( !@names ) {
		print "no rule files found\n";
		return;
	}

	my $failed = 0;
	foreach my $name (@names) {
		my $res = Log::Munger::RulesTest->test( 'file' => $name );

		if ( defined( $res->{'fatal'} ) ) {
			$failed++;
			printf( "FAIL  %-24s fatal: %s\n", $name, $res->{'fatal'} );
			next;
		}

		my $errors   = scalar( @{ $res->{'errors'} } );
		my $warnings = scalar( @{ $res->{'warnings'} } );
		$failed++ if ($errors);
		printf( "%-5s %-24s %d error(s), %d warning(s)\n", ( $errors ? 'FAIL' : 'ok' ), $name, $errors, $warnings );

		if ( $opts->{'verbose'} ) {
			print "        ERROR: $_\n"   for ( @{ $res->{'errors'} } );
			print "        warn:  $_\n"   for ( @{ $res->{'warnings'} } );
		}
	} ## end foreach my $name (@names)

	printf( "\n%d file(s), %d failed\n", scalar(@names), $failed );
	exit(1) if ($failed);

	return;
} ## end sub execute

1;
