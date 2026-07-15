package Log::Munger::App::Command::list;

use strict;
use warnings;
use Log::Munger::App -command;
use File::ShareDir ();

sub opt_spec {
	return ( [ 'paths|p', 'Also show the resolved path of each rule file.' ], );
}

sub abstract { "List the rule files discoverable across the search path" }

sub description {
	"Lists the rule files found across /etc/log_munger/rules, /usr/local/etc/log_munger/rules, "
		. "and the dist share dir (in that precedence order -- an earlier one shadows a later one).";
}

sub validate { return 1 }

sub _search_dirs {
	my @dirs = ( '/etc/log_munger/rules', '/usr/local/etc/log_munger/rules' );
	my $share;
	eval { $share = File::ShareDir::dist_dir('Log-Munger'); };
	push( @dirs, $share ) if ( defined($share) );
	return @dirs;
}

sub execute {
	my ( $self, $opts, $args ) = @_;

	my %seen;    # name => path (first, highest-precedence wins)
	foreach my $dir ( _search_dirs() ) {
		next if ( !-d $dir );
		foreach my $file ( sort glob("$dir/*.yaml") ) {
			my ($name) = $file =~ m{([^/]+)\.yaml\z};
			next if ( !defined($name) );
			$seen{$name} = $file if ( !exists( $seen{$name} ) );
		}
	}

	foreach my $name ( sort keys %seen ) {
		if ( $opts->{'paths'} ) {
			printf( "%-24s %s\n", $name, $seen{$name} );
		} else {
			print "$name\n";
		}
	}

	return;
} ## end sub execute

1;
