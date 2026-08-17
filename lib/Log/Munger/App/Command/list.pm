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
	"Lists the rule files found across /etc/log_munger/rules, /usr/local/etc/log_munger/rules, and
the dist share dir, in that precedence order. A name found in an earlier directory shadows the
same name in a later one, and only the one that would actually be used is listed.

Add -p to see what each name resolves to.
";
}

sub validate { return 1 }

# The directories rule files are looked for in, in precedence order.
#
# This mirrors the search order in Log::Munger::WhichRuleFile, which resolves one
# name at a time and so has no need to enumerate the directories. Listing wants
# them as a list, hence the second copy.
#
# The share dir lookup is wrapped in an eval because File::ShareDir::dist_dir dies
# when the distribution is not installed. Running out of a checkout is a perfectly
# normal thing to be doing, so that is treated as one fewer place to look rather
# than as an error.
#
# Takes no args.
#
# Returns a list of directory paths, highest precedence first. They are not
# checked for existence here; the caller skips any that are missing.
#
#     foreach my $dir ( _search_dirs() ) { ... }
sub _search_dirs {
	my @dirs = ( '/etc/log_munger/rules', '/usr/local/etc/log_munger/rules' );
	if ( defined( $ENV{'LOG_MUNGER_RULES_DIR'} ) && length( $ENV{'LOG_MUNGER_RULES_DIR'} ) ) {
		unshift( @dirs, $ENV{'LOG_MUNGER_RULES_DIR'} );
	}
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
