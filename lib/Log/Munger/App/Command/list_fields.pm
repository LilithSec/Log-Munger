package Log::Munger::App::Command::list_fields;

use strict;
use warnings;
use Log::Munger::App -command;
use Log::Munger::RuleFileParser ();

sub opt_spec {
	return ( [ 'f=s', 'Rule file to inspect.' ], );
}

sub abstract { "List the fields a rule file can produce (a schema hint)" }

sub description {
	"Statically lists the named-capture fields the patterns in a rule file can emit, the "
		. "pattern-decompose fields, the dynamic kv-decompose prefixes, and the geoip fields.";
}

sub validate { return 1 }

# pull (?<name> ... capture names out of a resolved regex string
sub _captures {
	my ( $string, $set ) = @_;
	while ( $string =~ /\(\?<([A-Za-z_]\w*)>/g ) {
		$set->{$1} = 1;
	}
	return;
}

sub execute {
	my ( $self, $opts, $args ) = @_;

	if ( !defined( $opts->{'f'} ) ) {
		die('No rule file specified via -f');
	}

	my $rules = Log::Munger::RuleFileParser->new->load( 'file' => $opts->{'f'} );
	my $vars  = ( ref( $rules->{'vars'} ) eq 'HASH' ) ? $rules->{'vars'} : {};

	my %fields;     # static capture names
	my %kv;         # prefix => source field (dynamic)
	my %geoip;      # field => 1

	my @rulelist = ( ref( $rules->{'rules'} ) eq 'ARRAY' ) ? @{ $rules->{'rules'} } : ();
	foreach my $rule (@rulelist) {
		next if ( ref($rule) ne 'HASH' );

		# pattern captures
		foreach my $pattern ( @{ $rule->{'patterns'} } ) {
			next if ( ref($pattern) ne '' );
			my $string = exists( $vars->{$pattern} ) ? $vars->{$pattern} : $pattern;
			_captures( $string, \%fields );
		}

		# decompose (rule-level, else file-level default)
		my $decompose = defined( $rule->{'decompose'} ) ? $rule->{'decompose'} : $rules->{'decompose'};
		if ( ref($decompose) eq 'ARRAY' ) {
			foreach my $d ( @{$decompose} ) {
				next if ( ref($d) ne 'HASH' );
				my $type = defined( $d->{'type'} ) ? $d->{'type'} : 'kv';
				if ( $type eq 'kv' ) {
					my $prefix = defined( $d->{'prefix'} ) ? $d->{'prefix'} : '';
					$kv{$prefix} = $d->{'field'};
				} elsif ( $type eq 'pattern' ) {
					my $string = exists( $vars->{ $d->{'pattern'} } ) ? $vars->{ $d->{'pattern'} } : $d->{'pattern'};
					_captures( $string, \%fields ) if ( defined($string) );
				}
			}
		} ## end if ( ref($decompose) eq...)

		# geoip (rule-level, else file-level default)
		my $g = defined( $rule->{'geoip'} ) ? $rule->{'geoip'} : $rules->{'geoip'};
		if ( ref($g) eq 'ARRAY' ) {
			$geoip{$_} = 1 for ( @{$g} );
		}
	} ## end foreach my $rule (@rulelist)

	print "fields:\n";
	print "  $_\n" for ( sort keys %fields );

	if (%kv) {
		print "\nkv-decompose (dynamic keys):\n";
		foreach my $prefix ( sort keys %kv ) {
			print "  ${prefix}* (from " . $kv{$prefix} . ")\n";
		}
	}

	if (%geoip) {
		print "\ngeoip:\n";
		print "  .geoip.$_\n" for ( sort keys %geoip );
	}

	return;
} ## end sub execute

1;
