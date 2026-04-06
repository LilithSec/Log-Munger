package Log::Munger::RuleFileParser;

use 5.006;
use strict;
use warnings;
use YAML::XS                   qw(Load);
use Log::Munger::WhichRuleFile ();
use File::Slurp                qw(read_file);
use Template;
use Hash::Merge ();

=head1 NAME

Log::Munger::RuleFileParser - Extracts info from 

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger;

    my $foo = Log::Munger->new();
    ...

=head1 METHODS

=head2 new

=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		'order'      => [],
		'mungers'    => {},
		'share_dir'  => File::ShareDir::dist_dir('Log-Munger'),
		'rules_dirs' => [ '/etc/log_munger/rules/', '/usr/local/etc/log_munger/rules/', ],
	};
	bless $self;

	return $self;
} ## end sub new

=head2 load

Loads a munger rule file.

    - file :: The file to load. Required.
        Default :: undef

=cut

sub load {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	} elsif ( ref( $opts{'file'} ) ne '' ) {
		die( '$opts{file} ref is "' . ref( $opts{'file'} ) . '" and not ""' );
	}

	my $file_location = Log::Munger::WhichRuleFile->rule_file_location( 'file' => $opts{'file'} );

	my $rules;
	eval {
		my $rules_yaml_raw = read_file($file_location);
		$rules = Load($rules_yaml_raw);
		if ( !defined($rules) ) {
			die('Load(read_file($file_location)) returned undef');
		}
		if ( ref($rules) ne 'HASH' ) {
			die( 'Load(read_file($file_location)) returned a ref of "' . ref($rules) . '" and not "HASH"' );
		}
	};
	if ($@) {
		die( 'Failed to read in and parse "' . $file_location . '"... ' . $@ );
	}

	if ( defined( $rules->{'includes'} ) ) {
		if ( ref( $rules->{'includes'} ) ne 'ARRAY' ) {
			die(      '.includes in "'
					. $file_location
					. '" is of ref "'
					. ref( $rules->{'incudes'} )
					. '" and not "ARRAY"' );
		}
		if ( defined( $rules->{'includes'}[0] ) ) {
			my $merger = Hash::Merge->new('RIGHT_PRECEDENT');
			my %included;
			my $include_int = 0;
			my %left_side   = %{$rules};
			while ( defined( $rules->{'includes'}[$include_int] ) ) {
				if ( ref( $rules->{'includes'}[$include_int] ) ne '' ) {
					die(      '.includes.'
							. $include_int
							. ' is a ref of "'
							. ref( $rules->{'includes'}[$include_int] )
							. '" and not ""' );
				}

				if ( !$included{ $rules->{'includes'}[$include_int] } ) {
					$included{ $rules->{'includes'}[$include_int] } = 1;

					my $include_location = Log::Munger::WhichRuleFile->rule_file_location(
						'file' => $rules->{'includes'}[$include_int] );
					my $rule_include;
					eval {
						my $raw_rules_include = read_file($include_location);
						$rule_include = Load($raw_rules_include);
						if ( !defined($rule_include) ) {
							die( 'Load(read_file("' . $include_location . '")) returned undef for include' );
						}
						if ( ref($rule_include) ne 'HASH' ) {
							die(      'Load(read_file("'
									. $include_location
									. '")) returned a ref of "'
									. ref($rule_include)
									. '" and not "HASH"' );
						}
					};

					$rules = $merger->merge( \%left_side, $rule_include );
				} ## end if ( !$included{ $rules->{'includes'}[$include_int...]})

				$include_int++;
			} ## end while ( defined( $rules->{'includes'}[$include_int...]))
		} ## end if ( defined( $rules->{'includes'}[0] ) )
	} ## end if ( defined( $rules->{'includes'} ) )

	return $rules;
} ## end sub load
