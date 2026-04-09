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

	if ( defined( $rules->{'vars'} ) ) {
		if ( ref( $rules->{'vars'} ) ne 'HASH' ) {
			die( '$rules->{vars} exists and is of ref "' . ref( $rules->{'vars'} ) . '" and not HASH' );
		}

		foreach my $item ( keys( %{ $rules->{'vars'} } ) ) {
			if (   ( ref( $rules->{'vars'}{$item} ) ne 'ARRAY' )
				&& ( ref( $rules->{'vars'}{$item} ) ne '' ) )
			{
				die(      '$rules->{vars}{'
						. $item
						. '} is of ref "'
						. ref( $rules->{'vars'}{$item} )
						. '" and not "HASH" or ""' );
			}
			if ( ref( $rules->{'vars'}{$item} ) eq 'ARRAY' ) {
				my $joined = join( '', @{ $rules->{'vars'}{$item} } );
				$rules->{'vars'}{$item} = $joined;
			}
		} ## end foreach my $item ( keys( %{ $rules->{'vars'} } ...))
	} ## end if ( defined( $rules->{'vars'} ) )

	my $tt = Template->new(
		'START_TAG' => '[%--',
		'END_TAG'   => '--%]',
	);

	my @template_hashes         = ( 'vars_templated', 'vars_templated_late' );
	my $vars_templated_late_int = 0;
	while ( defined( $rules->{ 'vars_templated_late' . $vars_templated_late_int } ) ) {
		push( @template_hashes, 'vars_templated_late' . $vars_templated_late_int );
		$vars_templated_late_int++;
	}

	foreach my $template_hash (@template_hashes) {
		if ( defined( $rules->{$template_hash} ) ) {
			if ( ref( $rules->{$template_hash} ) ne 'HASH' ) {
				die(      '$rules->{'
						. $template_hash
						. '} exists and is of ref "'
						. ref( $rules->{$template_hash} )
						. '" and not HASH' );
			}

			foreach my $item ( keys( %{ $rules->{$template_hash} } ) ) {
				if (   ( ref( $rules->{$template_hash}{$item} ) ne 'ARRAY' )
					&& ( ref( $rules->{$template_hash}{$item} ) ne '' ) )
				{
					die(      '$rules->{'
							. $template_hash . '}{'
							. $item
							. '} is of ref "'
							. ref( $rules->{'vars'}{$item} )
							. '" and not "HASH" or ""' );
				} ## end if ( ( ref( $rules->{$template_hash}{$item...})))
				if ( ref( $rules->{$template_hash}{$item} ) eq 'ARRAY' ) {
					my $joined = join( '', @{ $rules->{$template_hash}{$item} } );
					$rules->{$template_hash}{$item} = $joined;
				}

				my $results;
				$tt->process( \$rules->{$template_hash}{$item}, $rules->{'vars'}, \$results )
					|| die( 'Failed to process $rules->{' . $template_hash . '}{' . $item . '} ... ' . $tt->error() );
				$rules->{'vars'}{$item} = $results;
			} ## end foreach my $item ( keys( %{ $rules->{$template_hash...}}))
		} ## end if ( defined( $rules->{$template_hash} ) )
	} ## end foreach my $template_hash (@template_hashes)

	return $rules;
} ## end sub load
