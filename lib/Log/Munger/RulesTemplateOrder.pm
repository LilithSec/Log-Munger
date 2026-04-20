package Log::Munger::RulesTemplateOrder;

use 5.006;
use strict;
use warnings;
use Algorithm::Dependency::Ordered;
use Algorithm::Dependency::Source::HoA;
use Log::Munger::RuleFileParser;

=head1 NAME

Log::Munger::RulesTemplateOrder - Returns the location for a rule file for Log::Munger.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::RulesTemplateOrder;

    my @order = Log::Munger::WhichRuleFile->order_for_rules_hash('rules'=>$rules_hash);
    if ($@) {
      die( '' );
    }

=head1 METHODS

=cut

sub order_for_rules_hash {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'rules'} ) ) {
		die('$opts{rules} is undef');
	} elsif ( ref( $opts{'rules'} ) ne 'HASH' ) {
		die( '$opts{rules} has a ref of "' . ref( $opts{'rules'} ) . '" and not HASH' );
	}
	my $rules = $opts{'rules'};

	my $depends_info = Log::Munger::RulesTemplateOrder->depends_for_rules_hash( 'rules' => $rules );

	my @vars;
	if ( defined( $rules->{'vars'} ) ) {
		@vars = keys( %{ $rules->{'vars'} } );
	}

	# need to do this or Algorithm::Dependency::Ordered will error
	foreach my $var (@vars) {
		$depends_info->{$var} = [];
	}

	my $deps_source = Algorithm::Dependency::Source::HoA->new($depends_info);
	my $dep         = Algorithm::Dependency::Ordered->new(
		source   => $deps_source,
		selected => \@vars,
	) or die 'Failed to set up dependency algorithm';

	return $dep->schedule_all();
} ## end sub order_for_rules_hash

=head2 depends_for_rules_hash

Returns the full path to the rule file specified.

    - rules :: The rules hash to process.
        default :: undef

=cut

sub depends_for_rules_hash {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'rules'} ) ) {
		die('$opts{rules} is undef');
	} elsif ( ref( $opts{'rules'} ) ne 'HASH' ) {
		die( '$opts{rules} has a ref of "' . ref( $opts{'rules'} ) . '" and not HASH' );
	}
	my $rules = $opts{'rules'};

	if ( defined( $rules->{'vars'} ) & ( ref( $rules->{'vars'} ) ne 'HASH' ) ) {
		die( '$opts{rules}{vars} has a ref of "' . ref( $rules->{'vars'} ) . '" and not HASH' );
	} elsif ( defined( $rules->{'vars_templated'} ) & ( ref( $rules->{'vars_templated'} ) ne 'HASH' ) ) {
		die( '$opts{rules}{vars_templated} has a ref of "' . ref( $rules->{'vars_templated'} ) . '" and not HASH' );
	}

	my @templated_vars;
	if ( !defined( $rules->{'vars_templated'} ) ) {
		return {};
	} else {
		# check this here so we die earlier instead of later after doing more processing
		@templated_vars = keys( %{ $rules->{'vars_templated'} } );
		foreach my $var (@templated_vars) {
			if ( ref( $rules->{'vars_templated'}{$var} ) ne '' ) {
				die(      '$opts{rules}{vars_templated}{'
						. $var
						. '} has a ref of "'
						. ref( $rules->{'vars_templated'}{$var} )
						. '" and not ""' );
			}
		}
	} ## end else [ if ( !defined( $rules->{'vars_templated'} ...))]

	my $template_depends = {};
	foreach my $var (@templated_vars) {
		my @has_vars;
		my $string        = $rules->{'vars_templated'}{$var};
		my $loop_continue = 1;
		while ($loop_continue) {
			if ( $string =~ /(?<TEMPLATE>\[\% +(?<VAR>[A-Za-z0-9\_]+) +\%\])/ ) {
				my %found_items = %+;
				push( @has_vars, $found_items{'VAR'} );
				my $replacement_regexp = quotemeta( $found_items{'TEMPLATE'} );
				$string =~ s/$replacement_regexp//g;
			} else {
				$loop_continue = 0;
			}
		} ## end while ($loop_continue)
		$template_depends->{$var} = \@has_vars;
	} ## end foreach my $var (@templated_vars)

	return $template_depends;
} ## end sub depends_for_rules_hash

sub order_for_rules_file {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	} elsif ( ref( $opts{'file'} ) ne '' ) {
		die( '$opts{file} ref is "' . ref( $opts{'file'} ) . '" and not ""' );
	}

	my $rules;
	eval {
		my $parser = Log::Munger::RuleFileParser->new;
		$rules = $parser->load_no_templating( 'file' => $opts{'file'} );
	};
	if ($@) {
		die( 'Failed to call load_no_templating for "' . $opts{'file'} . '"... ' . $@ );
	}

	return Log::Munger::RulesTemplateOrder->order_for_rules_hash( 'rules' => $rules );
} ## end sub order_for_rules_file

sub depends_for_rules_file {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	} elsif ( ref( $opts{'file'} ) ne '' ) {
		die( '$opts{file} ref is "' . ref( $opts{'file'} ) . '" and not ""' );
	}

	my $rules;
	eval {
		my $parser = Log::Munger::RuleFileParser->new;
		$rules = $parser->load_no_templating( 'file' => $opts{'file'} );
	};
	if ($@) {
		die( 'Failed to call load_no_templating for "' . $opts{'file'} . '"... ' . $@ );
	}

	return Log::Munger::RulesTemplateOrder->depends_for_rules_hash( 'rules' => $rules );
} ## end sub depends_for_rules_file
