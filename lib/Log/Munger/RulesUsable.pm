package Log::Munger::RulesUsable;

use 5.006;
use strict;
use warnings;

=head1 NAME

Log::Munger::RulesUsable - Test if a rules hash is usable or not.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 METHODS

=head2 usable

Test of the rules are usable or not.

This does not test if they work as intended or not, just that the everything is sane
enought to run with out causing issues.

This is meant to be a faster option than doing a full test for when starting

    - rules :: The rules hash to rest
        default :: undef

=cut

sub usable {
	my ( $blank, %opts ) = @_;

	if (!defined($opts{'rules'})){
		die('$opts{rules} is undef');
	}elsif(ref($opts{'rules'}) ne 'HASH'){
		die('$opts{rules} has a ref of "'.ref($opts{'rules'}).'" and not "HASH"');
	}elsif(!defined($opts{'rules'}{'rules'})){
		die('$opts{rules}{rules} is undef meaning the rules hash contains no rules');
	}elsif(ref($opts{'rules'}{'rules'}) ne 'ARRAY'){
		die('$opts{rules}{rules} has a ref of "'.ref($opts{'rules'}{'rules'}).'" and not "ARRAY"');
	}elsif(!defined($opts{'rules'}{'rules'}[0])){
		die('$opts{rules}{rules}[0] is undef meaning the rules hash contains no rules');
	}

	return 1;
} ## end sub usable
