package Log::Munger::WhichRuleFile;

use 5.006;
use strict;
use warnings;
use File::ShareDir ();

=head1 NAME

Log::Munger::WhichRuleFile - Returns the location for a rule file for Log::Munger.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::WhichRuleFile;

    my $file_location = Log::Munger::WhichRuleFile->rule_file_location('file'=>'postfix');
    if (!defined($file_location)) {
        print "Not found.\n";
    } else {
        print 'File Location: ' . $file_location . "\n";
    }

=head1 METHODS

=head2 rule_file_location

Returns the full path to the rule file specified.

    - file :: The file to locate. If undef will die.
        Default :: undef

    my $file_location;
    $file_location = Log::Munger::WhichRuleFile->rule_file_location('file'=>'postfix');
    if (!defined($file_location)) {
        print "Not found.\n";
    } else {
        print 'File Location: ' . $file_location . "\n";
    }

=cut

sub rule_file_location {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'file'} ) ) {
		die('$opts{file} is undef');
	}

	if ( $opts{'file'} =~ /^(\/|\.\/|\.\.\/)/ ) {
		if ( -f $opts{'file'} ) {
			return $opts{'file'};
		} elsif ( -f $opts{'file'} . '.yaml' ) {
			return $opts{'file'} . '.yaml';
		} else {
			return undef;
		}
	}

	my @rules_dirs = ( '/etc/log_munger/rules/', '/usr/local/etc/log_munger/rules/' );
	foreach my $rules_dir (@rules_dirs) {
		if ( -d $rules_dir ) {
			if ( -f $rules_dir . '/' . $opts{'file'} ) {
				return $rules_dir . '/' . $opts{'file'};
			} elsif ( -f $rules_dir . '/' . $opts{'file'} . '.yaml' ) {
				return $rules_dir . '/' . $opts{'file'} . '.yaml';
			}

		}
	} ## end foreach my $rules_dir (@rules_dirs)

	my $share_dir = File::ShareDir::dist_dir('Log-Munger');
	if ( -f $share_dir . '/' . $opts{'file'} ) {
		return $share_dir . '/' . $opts{'file'};
	} elsif ( -f $share_dir . '/' . $opts{'file'} . '.yaml' ) {
		return $share_dir . '/' . $opts{'file'} . '.yaml';
	}

	return undef;
} ## end sub rule_file_location
