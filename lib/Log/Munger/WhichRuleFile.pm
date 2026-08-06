package Log::Munger::WhichRuleFile;

use 5.006;
use strict;
use warnings;
use File::ShareDir ();

=head1 NAME

Log::Munger::WhichRuleFile - Resolves a Log::Munger rule file name to a path.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::WhichRuleFile;

    my $file_location = Log::Munger::WhichRuleFile->rule_file_location( 'file' => 'postfix' );
    if ( !defined($file_location) ) {
        print "Not found.\n";
    } else {
        print 'File Location: ' . $file_location . "\n";
    }

Rule files are looked for in three places, and whichever is found first wins. That
ordering is what lets a local file shadow one shipped with the distribution: drop
your own C<sshd.yaml> in F</etc/log_munger/rules/> and every reference to C<sshd>
picks it up instead, with nothing else needing to change.

C<log_munger which_rule_file -f E<lt>nameE<gt>> is this method on the command line,
and C<log_munger list -p> shows what every discoverable name currently resolves to.

=head1 METHODS

=head2 rule_file_location

Returns the path a rule file name resolves to.

A name beginning with C</>, C<./>, or C<../> is treated as a path and used as
given. Anything else is searched for, in order, in:

=over 4

=item 1. F</etc/log_munger/rules/>

=item 2. F</usr/local/etc/log_munger/rules/>

=item 3. the distribution share directory, C<< File::ShareDir::dist_dir('Log-Munger') >>

=back

Each location is tried twice, first for the name as given and then with C<.yaml>
appended, so C<sshd> and C<sshd.yaml> both find the same file.

    - file :: The name or path to locate. Required.
        Default :: undef

Returns the resolved path, or undef if the name turned up nothing anywhere. Dies
only if C<file> is undef.

    my $file_location = Log::Munger::WhichRuleFile->rule_file_location( 'file' => 'postfix' );

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
