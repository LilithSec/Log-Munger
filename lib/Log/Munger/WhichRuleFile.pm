package Log::Munger::WhichRuleFile;

use 5.006;
use strict;
use warnings;
use File::ShareDir;

=head1 NAME

Log::Munger::WhichRuleFile - Extracts info from 

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

	if ( $opts{'file'} =~ /^\// ) {
		if ( -f $opts{'file'} ) {
			return $opts{'file'};
		} elsif ( -f $opts{'file'} . '.yaml' ) {
			return $opts{'file'} . '.yaml';
		} else {
			return undef;
		}
	}

	my @rules_dirs=('/etc/log_munger/rules/', '/usr/local/etc/log_munger/rules/');
	foreach my $rules_dir ( @rules_dirs ) {
		if ( -d $rules_dir ) {
			if ( -f $rules_dir . '/' . $opts{'file'} ) {
				return $rules_dir . '/' . $opts{'file'};
			} elsif ( -f $rules_dir . '/' . $opts{'file'} . '.yaml' ) {
				return $rules_dir . '/' . $opts{'file'} . '.yaml';
			}

		}
	} ## end foreach my $rules_dir ( @{ $self->{'rules_dirs'...}})

	my $share_dir=File::ShareDir::dist_dir('Log-Munger');
	if ( $share_dir . '/' . $opts{'file'} ) {
		return $share_dir . '/' . $opts{'file'};
	} elsif ( $share_dir . '/' . $opts{'file'} . '.yaml' ) {
		return $share_dir . '/' . $opts{'file'} . '.yaml';
	}

	return undef;
} ## end sub rule_file_location

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-log-munger at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Log-Munger>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Log::Munger


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Log-Munger>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Log-Munger>

=item * Search CPAN

L<https://metacpan.org/release/Log-Munger>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 3, June 2007


=cut

1;    # End of Log::Munger
