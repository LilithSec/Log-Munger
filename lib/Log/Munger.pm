package Log::Munger;

use 5.006;
use strict;
use warnings;
use Log::Munger::LogProcessor ();

=head1 NAME

Log::Munger - Extracts info from

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

Creates a new muncher. Rule files may be supplied up front and/or added later
via L</load>.

    my $munger = Log::Munger->new( 'rules' => [ 'base', 'postfix' ] );
    my $munger = Log::Munger->new( 'rules' => ['postfix'], 'geoip' => '/path/to/GeoLite2-City.mmdb' );

    - rules :: Rule files to load. The taken value is an array.
        Default :: undef

    - geoip :: Path to a MaxMind .mmdb database. When set, rules that flag
        captured fields with a C<geoip:> list have those looked up, with the
        result stored under C<< $result->{geoip}{$field} >>.
        Default :: undef (geoip disabled)

=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		'rule_files' => [],
		'processor'  => undef,
		'geoip'      => $opts{'geoip'},
	};
	bless $self;

	if ( defined( $opts{'rules'} ) ) {
		if ( ref( $opts{'rules'} ) ne 'ARRAY' ) {
			die( '$opts{rules} has a ref of "' . ref( $opts{'rules'} ) . '" and not "ARRAY"' );
		}
		push( @{ $self->{'rule_files'} }, @{ $opts{'rules'} } );
		$self->_build_processor;
	}

	return $self;
} ## end sub new

=head2 load

Loads an additional munger rule file and rebuilds the processor.

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

	push( @{ $self->{'rule_files'} }, $opts{'file'} );
	$self->_build_processor;

	return 1;
} ## end sub load

=head2 process_item

Runs a decoded log record through the loaded rules and returns the named
captures of the first matching rule, or undef if nothing matched (or no rules
have been loaded).

    - item :: The decoded log record (a hash ref), or a bare string. A bare
        string is treated as a raw log line and matched as the C<MESSAGE> field.
        If given, C<item> takes precedence over the field args below.
        Default :: undef

    - message :: The raw log message, assembled into C<< { MESSAGE => ... } >>.
        Default :: undef

    - program :: Optional C<PROGRAM> field (the usual daemon-rule gate).
        Default :: undef

    - priority :: Optional C<PRIORITY> field.
        Default :: undef

    - facility :: Optional C<FACILITY> field.
        Default :: undef

    my $fields = $munger->process_item( 'item' => $json );
    my $fields = $munger->process_item( 'item' => $raw_access_log_line );

    # from a syslog reader that already has the fields split out (e.g. baphomet):
    my $fields = $munger->process_item(
        'message'  => $message,
        'program'  => $program,
        'priority' => $priority,
        'facility' => $facility,
    );

=cut

sub process_item {
	my ( $self, %opts ) = @_;

	if ( !defined( $self->{'processor'} ) ) {
		return undef;
	}

	return $self->{'processor'}->process_item(%opts);
} ## end sub process_item

=head2 explain_item

Like L</process_item> but returns match metadata (which rule/pattern fired plus
the fields) instead of just the fields. See
L<Log::Munger::LogProcessor/explain_item>.

    my $why = $munger->explain_item( 'item' => $json );

=cut

sub explain_item {
	my ( $self, %opts ) = @_;

	if ( !defined( $self->{'processor'} ) ) {
		return { 'matched' => 0 };
	}

	return $self->{'processor'}->explain_item(%opts);
} ## end sub explain_item

# (re)builds the LogProcessor from the currently loaded rule file names
sub _build_processor {
	my ($self) = @_;

	my %args = ( 'rules' => $self->{'rule_files'} );
	$args{'geoip'} = $self->{'geoip'} if ( defined( $self->{'geoip'} ) );

	$self->{'processor'} = Log::Munger::LogProcessor->new(%args);

	return $self->{'processor'};
} ## end sub _build_processor

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
