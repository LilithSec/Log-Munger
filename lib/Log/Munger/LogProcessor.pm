package Log::Munger::LogProcessor;

use 5.006;
use strict;
use warnings;
use Scalar::Util qw(looks_like_number);
use JSON                        ();
use Log::Munger::RuleFileParser ();
use Log::Munger::RulesUsable    ();

# the "json" decompose type decodes with JSON::decode_json (utf8-on, and backed
# by JSON::XS when installed via the JSON front end) so it handles a raw-bytes
# MESSAGE without a separate decode step.

=head1 NAME

Log::Munger::LogProcessor - Loads rule files and enriches log items via their C<rules:> dispatch section.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Log::Munger::LogProcessor;

    my $processor = Log::Munger::LogProcessor->new( 'rules' => [ 'base', 'postfix' ] );

    my $fields = $processor->process_item( 'item' => $decoded_log_hashref );
    if ( defined($fields) ) {
        # $fields is a hashref of the named captures from the first matching rule
    }

Each named rule file is loaded and its C<rules:> section compiled into an ordered,
merged dispatch list. A rule file with no C<rules:> section (a pure primitive
library such as C<base>) is accepted and skipped for dispatch.

A rule dispatches when B<all> of its gates pass B<and> one of its patterns matches
the target field. Gates and patterns are both first-match-wins, and rules are
tried in load order (files in the order given, rules in file order).

=head1 METHODS

=head2 new

Loads and compiles the named rule files.

    - rules :: Rule files to load. The taken value is an array.
        default :: undef (required)

    - geoip :: Path to a MaxMind .mmdb database. When given, rules may flag
        captured fields (via a rule-level or file-level C<geoip:> list) whose
        values are looked up and stored under C<< $result->{geoip}{$field} >>.
        Requires IP::Geolocation::MMDB (a soft dependency, only loaded when this
        option is used).
        default :: undef (geoip disabled)

=cut

sub new {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{'rules'} ) ) {
		die('$opts{rules} is undef');
	} elsif ( ref( $opts{'rules'} ) ne 'ARRAY' ) {
		die( '$opts{rules} has a ref of "' . ref( $opts{'rules'} ) . '" and not "ARRAY"' );
	} elsif ( !defined( $opts{'rules'}[0] ) ) {
		die('$opts{rules}[0] is undef... no rules have been specified to use');
	}

	my $self = {
		'rules'        => [],       # compiled rules, ordered and merged across files
		'rule_files'   => [],       # names of the files loaded, in order
		'geoip_reader' => undef,    # IP::Geolocation::MMDB, if geoip is enabled
	};
	bless $self;

	# geoip is an opt-in feature with a soft dependency: only when a database
	# path is given do we require IP::Geolocation::MMDB and open the database
	if ( defined( $opts{'geoip'} ) ) {
		if ( ref( $opts{'geoip'} ) ne '' ) {
			die( '$opts{geoip} has a ref of "' . ref( $opts{'geoip'} ) . '" and not "" (a database path)' );
		}
		my $have_reader = eval { require IP::Geolocation::MMDB; 1; };
		if ( !$have_reader ) {
			die( 'geoip was requested but IP::Geolocation::MMDB is not installed... ' . $@ );
		}
		eval { $self->{'geoip_reader'} = IP::Geolocation::MMDB->new( 'file' => $opts{'geoip'} ); };
		if ($@) {
			die( 'Failed to open the geoip database "' . $opts{'geoip'} . '"... ' . $@ );
		}
	}

	my $parser = Log::Munger::RuleFileParser->new;

	my $rules_int = 0;
	while ( defined( $opts{'rules'}[$rules_int] ) ) {
		my $name = $opts{'rules'}[$rules_int];

		# RuleFileParser->load resolves the name (or path) itself via
		# WhichRuleFile, so do not pre-resolve here -- a pre-resolved
		# dist-share path would fail the parser's own re-resolution
		my $rules;
		eval { $rules = $parser->load( 'file' => $name ); };
		if ($@) {
			die( 'Failed to load $opts{rules}[' . $rules_int . '], "' . $name . '"... ' . $@ );
		}

		# a file used purely as a primitive library (e.g. base) has no rules:
		# section; it is legal to list it, it just contributes no dispatch rules
		if ( !defined( $rules->{'rules'} ) ) {
			push( @{ $self->{'rule_files'} }, $name );
			$rules_int++;
			next;
		}

		eval { Log::Munger::RulesUsable->usable( 'rules' => $rules ); };
		if ($@) {
			die( '.rules in "' . $name . '" is not usable... ' . $@ );
		}

		my $vars = $rules->{'vars'};
		if ( ref($vars) ne 'HASH' ) {
			$vars = {};
		}

		# file-level geoip / decompose / convert defaults for every rule in the
		# file that does not carry its own
		my $file_geoip     = $rules->{'geoip'};
		my $file_decompose = $rules->{'decompose'};
		my $file_convert   = $rules->{'convert'};

		my $rule_int = 0;
		foreach my $rule ( @{ $rules->{'rules'} } ) {
			my $compiled;
			eval {
				$compiled = $self->_compile_rule(
					'rule'              => $rule,
					'vars'              => $vars,
					'default_geoip'     => $file_geoip,
					'default_decompose' => $file_decompose,
					'default_convert'   => $file_convert,
				);
			};
			if ($@) {
				die( 'Failed to compile .rules[' . $rule_int . '] in "' . $name . '"... ' . $@ );
			}
			push( @{ $self->{'rules'} }, $compiled );
			$rule_int++;
		} ## end foreach my $rule ( @{ $rules->{'rules'} } )

		push( @{ $self->{'rule_files'} }, $name );
		$rules_int++;
	} ## end while ( defined( $opts{'rules'}[$rules_int...]))

	return $self;
} ## end sub new

=head2 process_item

Runs an item through the compiled rules and returns the named captures of the
first matching rule.

The item may be given directly with C<item>, or assembled from the individual
syslog fields with C<message> (plus the optional C<program> / C<priority> /
C<facility>). This lets a caller that already has the fields split out (a syslog
reader, C<baphomet>, etc.) hand them over without building the record hash
itself.

    - item :: The decoded log record (a hash ref), or a bare string. A bare
        string is treated as a raw log line and matched as the C<MESSAGE> field,
        so callers feeding whole log lines (e.g. apache/nginx access logs) need
        not wrap them. If given, C<item> takes precedence and the C<message> /
        C<program> / C<priority> / C<facility> args below are ignored.
        default :: undef

    - message :: The raw log message; assembled into C<< { MESSAGE => ... } >>.
        default :: undef

    - program :: Adds a C<PROGRAM> field (the usual gate for daemon rule files).
        default :: undef

    - priority :: Adds a C<PRIORITY> field.
        default :: undef

    - facility :: Adds a C<FACILITY> field.
        default :: undef

    my $fields = $processor->process_item( 'item' => $decoded_hashref );
    my $fields = $processor->process_item( 'message' => $line, 'program' => 'sshd' );

Returns a hash ref of the winning pattern's named captures on a match (which may
be an empty hash ref if the pattern had no named captures), or C<undef> if no rule
matched. This method never dies: a bad item or a pathological pattern yields
C<undef> so a single log line can never cost the caller.

=cut

sub process_item {
	my ( $self, %opts ) = @_;

	my $match = $self->_run( $self->_item_from_opts(%opts) );
	return $match->{'matched'} ? $match->{'fields'} : undef;
} ## end sub process_item

=head2 explain_item

Like L</process_item> but returns match metadata instead of just the fields,
for tooling that needs to know I<which> rule fired. Accepts the same arguments as
L</process_item> (C<item>, or C<message> plus optional C<program> / C<priority> /
C<facility>). Returns a hash ref:

    { matched => 0 }                                         # nothing matched
    { matched => 1, rule => <name>, pattern => <index>,
      field => <target field>, fields => { ...captures... } } # a rule fired

Never dies.

=cut

sub explain_item {
	my ( $self, %opts ) = @_;

	return $self->_run( $self->_item_from_opts(%opts) );
} ## end sub explain_item

=head2 _item_from_opts

Internal. Resolves the item to run from the caller's arguments. An explicit
C<item> (hash ref or bare string) is returned as-is for backward compatibility.
Otherwise, when C<message> is given, a record hash is assembled from it plus any
of the optional C<program> / C<priority> / C<facility> fields (mapped to the
syslog-ng-style upper-case keys C<PROGRAM> / C<PRIORITY> / C<FACILITY> that rule
gates match on). Returns C<undef> when neither C<item> nor C<message> is given
(which C<_run> treats as a non-match).

=cut

sub _item_from_opts {
	my ( $self, %opts ) = @_;

	# an explicit item wins, preserving the original hashref/bare-string behavior
	return $opts{'item'} if ( exists( $opts{'item'} ) );

	# nothing to assemble
	return undef if ( !defined( $opts{'message'} ) );

	my $item = { 'MESSAGE' => $opts{'message'} };
	$item->{'PROGRAM'}  = $opts{'program'}  if ( defined( $opts{'program'} ) );
	$item->{'PRIORITY'} = $opts{'priority'} if ( defined( $opts{'priority'} ) );
	$item->{'FACILITY'} = $opts{'facility'} if ( defined( $opts{'facility'} ) );

	return $item;
} ## end sub _item_from_opts

=head2 _run

Internal. The shared matcher for L</process_item> and L</explain_item>. Coerces a
bare-string item to C<< { MESSAGE => $string } >>, walks the rules, and on the
first gate-passing pattern match runs decompose -> geoip -> convert. Returns the
match-metadata hash (see L</explain_item>). Never dies.

=cut

sub _run {
	my ( $self, $item ) = @_;

	# a bare string is treated as a raw log line and matched as MESSAGE, so
	# callers feeding whole log lines (apache/nginx access logs, etc.) do not
	# have to wrap them in a hash themselves
	if ( defined($item) && ref($item) eq '' ) {
		$item = { 'MESSAGE' => $item };
	}
	if ( !defined($item) || ref($item) ne 'HASH' ) {
		return { 'matched' => 0 };
	}

	my $result = { 'matched' => 0 };
	eval {
		RULE: foreach my $rule ( @{ $self->{'rules'} } ) {

			# gates: every gate must pass (ANDed)
			foreach my $gate ( @{ $rule->{'gate'} } ) {
				my $value = $item->{ $gate->{'field'} };
				# an absent, undef, or non-scalar gate field fails the gate
				if ( !defined($value) || ref($value) ne '' ) {
					next RULE;
				}
				my $gate_hit = 0;
				if ( $gate->{'literals'}{$value} ) {
					$gate_hit = 1;
				} else {
					foreach my $re ( @{ $gate->{'regexps'} } ) {
						if ( $value =~ $re ) {
							$gate_hit = 1;
							last;
						}
					}
				}
				if ( !$gate_hit ) {
					next RULE;
				}
			} ## end foreach my $gate ( @{ $rule->{'gate'} } )

			# target field to munge
			my $target = $item->{ $rule->{'field'} };
			if ( !defined($target) || ref($target) ne '' ) {
				next RULE;
			}

			# patterns: first match wins
			my $pattern_int = 0;
			foreach my $pattern ( @{ $rule->{'patterns'} } ) {
				if ( $target =~ $pattern ) {
					# copy %+ immediately, before any later match can clobber it
					my %captures = %+;
					# decompose first (it can produce fields geoip then looks up)
					if ( @{ $rule->{'decompose'} } ) {
						$self->_decompose( $rule, \%captures );
					}
					if ( $self->{'geoip_reader'} && @{ $rule->{'geoip'} } ) {
						$self->_geoip_enrich( $rule, \%captures );
					}
					# coerce numeric fields last, after geoip has seen the
					# string addresses
					if ( keys( %{ $rule->{'convert'} } ) ) {
						$self->_convert( $rule, \%captures );
					}
					$result = {
						'matched' => 1,
						'rule'    => $rule->{'name'},
						'pattern' => $pattern_int,
						'field'   => $rule->{'field'},
						'fields'  => \%captures,
					};
					last RULE;
				} ## end if ( $target =~ $pattern)
				$pattern_int++;
			} ## end foreach my $pattern ( @{ $rule...})
		} ## end RULE: foreach my $rule ( @{ $self->{'rules'...}})
	};
	if ($@) {
		return { 'matched' => 0 };
	}

	return $result;
} ## end sub _run

=head2 _geoip_enrich

Internal. For each of the rule's flagged geoip fields that was captured, looks
the value up in the geoip database and stores the record under
C<< $captures->{geoip}{$field} >>. A field that is undef, empty, not an address,
or absent from the database is simply skipped; a lookup never dies.

=cut

sub _geoip_enrich {
	my ( $self, $rule, $captures ) = @_;

	my %geo;
	foreach my $field ( @{ $rule->{'geoip'} } ) {
		my $address = $captures->{$field};
		next if ( !defined($address) || $address eq '' );

		my $record;
		# record_for_address dies on a non-address; keep that local so a bad
		# value never costs the rest of the enrichment
		eval { $record = $self->{'geoip_reader'}->record_for_address($address); };
		next if ( $@ || !defined($record) );

		$geo{$field} = $record;
	}

	if (%geo) {
		$captures->{'geoip'} = \%geo;
	}

	return;
} ## end sub _geoip_enrich

=head2 _compile_decompose

Internal. Compiles a C<decompose:> list (an array of C<{field, type, ...}>
entries) into runtime structures. Three types are supported:

    - kv      :: split a "k=v k=v" blob into fields. Options: field_split
                 (default " "), value_split (default "="), prefix (default ""),
                 trim (chars stripped from each end of a value), remove. With
                 quoted => true it is quote-aware instead: a value may be
                 "double" or 'single' quoted (quotes stripped, the separator
                 allowed inside them), and pairs are whitespace-separated.
    - pattern :: re-match the field against a named var (or inline regexp),
                 anchored, and merge its named captures. Options: pattern, remove.
    - json    :: JSON-decode the field (for logs that embed a JSON document in a
                 sub-field, e.g. MongoDB). By default the decoded structure is
                 flattened into keys of C<< prefix + path >> joined by C<separator>
                 (default "_"); MongoDB extended-JSON wrappers ({"$date":...},
                 {"$oid":...}, {"$numberLong":...}) collapse to their scalar,
                 booleans normalize to 1/0, and JSON null is skipped. Arrays are
                 keyed by index. Options: prefix (default ""), separator
                 (default "_"), remove, and nested => true (store the decoded
                 structure whole under a single key instead of flattening). A
                 field whose value is not valid JSON is left untouched.

Every entry may set C<< remove: true >> to drop the source field afterwards.

An entry may also carry a C<< tests: [ { input, result }, ... ] >> list:
L<Log::Munger::RulesTest> applies the entry on its own to C<< { field => input } >>
and checks that the resulting captures equal C<result> (which reflects the
entry's C<remove:> setting). The C<tests> key is ignored at runtime.

=cut

sub _compile_decompose {
	my ( $self, $decompose, $vars ) = @_;

	if ( ref($decompose) ne 'ARRAY' ) {
		die( '.decompose has a ref of "' . ref($decompose) . '" and not "ARRAY"' );
	}

	my @compiled;
	my $int = 0;
	foreach my $d ( @{$decompose} ) {
		if ( ref($d) ne 'HASH' ) {
			die( '.decompose[' . $int . '] has a ref of "' . ref($d) . '" and not "HASH"' );
		}
		if ( !defined( $d->{'field'} ) || ref( $d->{'field'} ) ne '' ) {
			die( '.decompose[' . $int . '].field is undef or not a string' );
		}
		my $type = defined( $d->{'type'} ) ? $d->{'type'} : 'kv';
		my $c = {
			'field'  => $d->{'field'},
			'type'   => $type,
			'remove' => ( $d->{'remove'} ? 1 : 0 ),
		};

		if ( $type eq 'kv' ) {
			$c->{'prefix'}      = defined( $d->{'prefix'} )      ? $d->{'prefix'}      : '';
			$c->{'trim'}        = $d->{'trim'};                                            # may be undef
			$c->{'field_split'} = defined( $d->{'field_split'} ) ? $d->{'field_split'} : ' ';
			$c->{'value_split'} = defined( $d->{'value_split'} ) ? $d->{'value_split'} : '=';
			$c->{'quoted'}      = ( $d->{'quoted'} ? 1 : 0 );
			if ( $c->{'field_split'} eq '' ) { die( '.decompose[' . $int . '].field_split is empty' ); }
			if ( $c->{'value_split'} eq '' ) { die( '.decompose[' . $int . '].value_split is empty' ); }
		} elsif ( $type eq 'pattern' ) {
			my $pname = $d->{'pattern'};
			if ( !defined($pname) || ref($pname) ne '' ) {
				die( '.decompose[' . $int . '].pattern is undef or not a string' );
			}
			my $rx_string = exists( $vars->{$pname} ) ? $vars->{$pname} : $pname;
			if ( $rx_string =~ /%\{[^}]*\}/ ) {
				die( '.decompose[' . $int . '].pattern ("' . $pname . '") contains un-degrokked grok "%{...}"' );
			}
			my $rx;
			eval { $rx = qr/\A(?:$rx_string)\z/; };
			if ($@) {
				die( '.decompose[' . $int . '].pattern ("' . $pname . '") does not compile... ' . $@ );
			}
			$c->{'regexp'} = $rx;
		} elsif ( $type eq 'json' ) {
			# JSON-decode the field and either flatten the structure into
			# prefixed keys (default) or store the decoded structure whole
			# (nested => true).
			$c->{'prefix'}    = defined( $d->{'prefix'} )    ? $d->{'prefix'}    : '';
			$c->{'separator'} = defined( $d->{'separator'} ) ? $d->{'separator'} : '_';
			$c->{'nested'}    = ( $d->{'nested'} ? 1 : 0 );
			if ( ref( $c->{'prefix'} ) ne '' ) {
				die( '.decompose[' . $int . '].prefix is not a string' );
			}
			if ( ref( $c->{'separator'} ) ne '' || $c->{'separator'} eq '' ) {
				die( '.decompose[' . $int . '].separator is undef, empty, or not a string' );
			}
		} else {
			die( '.decompose[' . $int . '].type "' . $type . '" is unknown (expected "kv", "pattern", or "json")' );
		}

		push( @compiled, $c );
		$int++;
	} ## end foreach my $d ( @{$decompose} )

	return \@compiled;
} ## end sub _compile_decompose

=head2 _decompose

Internal. Applies a rule's compiled decompose entries to the captures hash, in
order, so a later entry can break down a field produced by an earlier one. New
fields never clobber an existing capture. Never dies.

=cut

sub _decompose {
	my ( $self, $rule, $captures ) = @_;

	foreach my $d ( @{ $rule->{'decompose'} } ) {
		my $value = $captures->{ $d->{'field'} };
		next if ( !defined($value) || ref($value) ne '' );

		if ( $d->{'type'} eq 'kv' ) {
			if ( $d->{'quoted'} ) {
				# quote-aware: a value may be "double" or 'single' quoted (quotes
				# stripped, the field separator allowed inside), else a bareword.
				# pairs are whitespace-separated; the value_split joins key/value.
				my $vs = quotemeta( $d->{'value_split'} );
				while ( $value =~ /([\w.\-]+)$vs(?:"([^"]*)"|'([^']*)'|(\S*))/g ) {
					my $key = $1;
					my $val = defined($2) ? $2 : ( defined($3) ? $3 : $4 );
					if ( defined( $d->{'trim'} ) && length( $d->{'trim'} ) ) {
						my $tc = $d->{'trim'};
						$val =~ s/\A[\Q$tc\E]+//;
						$val =~ s/[\Q$tc\E]+\z//;
					}
					$key = $d->{'prefix'} . $key;
					next if ( exists( $captures->{$key} ) );    # do not clobber a real capture
					$captures->{$key} = $val;
				}
			} else {
				my $fs = quotemeta( $d->{'field_split'} );
				foreach my $token ( split( /$fs/, $value, -1 ) ) {
					next if ( $token eq '' );
					my $idx = index( $token, $d->{'value_split'} );
					next if ( $idx < 1 );    # need at least a one-char key before the split
					my $key   = substr( $token, 0, $idx );
					my $val   = substr( $token, $idx + length( $d->{'value_split'} ) );
					if ( defined( $d->{'trim'} ) && length( $d->{'trim'} ) ) {
						my $tc = $d->{'trim'};
						$val =~ s/\A[\Q$tc\E]+//;
						$val =~ s/[\Q$tc\E]+\z//;
					}
					$key = $d->{'prefix'} . $key;
					next if ( exists( $captures->{$key} ) );    # do not clobber a real capture
					$captures->{$key} = $val;
				}
			}
		} elsif ( $d->{'type'} eq 'pattern' ) {
			if ( $value =~ $d->{'regexp'} ) {
				my %sub = %+;
				foreach my $key ( keys(%sub) ) {
					next if ( exists( $captures->{$key} ) );
					$captures->{$key} = $sub{$key};
				}
			}
		} elsif ( $d->{'type'} eq 'json' ) {
			my $decoded;
			eval { $decoded = JSON::decode_json($value); };
			# a value that is not valid JSON (or decodes to a bare scalar) is left
			# untouched -- skip this entry entirely so the raw field survives
			next if ( $@ || !defined($decoded) || ref($decoded) eq '' );
			if ( $d->{'nested'} ) {
				my $key = $d->{'prefix'};
				if ( $key ne '' ) {
					$key =~ s/\Q$d->{'separator'}\E\z//;    # trim a trailing separator
				} else {
					$key = $d->{'field'};
				}
				$captures->{$key} = $decoded if ( !exists( $captures->{$key} ) );
			} else {
				$self->_json_flatten( $decoded, '', $d->{'separator'}, $d->{'prefix'}, $captures );
			}
		}

		if ( $d->{'remove'} ) {
			delete $captures->{ $d->{'field'} };
		}
	} ## end foreach my $d ( @{ $rule->{'decompose'...}})

	return;
} ## end sub _decompose

=head2 _json_flatten

Internal. Recursively flattens a decoded-JSON structure into the captures hash.
Each leaf becomes C<< prefix + path >> where path is the sequence of object keys
and array indices joined by C<separator>. MongoDB extended-JSON wrappers (a hash
with a single C<$>-prefixed key such as C<$date> / C<$oid> / C<$numberLong>)
collapse transparently to their inner value; booleans normalize to 1/0; JSON
null is skipped; an already-present capture is never clobbered. Never dies.

=cut

sub _json_flatten {
	my ( $self, $data, $path, $sep, $prefix, $captures ) = @_;

	if ( ref($data) eq 'HASH' ) {
		# collapse a MongoDB extended-JSON wrapper: { "$date" => ... } etc.
		my @keys = keys( %{$data} );
		if ( scalar(@keys) == 1 && $keys[0] =~ /\A\$/ ) {
			return $self->_json_flatten( $data->{ $keys[0] }, $path, $sep, $prefix, $captures );
		}
		foreach my $key ( keys( %{$data} ) ) {
			my $child = ( $path eq '' ) ? $key : $path . $sep . $key;
			$self->_json_flatten( $data->{$key}, $child, $sep, $prefix, $captures );
		}
		return;
	}
	if ( ref($data) eq 'ARRAY' ) {
		my $index = 0;
		foreach my $element ( @{$data} ) {
			my $child = ( $path eq '' ) ? $index : $path . $sep . $index;
			$self->_json_flatten( $element, $child, $sep, $prefix, $captures );
			$index++;
		}
		return;
	}

	# leaf
	return if ( !defined($data) );    # skip JSON null
	if ( JSON::is_bool($data) ) {     # backend-agnostic (JSON::XS or JSON::PP boolean)
		$data = $data ? 1 : 0;
	} elsif ( ref($data) ) {
		$data = "$data";              # any other blessed leaf: stringify defensively
	}
	return if ( $path eq '' );        # a top-level bare scalar has no key to store under

	my $key = $prefix . $path;
	return if ( exists( $captures->{$key} ) );    # do not clobber an existing capture
	$captures->{$key} = $data;

	return;
} ## end sub _json_flatten

=head2 _compile_convert

Internal. Validates a C<convert:> map (field => type) and returns a normalized
copy (type is one of C<int>, C<float>, C<lc>, or C<uc>; C<integer> is accepted as
an alias for C<int>, C<num>/C<number> for C<float>, and
C<lower>/C<lowercase>/C<upper>/C<uppercase> for the two case folds). Dies on an
unknown type.

C<lc>/C<uc> exist so a rule file can normalize a captured token whose case varies
between the log sources that produce it -- SELinux writes C<avc: denied> while
AppArmor writes C<apparmor="DENIED"> for the same verdict, and a consumer should
not have to care which one it is looking at.

=cut

sub _compile_convert {
	my ( $self, $convert ) = @_;

	if ( ref($convert) ne 'HASH' ) {
		die( '.convert has a ref of "' . ref($convert) . '" and not "HASH"' );
	}

	my %normalized;
	foreach my $field ( keys( %{$convert} ) ) {
		my $type = $convert->{$field};
		if ( !defined($type) || ref($type) ne '' ) {
			die( '.convert.' . $field . ' type is undef or not a string' );
		}
		if ( $type =~ /\A(?:int|integer)\z/i ) {
			$normalized{$field} = 'int';
		} elsif ( $type =~ /\A(?:float|num|number)\z/i ) {
			$normalized{$field} = 'float';
		} elsif ( $type =~ /\A(?:lc|lower|lowercase)\z/i ) {
			$normalized{$field} = 'lc';
		} elsif ( $type =~ /\A(?:uc|upper|uppercase)\z/i ) {
			$normalized{$field} = 'uc';
		} else {
			die( '.convert.' . $field . ' type "' . $type . '" is unknown (expected int, float, lc, or uc)' );
		}
	}

	return \%normalized;
} ## end sub _compile_convert

=head2 _convert

Internal. Coerces the rule's convert fields in the captures hash: C<int>/C<float>
to numbers so they serialize as JSON numbers rather than strings, C<lc>/C<uc> to
a case-folded string. A value that is not present is left untouched, as is a
numeric conversion of something that does not look like a number. Never dies.

=cut

sub _convert {
	my ( $self, $rule, $captures ) = @_;

	foreach my $field ( keys( %{ $rule->{'convert'} } ) ) {
		next if ( !exists( $captures->{$field} ) );
		my $value = $captures->{$field};
		next if ( !defined($value) || ref($value) ne '' );

		my $type = $rule->{'convert'}{$field};

		# the case folds apply to any string, so they sit ahead of the
		# looks-like-a-number guard the numeric conversions need
		if ( $type eq 'lc' ) {
			$captures->{$field} = lc($value);
			next;
		} elsif ( $type eq 'uc' ) {
			$captures->{$field} = uc($value);
			next;
		}

		next if ( !looks_like_number($value) );

		if ( $type eq 'int' ) {
			$captures->{$field} = int( $value + 0 );
		} else {
			$captures->{$field} = $value + 0;
		}
	} ## end foreach my $field ( keys( %{ $rule->{'convert'...}}))

	return;
} ## end sub _convert

=head2 _compile_rule

Internal. Compiles a single C<rules:> entry into the runtime structure:

    {
        name     => ...,          # optional, diagnostics only
        field    => 'MESSAGE',    # target field, defaults to MESSAGE
        gate     => [ { field => ..., literals => {...}, regexps => [ qr//, ... ] }, ... ],
        patterns => [ qr//, ... ],
    }

    - rule :: The raw rule hash ref.
    - vars :: The compiled vars hash ref (pattern names resolve against this).

A rule may set C<< anchored: true >>, in which case each pattern is wrapped as
C<< \A(?:...)\z >> so it must match the whole target field (the equivalent of a
logstash C<< ^...$ >> grok) rather than any substring.

A rule (or a file-level default) may carry a C<decompose:> list to break
captured fields down further at match time -- see L</_compile_decompose> -- and a
C<convert:> map (field => C<int>|C<float>|C<lc>|C<uc>) to coerce captured fields
to numbers or to a case-folded string.
C<geoip:>, C<decompose:>, and C<convert:> may each be given per-rule or once at
the top of the file as a default for every rule. They run in order
decompose -> geoip -> convert, so geoip can look up a field a decompose step
produced and convert only coerces after geoip has seen the string addresses.

Dies on a malformed rule, an un-degrokked C<%{...}> remnant, or a pattern that
will not compile (which is where an illegal named capture such as a C<-> in the
name is caught, at load time rather than at match time).

=cut

sub _compile_rule {
	my ( $self, %opts ) = @_;

	my $rule = $opts{'rule'};
	my $vars = $opts{'vars'};
	if ( ref($rule) ne 'HASH' ) {
		die( 'rule has a ref of "' . ref($rule) . '" and not "HASH"' );
	}
	if ( ref($vars) ne 'HASH' ) {
		$vars = {};
	}

	my $compiled = {
		'name'       => $rule->{'name'},
		'field'      => ( defined( $rule->{'field'} ) ? $rule->{'field'} : 'MESSAGE' ),
		'gate'       => [],
		'patterns'   => [],
		'geoip'      => [],
		'decompose'  => [],
		'convert'    => {},
	};
	if ( ref( $compiled->{'field'} ) ne '' ) {
		die( '.field has a ref of "' . ref( $compiled->{'field'} ) . '" and not ""' );
	}

	# numeric coercion of captured fields (rule-level, else the file default)
	my $convert = defined( $rule->{'convert'} ) ? $rule->{'convert'} : $opts{'default_convert'};
	if ( defined($convert) ) {
		$compiled->{'convert'} = $self->_compile_convert($convert);
	}

	# captured fields to enrich with geoip (rule-level, else the file default)
	my $geoip = defined( $rule->{'geoip'} ) ? $rule->{'geoip'} : $opts{'default_geoip'};
	if ( defined($geoip) ) {
		if ( ref($geoip) ne 'ARRAY' ) {
			die( '.geoip has a ref of "' . ref($geoip) . '" and not "ARRAY"' );
		}
		foreach my $field ( @{$geoip} ) {
			if ( ref($field) ne '' ) {
				die( '.geoip entry has a ref of "' . ref($field) . '" and not ""' );
			}
			push( @{ $compiled->{'geoip'} }, $field );
		}
	}

	# captured fields to break down further (rule-level, else the file default)
	my $decompose = defined( $rule->{'decompose'} ) ? $rule->{'decompose'} : $opts{'default_decompose'};
	if ( defined($decompose) ) {
		$compiled->{'decompose'} = $self->_compile_decompose( $decompose, $vars );
	}

	# when anchored, each pattern must match the whole target field (like a
	# logstash "^...$" grok), not just a substring
	my $anchored = ( defined( $rule->{'anchored'} ) && $rule->{'anchored'} ) ? 1 : 0;

	# gates
	if ( defined( $rule->{'gate'} ) ) {
		if ( ref( $rule->{'gate'} ) ne 'ARRAY' ) {
			die( '.gate has a ref of "' . ref( $rule->{'gate'} ) . '" and not "ARRAY"' );
		}
		my $gate_int = 0;
		foreach my $gate ( @{ $rule->{'gate'} } ) {
			if ( ref($gate) ne 'HASH' ) {
				die( '.gate[' . $gate_int . '] has a ref of "' . ref($gate) . '" and not "HASH"' );
			}
			if ( !defined( $gate->{'field'} ) || ref( $gate->{'field'} ) ne '' ) {
				die( '.gate[' . $gate_int . '].field is undef or not a string' );
			}
			if ( !defined( $gate->{'values'} ) || ref( $gate->{'values'} ) ne 'ARRAY' ) {
				die( '.gate[' . $gate_int . '].values is undef or not an "ARRAY"' );
			}

			my $compiled_gate = {
				'field'    => $gate->{'field'},
				'literals' => {},
				'regexps'  => [],
			};
			my $value_int = 0;
			foreach my $value ( @{ $gate->{'values'} } ) {
				if ( ref($value) ne '' ) {
					die( '.gate[' . $gate_int . '].values[' . $value_int . '] has a ref of "' . ref($value) . '" and not ""' );
				}
				# //regexp// is the gate-value regexp marker; the outer slashes
				# are stripped strictly so an interior // (e.g. http://) survives
				if ( $value =~ /^\/\/(.*)\/\/\z/s ) {
					my $re = $1;
					my $compiled_re;
					eval { $compiled_re = qr/$re/; };
					if ($@) {
						die(      '.gate['
								. $gate_int
								. '].values['
								. $value_int
								. '] //regexp// "'
								. $value
								. '" does not compile... '
								. $@ );
					}
					push( @{ $compiled_gate->{'regexps'} }, $compiled_re );
				} else {
					$compiled_gate->{'literals'}{$value} = 1;
				}
				$value_int++;
			} ## end foreach my $value ( @{ $gate->{'values'} } )

			push( @{ $compiled->{'gate'} }, $compiled_gate );
			$gate_int++;
		} ## end foreach my $gate ( @{ $rule->{'gate'} } )
	} ## end if ( defined( $rule->{'gate'} ) )

	# patterns
	if ( !defined( $rule->{'patterns'} ) ) {
		die('.patterns is undef; a rule needs at least one pattern');
	} elsif ( ref( $rule->{'patterns'} ) ne 'ARRAY' ) {
		die( '.patterns has a ref of "' . ref( $rule->{'patterns'} ) . '" and not "ARRAY"' );
	} elsif ( !defined( $rule->{'patterns'}[0] ) ) {
		die('.patterns[0] is undef; a rule needs at least one pattern');
	}
	my $pattern_int = 0;
	foreach my $pattern ( @{ $rule->{'patterns'} } ) {
		if ( ref($pattern) ne '' ) {
			die( '.patterns[' . $pattern_int . '] has a ref of "' . ref($pattern) . '" and not ""' );
		}
		# a bare name that resolves to a compiled var uses that var's regexp
		# string; anything else is treated as an inline regexp
		my $regexp_string = ( exists( $vars->{$pattern} ) ) ? $vars->{$pattern} : $pattern;

		if ( $regexp_string =~ /%\{[^}]*\}/ ) {
			die( '.patterns[' . $pattern_int . '] ("' . $pattern . '") contains un-degrokked grok "%{...}"' );
		}

		if ($anchored) {
			$regexp_string = '\A(?:' . $regexp_string . ')\z';
		}

		my $compiled_re;
		eval { $compiled_re = qr/$regexp_string/; };
		if ($@) {
			die( '.patterns[' . $pattern_int . '] ("' . $pattern . '") does not compile as a regexp... ' . $@ );
		}
		push( @{ $compiled->{'patterns'} }, $compiled_re );
		$pattern_int++;
	} ## end foreach my $pattern ( @{ $rule->{'patterns'} } )

	return $compiled;
} ## end sub _compile_rule

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 3, June 2007

=cut

1;    # End of Log::Munger::LogProcessor
