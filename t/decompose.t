#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile);

BEGIN {
	use_ok('Log::Munger') || print "Bail out!\n";
}

#
# The shipped postfix rules carry a file-level decompose that kv-splits
# postfix_keyvalue_data and re-groks the relay/delays/command-counter blobs.
#
my $m = Log::Munger->new( 'rules' => [ 'base', 'postfix' ] );

# a smtp delivery line: kv split, then relay + delays re-grokked
my $d = $m->process_item(
	'item' => {
		PROGRAM => 'postfix/smtp',
		MESSAGE => '3F8B2A9C1D5E: to=<other@example.org>, orig_to=<x@y.com>, '
			. 'relay=mx.example.com[1.2.3.4]:25, delay=0.12, delays=0.05/0/0/0.07, dsn=2.0.0, status=sent (250 ok)'
	}
);
# kv fields (trimmed of <>,)
is( $d->{'postfix_to'},      'other@example.org', 'kv: to trimmed of <>' );
is( $d->{'postfix_orig_to'}, 'x@y.com',           'kv: orig_to' );
is( $d->{'postfix_dsn'},     '2.0.0',             'kv: dsn' );
is( $d->{'postfix_delay'},   '0.12',              'kv: delay' );
# relay re-grokked from postfix_relay
is( $d->{'postfix_relay_hostname'}, 'mx.example.com', 'pattern: relay hostname' );
is( $d->{'postfix_relay_ip'},       '1.2.3.4',        'pattern: relay ip' );
is( $d->{'postfix_relay_port'},     '25',             'pattern: relay port' );
# delays re-grokked from postfix_delays
is( $d->{'postfix_delay_before_qmgr'},  '0.05', 'pattern: delay_before_qmgr' );
is( $d->{'postfix_delay_transmission'}, '0.07', 'pattern: delay_transmission' );
# source blobs removed
ok( !exists( $d->{'postfix_keyvalue_data'} ), 'kv source field removed' );
ok( !exists( $d->{'postfix_relay'} ),         'relay blob removed after re-grok' );
ok( !exists( $d->{'postfix_delays'} ),        'delays blob removed after re-grok' );
# main-pattern captures preserved
is( $d->{'postfix_queueid'}, '3F8B2A9C1D5E', 'main capture preserved (queueid)' );
is( $d->{'postfix_status'},  'sent',         'main capture preserved (status)' );

# a smtpd disconnect line: command-counter decompose
my $c = $m->process_item(
	'item' => {
		PROGRAM => 'postfix/smtpd',
		MESSAGE => 'disconnect from mail.example.com[1.2.3.4] ehlo=1 mail=1 rcpt=0/1 data=0/1 quit=1 commands=3/5'
	}
);
is( $c->{'postfix_cmd_ehlo'},          '1', 'command-counter: ehlo' );
is( $c->{'postfix_cmd_rcpt'},          '1', 'command-counter: rcpt' );
is( $c->{'postfix_cmd_rcpt_accepted'}, '0', 'command-counter: rcpt_accepted' );
is( $c->{'postfix_cmd_count'},         '5', 'command-counter: count' );
ok( !exists( $c->{'postfix_command_counter_data'} ), 'command-counter blob removed' );

# a line with no decomposable blob is unchanged
my $q = $m->process_item( 'item' => { PROGRAM => 'postfix/qmgr', MESSAGE => 'ABCDEF123456: removed' } );
is_deeply( $q, { postfix_queueid => 'ABCDEF123456' }, 'line without blobs is left untouched' );

#
# a self-contained rule exercising kv options directly (prefix/trim/splits) and
# the no-clobber rule
#
my ( $fh, $file ) = tempfile( 'lm_decompose_XXXXXX', SUFFIX => '.yaml', TMPDIR => 1, UNLINK => 1 );
print {$fh} <<'YAML';
---
includes:
- base
vars_templated:
  KVLINE: '(?<who>[% WORD %]) (?<kvdata>[% GREEDYDATA %])'
rules:
  - name: kv
    field: MESSAGE
    anchored: true
    decompose:
      - field: kvdata
        type: kv
        prefix: 'x_'
        trim: '"'
        remove: true
    patterns: [KVLINE]
    tests:
      positive:
        - string: 'bob a=1 b="two" who=nope'
          result:
            who: 'bob'
            kvdata: 'a=1 b="two" who=nope'
      negative: ['zzz']
YAML
close($fh);

my $km = Log::Munger->new( 'rules' => [$file] );
my $k  = $km->process_item( 'item' => { MESSAGE => 'bob a=1 b="two" who=nope' } );
is( $k->{'x_a'}, '1',   'kv custom prefix' );
is( $k->{'x_b'}, 'two', 'kv trim of quotes' );
is( $k->{'who'}, 'bob', 'existing capture not clobbered by kv (x_who added instead)' );
is( $k->{'x_who'}, 'nope', 'kv writes to prefixed key, leaving the original who intact' );
ok( !exists( $k->{'kvdata'} ), 'kv source removed' );

done_testing();
