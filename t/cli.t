#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

BEGIN { use_ok('Log::Munger') || print "Bail out!\n"; }

# ---- explain_item (the shared matcher used by the explain command) ----
my $m   = Log::Munger->new( 'rules' => [ 'base', 'postfix' ] );
my $why = $m->explain_item( 'item' => { PROGRAM => 'postfix/qmgr', MESSAGE => 'ABCDEF123456: removed' } );
is( $why->{'matched'}, 1,              'explain_item: matched' );
is( $why->{'rule'},    'postfix_qmgr', 'explain_item: rule name' );
is( $why->{'pattern'}, 0,              'explain_item: pattern index' );
is( $why->{'fields'}{'postfix_queueid'}, 'ABCDEF123456', 'explain_item: fields' );
is( $m->explain_item( 'item' => { PROGRAM => 'cron', MESSAGE => 'x' } )->{'matched'}, 0, 'explain_item: no match' );

# process_item still works after the refactor
is_deeply(
	$m->process_item( 'item' => { PROGRAM => 'postfix/qmgr', MESSAGE => 'ABCDEF123456: removed' } ),
	{ 'postfix_queueid' => 'ABCDEF123456' },
	'process_item unchanged'
);

# ---- the CLI (skipped if the app is not built) ----
my $script = 'blib/script/log_munger';
SKIP: {
	skip 'built CLI (blib/script/log_munger) not present', 6 unless -f $script;

	my @inc = ( '-Ilib', '-Iblib/lib' );
	my $run = sub {
		my @cmd = @_;
		open( my $fh, '-|', $^X, @inc, $script, @cmd ) or return '';
		local $/ = undef;
		my $out = <$fh>;
		close($fh);
		return defined($out) ? $out : '';
	};

	like( $run->('list'), qr/^postfix$/m, 'CLI list: shows postfix' );
	like( $run->('list'), qr/^auditd$/m, 'CLI list: shows auditd' );
	like( $run->( 'list_fields', '-f', 'sshd' ), qr/ssh_src_ip/, 'CLI list_fields: ssh_src_ip' );
	like(
		$run->( 'dump_rule_file', '-f', 'postfix', '--var', 'POSTFIX_QMGR_REMOVED' ),
		qr/postfix_queueid/,
		'CLI dump_rule_file --var: resolved regexp'
	);
	like(
		$run->( 'explain', '-r', 'sshd', '-s', '{"PROGRAM":"sshd","MESSAGE":"Failed password for root from 1.2.3.4 port 22 ssh2"}' ),
		qr/matched: yes.*rule: sshd/s,
		'CLI explain: matched rule'
	);
	like(
		$run->( 'munge', '-r', 'base', '-r', 'postfix', '-s', '{"PROGRAM":"postfix/qmgr","MESSAGE":"ABCDEF123456: removed"}' ),
		qr/postfix_queueid: ABCDEF123456/,
		'CLI munge: dumps fields'
	);
}

done_testing();
