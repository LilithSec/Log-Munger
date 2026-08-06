#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Scalar::Util qw(looks_like_number);
use File::ShareDir ();

BEGIN {
	use_ok('Log::Munger') || print "Bail out!\n";
}

#
# The rule files added to cover daemons the distribution had nothing for.
#
# t/all_rules_clean.t already runs every file's own embedded tests, and those
# only exercise patterns. What is checked here is everything they cannot reach:
# that each file's gate actually lets its daemon's lines through, that the
# converted values come out as numbers, and -- most of all -- that none of these
# files reaches out and claims another one's lines when the whole set is loaded
# at once.
#
# That last one is the risk worth a test. Several of these files end in a
# catch-all pattern so an unrecognised line is not silently dropped, and pf is
# gateless because pf does not log through syslog at all. Either of those, done
# carelessly, turns "load everything" into "the first rule file wins".
#

#
# each new file matches a representative line through its own gate
#
my @cases = (
	{   file    => 'samba',
		program => 'smbd',
		message => '  Auth: [SMB2,(null)] user [DOMAIN]\[admin] at [Tue, 15 Jul 2026 10:00:00 UTC] with [NTLMv2] status [NT_STATUS_NO_SUCH_USER] workstation [WS] remote host [ipv4:192.0.2.5:49152] mapped to [DOMAIN]\[admin]. local host [ipv4:192.0.2.1:445]',
		expect  => { samba_user => 'admin', samba_status => 'NT_STATUS_NO_SUCH_USER' },
		# the combined peer token is split by a decompose, which rule tests
		# never run, so this is the only place it is checked
		numeric => ['samba_remote_port'],
		also    => { samba_remote_ip => '192.0.2.5' },
	},
	{   file    => 'vsftpd',
		program => 'vsftpd',
		message => '[pid 1234] [kitsune] FAIL LOGIN: Client "192.0.2.5"',
		expect  => { vsftpd_user => 'kitsune', vsftpd_result => 'FAIL', vsftpd_client_ip => '192.0.2.5' },
		numeric => ['vsftpd_pid'],
	},
	{   file    => 'proftpd',
		program => 'proftpd',
		message => '192.0.2.1 (scanner[203.0.113.7]) - USER admin (Login failed): Incorrect password.',
		expect  => { proftpd_user => 'admin', proftpd_client_ip => '203.0.113.7' },
	},
	{   file    => 'openvpn',
		program => 'openvpn-server',
		message => 'kitsune/192.0.2.5:49152 [kitsune] Peer Connection Initiated with [AF_INET]192.0.2.5:49152',
		expect  => { openvpn_cn => 'kitsune', openvpn_src_ip => '192.0.2.5' },
		numeric => ['openvpn_src_port'],
	},
	{   file    => 'slapd',
		program => 'slapd',
		message => 'conn=1000 op=0 RESULT tag=97 err=49 text=',
		expect  => { slapd_text => '' },
		numeric => [ 'slapd_conn', 'slapd_err' ],
	},
	{   file    => 'haproxy',
		program => 'haproxy',
		message => '192.0.2.5:49152 [15/Jul/2026:10:00:00.123] http-in be/srv 0/0/1/2/3 200 1234 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"',
		expect  => { haproxy_client_ip => '192.0.2.5', haproxy_term_state => '----', haproxy_timers => '0/0/1/2/3' },
		numeric => ['haproxy_client_port'],
	},
	{   file    => 'mysql',
		program => 'mariadbd',
		message => q{Access denied for user 'root'@'192.0.2.5' (using password: YES)},
		expect  => { mysql_user => 'root', mysql_src_ip => '192.0.2.5', mysql_used_password => 'YES' },
	},
	{   file    => 'postgresql',
		program => 'postgres',
		message => 'FATAL:  password authentication failed for user "kitsune"',
		expect  => { pgsql_level => 'FATAL', pgsql_user => 'kitsune' },
	},
	{   file    => 'polkit',
		program => 'polkitd',
		message => 'Operator of unix-session:1 FAILED to authenticate to gain authorization for action org.freedesktop.systemd1.manage-units for system-bus-name::1.234 [systemctl restart foo] (owned by unix-user:kitsune)',
		expect  => { polkit_action => 'org.freedesktop.systemd1.manage-units', polkit_owner => 'unix-user:kitsune' },
	},
	{   file    => 'smartd',
		program => 'smartd',
		message => 'Device: /dev/sda [SAT], SMART Prefailure Attribute: 5 Reallocated_Sector_Ct changed from 100 to 99',
		expect  => { smartd_device => '/dev/sda', smartd_attribute_name => 'Reallocated_Sector_Ct' },
		numeric => [ 'smartd_value_from', 'smartd_value_to' ],
	},
	{   file    => 'rspamd',
		program => 'rspamd',
		message => '<a1b2c3>; proxy; rspamd_task_write_log: id: <a1b2c3>, qid: <1rABCD>, ip: 192.0.2.5, from: <s@e.com>, (default: F (add header): [8.50/15.00] [BAYES_SPAM(4.50)]), len: 1234, time: 50.123ms',
		expect  => { rspamd_qid => '1rABCD', rspamd_action => 'add header', rspamd_src_ip => '192.0.2.5' },
		numeric => [ 'rspamd_score', 'rspamd_required_score' ],
	},
	{   file    => 'clamav',
		program => 'clamd',
		message => '/home/kitsune/file.exe: Win.Test.EICAR_HDB-1 FOUND',
		expect  => { clamav_path => '/home/kitsune/file.exe', clamav_signature => 'Win.Test.EICAR_HDB-1' },
	},
	{   file    => 'spamd',
		program => 'spamd',
		message => 'spamd: result: Y 12 - BAYES_99,HTML_MESSAGE scantime=1.2,size=1234,user=kitsune,uid=1000,required_score=5.0,rhost=localhost,raddr=127.0.0.1',
		expect  => { spamd_verdict => 'Y', spamd_symbols => 'BAYES_99,HTML_MESSAGE' },
		# the kv blob is split by a decompose into spamd's own key names
		also    => { user => 'kitsune', raddr => '127.0.0.1', required_score => '5.0' },
	},
	{   file    => 'opendkim',
		program => 'opendkim',
		message => '1rABCD: s=default d=example.com SSL',
		expect  => { opendkim_qid => '1rABCD', opendkim_domain => 'example.com', opendkim_selector => 'default' },
	},
	{   file    => 'opendmarc',
		program => 'opendmarc',
		message => '1rABCD: example.com fail; dkim=fail (bad signature) spf=pass',
		expect  => { opendmarc_qid => '1rABCD', opendmarc_domain => 'example.com', opendmarc_result => 'fail' },
	},
);

foreach my $case ( @cases ) {
	my $munger = Log::Munger->new( 'rules' => [ $case->{'file'} ] );
	my $fields = $munger->process_item( 'message' => $case->{'message'}, 'program' => $case->{'program'} );

	if ( !defined($fields) ) {
		fail( $case->{'file'} . ": matched through the PROGRAM=" . $case->{'program'} . " gate" );
		next;
	}
	pass( $case->{'file'} . ": matched through the PROGRAM=" . $case->{'program'} . " gate" );

	foreach my $key ( sort keys %{ $case->{'expect'} } ) {
		is( $fields->{$key}, $case->{'expect'}{$key}, "$case->{file}: $key" );
	}
	foreach my $key ( sort keys %{ $case->{'also'} || {} } ) {
		is( $fields->{$key}, $case->{'also'}{$key}, "$case->{file}: $key (from a decompose)" );
	}
	foreach my $key ( @{ $case->{'numeric'} || [] } ) {
		ok( looks_like_number( $fields->{$key} ), "$case->{file}: $key is numeric after convert" );
	}
}

#
# pf is gateless, because pf writes binary pcap rather than syslog and its text
# form only exists once tcpdump has rendered it. So it is fed raw.
#
my $pf = Log::Munger->new( 'rules' => ['pf'] );
my $blocked = $pf->process_item(
	'item' => 'rule 12/0(match): block in on em0: 192.0.2.5.49152 > 192.0.2.1.22: Flags [S], seq 1234, win 65535, length 0' );
is( $blocked->{'pf_action'},    'block',       'pf: verdict' );
is( $blocked->{'pf_iface'},     'em0',         'pf: interface' );
is( $blocked->{'pf_src_ip'},    '192.0.2.5',   'pf: source address split off its dotted port' );
is( $blocked->{'pf_dst_ip'},    '192.0.2.1',   'pf: destination address' );
ok( looks_like_number( $blocked->{'pf_src_port'} ), 'pf: source port is numeric' );
ok( looks_like_number( $blocked->{'pf_dst_port'} ), 'pf: destination port is numeric' );

# a protocol with no ports still yields both addresses
my $icmp = $pf->process_item( 'item' => 'rule 0/0(match): block in on em0: 192.0.2.5 > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64' );
is( $icmp->{'pf_src_ip'}, '192.0.2.5', 'pf: portless protocol source' );
ok( !exists( $icmp->{'pf_src_port'} ), 'pf: portless protocol sets no port' );

#
# With every shipped rule file loaded at once, each daemon's line still goes to
# the file that owns it.
#
# Several of these files end in a catch-all so an unrecognised line keeps its
# text, and pf is gateless. Both are fine on their own and both are ways to
# accidentally swallow someone else's traffic, so the property is asserted
# rather than assumed.
#
my $share = File::ShareDir::dist_dir('Log-Munger');
my @all = map { m{([^/]+)\.yaml\z} } sort glob("$share/*.yaml");
cmp_ok( scalar(@all), '>=', 40, 'found the full set of shipped rule files' );

my $everything = Log::Munger->new( 'rules' => \@all );

my @ownership = (
	[ 'sshd goes to sshd', { PROGRAM => 'sshd', MESSAGE => 'Failed password for root from 203.0.113.7 port 44444 ssh2' }, 'ssh_user' ],
	[ 'postfix goes to postfix', { PROGRAM => 'postfix/smtpd', MESSAGE => 'connect from unknown[192.0.2.5]' }, 'postfix_client_ip' ],
	[ 'netfilter goes to netfilter', { PROGRAM => 'kernel', MESSAGE => '[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=192.0.2.1 PROTO=TCP SPT=44444 DPT=22' }, 'nf_SRC' ],
	[ 'samba goes to samba', { PROGRAM => 'smbd', MESSAGE => '  check_ntlm_password:  Authentication for user [admin] -> [admin] FAILED with error NT_STATUS_NO_SUCH_USER' }, 'samba_status' ],
	[ 'slapd goes to slapd', { PROGRAM => 'slapd', MESSAGE => 'conn=1000 op=0 RESULT tag=97 err=49 text=' }, 'slapd_err' ],
	[ 'polkit goes to polkit', { PROGRAM => 'polkitd', MESSAGE => 'Loading rules from directory /etc/polkit-1/rules.d' }, 'polkit_message' ],
	[ 'rspamd goes to rspamd', { PROGRAM => 'rspamd', MESSAGE => 'rspamd 3.7.5 is loading configuration' }, 'rspamd_message' ],
	[ 'clamav goes to clamav', { PROGRAM => 'clamd', MESSAGE => 'SelfCheck: Database status OK.' }, 'clamav_message' ],
	# the three raw, gateless formats, which are the ones with nothing but
	# their own shape keeping them apart
	[ 'an apache line goes to http_access_logs', '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"', 'http_clientip' ],
	[ 'a squid line goes to squid', '1626345600.123 234 192.0.2.5 TCP_MISS/200 1234 GET http://e.com/ - DIRECT/1.2.3.4 text/html', 'squid_client_ip' ],
	[ 'a pf line goes to pf', 'rule 12/0(match): block in on em0: 192.0.2.5.49152 > 192.0.2.1.22: Flags [S], length 0', 'pf_src_ip' ],
);

foreach my $case (@ownership) {
	my ( $label, $item, $want ) = @{$case};
	my $fields = $everything->process_item( 'item' => $item );
	ok( defined($fields) && exists( $fields->{$want} ), $label )
		or diag( defined($fields) ? 'got instead: ' . join( ', ', sort keys %{$fields} ) : 'no match at all' );
}

done_testing();
