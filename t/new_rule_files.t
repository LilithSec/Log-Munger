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
		message => '[pid 1234] [neti] FAIL LOGIN: Client "192.0.2.5"',
		expect  => { vsftpd_user => 'neti', vsftpd_result => 'FAIL', vsftpd_client_ip => '192.0.2.5' },
		numeric => ['vsftpd_pid'],
	},
	{   file    => 'proftpd',
		program => 'proftpd',
		message => '192.0.2.1 (scanner[203.0.113.7]) - USER admin (Login failed): Incorrect password.',
		expect  => { proftpd_user => 'admin', proftpd_client_ip => '203.0.113.7' },
	},
	{   file    => 'openvpn',
		program => 'openvpn-server',
		message => 'neti/192.0.2.5:49152 [neti] Peer Connection Initiated with [AF_INET]192.0.2.5:49152',
		expect  => { openvpn_cn => 'neti', openvpn_src_ip => '192.0.2.5' },
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
		message => 'FATAL:  password authentication failed for user "neti"',
		expect  => { pgsql_level => 'FATAL', pgsql_user => 'neti' },
	},
	{   file    => 'polkit',
		program => 'polkitd',
		message => 'Operator of unix-session:1 FAILED to authenticate to gain authorization for action org.freedesktop.systemd1.manage-units for system-bus-name::1.234 [systemctl restart foo] (owned by unix-user:neti)',
		expect  => { polkit_action => 'org.freedesktop.systemd1.manage-units', polkit_owner => 'unix-user:neti' },
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
		message => '/home/neti/file.exe: Win.Test.EICAR_HDB-1 FOUND',
		expect  => { clamav_path => '/home/neti/file.exe', clamav_signature => 'Win.Test.EICAR_HDB-1' },
	},
	{   file    => 'spamd',
		program => 'spamd',
		message => 'spamd: result: Y 12 - BAYES_99,HTML_MESSAGE scantime=1.2,size=1234,user=neti,uid=1000,required_score=5.0,rhost=localhost,raddr=127.0.0.1',
		expect  => { spamd_verdict => 'Y', spamd_symbols => 'BAYES_99,HTML_MESSAGE' },
		# the kv blob is split by a decompose into spamd's own key names
		also    => { user => 'neti', raddr => '127.0.0.1', required_score => '5.0' },
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
	{   file    => 'sendmail',
		program => 'sm-mta',
		message => '1rABCD012345: from=<sender@example.com>, size=1234, class=0, nrcpts=1, proto=ESMTP, daemon=MTA, relay=mail.example.com [192.0.2.5]',
		expect  => { sendmail_qid => '1rABCD012345' },
		# two decomposes in sequence: the kv split produces sendmail_relay,
		# which the second one then splits into a host and an address
		also    => {
			sendmail_from      => '<sender@example.com>',
			sendmail_proto     => 'ESMTP',
			sendmail_relay     => 'mail.example.com [192.0.2.5]',
			sendmail_relay_host => 'mail.example.com',
			sendmail_relay_ip  => '192.0.2.5',
		},
		numeric => [ 'sendmail_size', 'sendmail_nrcpts' ],
	},
	{   file    => 'docker',
		program => 'dockerd',
		message => 'time="2026-07-15T10:00:00.123456789Z" level=error msg="Handler for GET /v1.43/containers/json returned error" error="No such container"',
		expect  => {},
		# quote-aware logfmt: msg= and error= both contain spaces
		also    => {
			docker_level => 'error',
			docker_msg   => 'Handler for GET /v1.43/containers/json returned error',
			docker_error => 'No such container',
		},
	},
	{   file    => 'freeradius',
		program => 'radiusd',
		message => 'Login incorrect (mschap: MS-CHAP2-Response is incorrect): [admin/password] (from client wifi port 0 cli aa-bb-cc-dd-ee-ff)',
		expect  => {
			radius_result          => 'incorrect',
			radius_user            => 'admin',
			radius_client          => 'wifi',
			radius_calling_station => 'aa-bb-cc-dd-ee-ff',
		},
	},
	{   file    => 'strongswan',
		program => 'charon',
		message => '12[IKE] IKE_SA remote[1] established between 192.0.2.1[server]...203.0.113.7[client]',
		expect  => { ipsec_subsystem => 'IKE', ipsec_remote_ip => '203.0.113.7', ipsec_remote_id => 'client' },
		numeric => ['ipsec_thread'],
	},
	{   file    => 'wpa_supplicant',
		program => 'wpa_supplicant',
		message => 'wlan0: CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\'home\' auth_failures=1 duration=10 reason=WRONG_KEY',
		expect  => { wpa_iface => 'wlan0', wpa_ssid => 'home', wpa_reason => 'WRONG_KEY' },
		numeric => ['wpa_auth_failures'],
	},
	{   file    => 'networkmanager',
		program => 'NetworkManager',
		message => '<warn>  [1626345600.1234] device (wlan0): state change: config -> failed (reason \'no-secrets\', sys-iface-state: \'managed\')',
		expect  => { nm_level => 'warn', nm_device => 'wlan0', nm_state_to => 'failed', nm_reason => 'no-secrets' },
	},
	{   file    => 'resolved',
		program => 'systemd-resolved',
		message => 'DNSSEC validation failed for question example.com IN A: no-signature',
		expect  => { resolved_query_name => 'example.com', resolved_dnssec_result => 'no-signature' },
	},
	{   file    => 'networkd',
		program => 'systemd-networkd',
		message => 'eth0: DHCPv4 address 192.0.2.50/24 via 192.0.2.1',
		expect  => { networkd_iface => 'eth0', networkd_address => '192.0.2.50', networkd_gateway => '192.0.2.1' },
		numeric => ['networkd_prefix_length'],
	},
	{   file    => 'timesyncd',
		program => 'systemd-timesyncd',
		message => 'Synchronized to time server 192.0.2.1:123 (ntp.example.com).',
		expect  => { timesyncd_server_ip => '192.0.2.1', timesyncd_server_name => 'ntp.example.com' },
		numeric => ['timesyncd_server_port'],
	},
	{   file    => 'zed',
		program => 'zed',
		message => 'eid=5 class=checksum pool=\'tank\' vdev=sda1 cksum_errors=1',
		expect  => {},
		also    => { zed_class => 'checksum', zed_pool => 'tank', zed_vdev => 'sda1' },
		numeric => [ 'zed_eid', 'zed_cksum_errors' ],
	},
	{   file    => 'cups',
		program => 'cupsd',
		message => 'E [15/Jul/2026:10:00:00 +0000] [Job 123] The printer is not responding.',
		expect  => { cups_level => 'E', cups_scope => 'Job 123', cups_message => 'The printer is not responding.' },
	},
	{   file    => 'php_fpm',
		program => 'php8.2-fpm',
		message => '[15-Jul-2026 10:00:00] WARNING: [pool www] child 1234 exited on signal 11 (SIGSEGV) after 100.123456 seconds from start',
		expect  => { php_pool => 'www', php_signal_name => 'SIGSEGV', php_level => 'warning' },
		numeric => [ 'php_pid', 'php_signal', 'php_uptime' ],
	},
	{   file    => 'syslog_daemon',
		program => 'rsyslogd',
		message => 'imuxsock: 1234 messages lost due to rate-limiting',
		expect  => { syslogd_module => 'imuxsock' },
		numeric => ['syslogd_lost'],
	},
	{   file    => 'xinetd',
		program => 'xinetd',
		message => 'FAIL: ftp address from=203.0.113.7',
		expect  => { xinetd_service => 'ftp', xinetd_fail_reason => 'address', xinetd_src_ip => '203.0.113.7' },
	},
	{   file    => 'snmpd',
		program => 'snmpd',
		message => 'Connection from UDP: [203.0.113.7]:12345->[192.0.2.1]:161',
		expect  => { snmpd_transport => 'UDP', snmpd_src_ip => '203.0.113.7', snmpd_dst_ip => '192.0.2.1' },
		numeric => [ 'snmpd_src_port', 'snmpd_dst_port' ],
	},
	{   file    => 'nfs',
		program => 'rpc.mountd',
		message => 'refused mount request from 203.0.113.7 for /export (/export): illegal port',
		expect  => { nfs_src_ip => '203.0.113.7', nfs_path => '/export', nfs_refusal_reason => 'illegal port' },
	},
	{   file    => 'atd',
		program => 'atd',
		message => 'Starting job 5 (a000050192abc) for user \'neti\' (1000)',
		expect  => { atd_job => '5', atd_user => 'neti' },
		numeric => ['atd_uid'],
	},
	{   file    => 'suricata',
		program => 'suricata',
		message => '[1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.7:44444 -> 192.0.2.1:22',
		expect  => { suricata_alert_signature => 'ET SCAN Potential SSH Scan', suricata_src_ip => '203.0.113.7' },
		numeric => [ 'suricata_alert_signature_id', 'suricata_src_port' ],
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
# suricata's eve.json rule is also gateless, since eve.json is tailed off disk.
# Its pattern demands an "event_type" key so that being gateless does not turn
# into claiming every other daemon's JSON.
#
my $suricata = Log::Munger->new( 'rules' => ['suricata'] );
my $eve = $suricata->process_item(
	'item' => '{"timestamp":"2026-07-15T10:00:00.123456+0000","event_type":"alert","src_ip":"203.0.113.7","src_port":44444,"dest_ip":"192.0.2.1","dest_port":22,"proto":"TCP","alert":{"signature_id":2001219,"signature":"ET SCAN Potential SSH Scan","severity":2}}' );
is( $eve->{'suricata_event_type'},        'alert',                      'suricata: eve event_type' );
is( $eve->{'suricata_src_ip'},            '203.0.113.7',                'suricata: eve source, flattened out of the JSON' );
is( $eve->{'suricata_alert_signature'},   'ET SCAN Potential SSH Scan', 'suricata: nested alert object flattened' );
ok( looks_like_number( $eve->{'suricata_alert_signature_id'} ), 'suricata: signature id is numeric' );
ok( !exists( $eve->{'suricata_json'} ), 'suricata: the raw JSON is removed once flattened' );

# a JSON line from another daemon must not be claimed by the gateless rule
my $not_eve = $suricata->process_item(
	'item' => '{"t":{"$date":"2026-07-27T02:49:30.131+00:00"},"s":"I","c":"NETWORK","msg":"Connection accepted"}' );
is( $not_eve, undef, 'suricata: JSON from another daemon is left alone' );

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
	# tier-two daemons, several of which also end in a catch-all
	[ 'docker goes to docker', { PROGRAM => 'dockerd', MESSAGE => 'failed to start daemon: no such file' }, 'docker_message' ],
	[ 'sendmail goes to sendmail', { PROGRAM => 'sm-mta', MESSAGE => 'starting daemon (8.17.1): SMTP+queueing@00:30:00' }, 'sendmail_message' ],
	[ 'freeradius goes to freeradius', { PROGRAM => 'radiusd', MESSAGE => 'Ready to process requests' }, 'radius_message' ],
	[ 'strongswan goes to strongswan', { PROGRAM => 'charon', MESSAGE => 'charon stopped after 200 ms' }, 'ipsec_message' ],
	[ 'wpa_supplicant goes to wpa_supplicant', { PROGRAM => 'wpa_supplicant', MESSAGE => 'Successfully initialized wpa_supplicant' }, 'wpa_message' ],
	[ 'networkd goes to networkd', { PROGRAM => 'systemd-networkd', MESSAGE => 'Enumeration completed' }, 'networkd_message' ],
	[ 'resolved goes to resolved', { PROGRAM => 'systemd-resolved', MESSAGE => 'Positive Trust Anchors:' }, 'resolved_message' ],
	[ 'timesyncd goes to timesyncd', { PROGRAM => 'systemd-timesyncd', MESSAGE => 'Network configuration changed, trying to establish connection.' }, 'timesyncd_message' ],
	[ 'zed goes to zed', { PROGRAM => 'zed', MESSAGE => 'ZFS Event Daemon 2.1.11-1 (PID 1234)' }, 'zed_message' ],
	[ 'cups goes to cups', { PROGRAM => 'cupsd', MESSAGE => 'Scheduler shutting down normally.' }, 'cups_message' ],
	[ 'php-fpm goes to php_fpm', { PROGRAM => 'php-fpm8.2', MESSAGE => 'ready to handle connections' }, 'php_message' ],
	[ 'rsyslogd goes to syslog_daemon', { PROGRAM => 'rsyslogd', MESSAGE => 'rsyslogd\'s groupid changed to 106' }, 'syslogd_message' ],
	[ 'xinetd goes to xinetd', { PROGRAM => 'xinetd', MESSAGE => 'xinetd Version 2.3.15 started' }, 'xinetd_message' ],
	[ 'snmpd goes to snmpd', { PROGRAM => 'snmpd', MESSAGE => 'NET-SNMP version 5.9.3' }, 'snmpd_message' ],
	[ 'mountd goes to nfs', { PROGRAM => 'rpc.mountd', MESSAGE => 'Version 1.3.4 starting' }, 'nfs_message' ],
	[ 'atd goes to atd', { PROGRAM => 'atd', MESSAGE => 'File a000050192abc is in the future' }, 'atd_message' ],
	# the four raw, gateless formats, which are the ones with nothing but
	# their own shape keeping them apart
	[ 'an apache line goes to http_access_logs', '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"', 'http_clientip' ],
	[ 'a squid line goes to squid', '1626345600.123 234 192.0.2.5 TCP_MISS/200 1234 GET http://e.com/ - DIRECT/1.2.3.4 text/html', 'squid_client_ip' ],
	[ 'a pf line goes to pf', 'rule 12/0(match): block in on em0: 192.0.2.5.49152 > 192.0.2.1.22: Flags [S], length 0', 'pf_src_ip' ],
	[ 'an eve.json line goes to suricata', '{"timestamp":"2026-07-15T10:00:00+0000","event_type":"alert","src_ip":"203.0.113.7","src_port":44444,"dest_ip":"192.0.2.1","dest_port":22}', 'suricata_event_type' ],
	# ...and a mongodb JSON line must still reach mongodb rather than being
	# taken by suricata's gateless JSON rule
	[ 'mongodb JSON goes to mongodb', { PROGRAM => 'mongod', MESSAGE => '{"t":{"$date":"2026-07-27T02:49:30.131+00:00"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"Connection accepted"}' }, 'mongo_msg' ],
);

foreach my $case (@ownership) {
	my ( $label, $item, $want ) = @{$case};
	my $fields = $everything->process_item( 'item' => $item );
	ok( defined($fields) && exists( $fields->{$want} ), $label )
		or diag( defined($fields) ? 'got instead: ' . join( ', ', sort keys %{$fields} ) : 'no match at all' );
}

done_testing();
