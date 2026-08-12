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
	{   file    => 'dropbear',
		program => 'dropbear',
		message => "Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:AbCdEf0123456789 from 192.0.2.5:48719",
		expect  => {
			dropbear_method => 'Pubkey',
			dropbear_user   => 'root',
			dropbear_src_ip => '192.0.2.5',
		},
		numeric => ['dropbear_src_port'],
	},
	{   file    => 'odhcpd',
		program => 'odhcpd',
		message => 'No default route present, overriding ra_lifetime to 0!',
		expect  => { odhcpd_action => 'overriding' },
		numeric => ['odhcpd_ra_lifetime'],
	},
	{   file    => 'netifd',
		program => 'netifd',
		message => 'radio1 (12693): wifi-scripts: Starting',
		expect  => { netifd_device => 'radio1', netifd_message => 'wifi-scripts: Starting' },
		numeric => ['netifd_pid'],
	},
	{   file    => 'lldpd',
		program => 'lldpcli',
		message => 'system name set to new value wap0.example.net',
		expect  => { lldpd_setting => 'system name', lldpd_value => 'wap0.example.net' },
	},
	{   file    => 'luci',
		program => 'dispatcher.uc',
		message => 'luci: accepted login on / for root from 192.0.2.5',
		expect  => { luci_result => 'accepted', luci_user => 'root', luci_src_ip => '192.0.2.5' },
	},
	{   file    => 'pkg',
		program => 'pkg',
		message => 'py311-certifi-2024.8.30 installed',
		expect  => { pkg_name => 'py311-certifi', pkg_version => '2024.8.30', pkg_action => 'installed' },
	},
	{   file    => 'sympa',
		program => 'task_manager',
		message => 'notice Sympa::Spindle::ProcessTask::_execute() Running task Sympa::Task <date=1769401093;label=ACTION;model=eval_bouncers;context=*>',
		expect  => { sympa_level => 'notice', sympa_function => 'Sympa::Spindle::ProcessTask::_execute' },
		# the object reference is lifted out of the message text by a pattern
		# decompose and then kv-split, neither of which rule tests run
		also    => {
			sympa_task       => 'date=1769401093;label=ACTION;model=eval_bouncers;context=*',
			sympa_task_model => 'eval_bouncers',
			sympa_task_label => 'ACTION',
		},
		numeric => ['sympa_task_date'],
	},
	{   file    => 'nslcd',
		program => 'nslcd',
		message => '[045836] <authc="neti"> uid=neti,ou=users,dc=example,dc=com: Invalid credentials',
		expect  => {
			nslcd_session      => '045836',
			nslcd_request_type => 'authc',
			nslcd_request_arg  => 'neti',
			nslcd_dn           => 'uid=neti,ou=users,dc=example,dc=com',
			nslcd_error        => 'Invalid credentials',
		},
	},
	{   file    => 'tor',
		program => 'Tor',
		message => 'Bootstrapped 75% (enough_dirinfo): Loaded enough directory info to build circuits',
		expect  => { tor_bootstrap_tag => 'enough_dirinfo', tor_bootstrap_summary => 'Loaded enough directory info to build circuits' },
		numeric => ['tor_bootstrap_percent'],
	},
	{   file    => 'dbus',
		program => 'dbus-daemon',
		message => '[system] Activating via systemd: service name=\'org.freedesktop.fwupd\' unit=\'fwupd.service\' requested by \':1.558\' (uid=989 pid=190138 comm="/usr/bin/fwupdmgr refresh")',
		expect  => { dbus_bus => 'system', dbus_service => 'org.freedesktop.fwupd', dbus_unit => 'fwupd.service' },
		# the requester blob is quote-aware kv-split by a decompose, so the
		# whole argv survives with its spaces
		also    => { dbus_requester_comm => '/usr/bin/fwupdmgr refresh' },
		numeric => [ 'dbus_requester_uid', 'dbus_requester_pid' ],
	},
	{   file    => 'libvirt',
		program => 'virtqemud',
		message => "Domain id=17 name='sandbox70' uuid=4886ce36-05ed-4f35-bfbf-a6950de14804 is tainted: high-privileges",
		expect  => {
			libvirt_domain      => 'sandbox70',
			libvirt_domain_uuid => '4886ce36-05ed-4f35-bfbf-a6950de14804',
			libvirt_taint       => 'high-privileges',
		},
		numeric => ['libvirt_domain_id'],
	},
	{   file    => 'fwupd',
		program => 'fwupd',
		message => '00:40:52.210 FuMain               fwupd 1.9.34 ready for requests (locale en_US.UTF-8)',
		expect  => { fwupd_domain => 'FuMain', fwupd_version => '1.9.34', fwupd_locale => 'en_US.UTF-8' },
	},
	{   file    => 'avahi',
		program => 'avahi-daemon',
		message => 'Joining mDNS multicast group on interface virbr0.IPv4 with address 192.0.2.1.',
		expect  => {
			avahi_action   => 'Joining',
			avahi_iface    => 'virbr0',
			avahi_protocol => 'IPv4',
			avahi_address  => '192.0.2.1',
		},
	},
	{   file    => 'mojo_cape_submit',
		program => 'mojo_cape_submit',
		message => '0 : Got File... size=237985792 filename="sample.msi" sha256="88d47f551082e6284d5c0845261a8110e361b6d9ce3fe805af6bec711514a34e"',
		expect  => {},
		# the upload tail is a quoted kv blob split by a decompose, which rule
		# tests never run
		also    => {
			cape_submit_filename => 'sample.msi',
			cape_submit_sha256   => '88d47f551082e6284d5c0845261a8110e361b6d9ce3fe805af6bec711514a34e',
		},
		numeric => [ 'cape_submit_item', 'cape_submit_size' ],
	},
	{   file    => 'suricata',
		program => 'suricata',
		message => '[1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.7:44444 -> 192.0.2.1:22',
		expect  => { suricata_alert_signature => 'ET SCAN Potential SSH Scan', suricata_src_ip => '203.0.113.7' },
		numeric => [ 'suricata_alert_signature_id', 'suricata_src_port' ],
	},
	# the Ereshkigal suite: Galla watches logs and decides, Kur carries the ban
	# out, and Baphomet and Ereshkigal supervise them. Galla and Kur run one
	# process per instance and put the instance name in the syslog tag, so their
	# gates have to accept a suffix.
	{   file    => 'kur',
		program => 'kur-sshd',
		message => 'banned 192.0.2.7 expires=1785727347',
		expect  => { kur_action => 'banned', kur_ip => '192.0.2.7' },
		numeric => ['kur_expires'],
	},
	{   file    => 'galla',
		program => 'galla-suricata',
		message => 'banished 192.0.2.7 to Kur ban_time=300',
		expect  => { galla_action => 'banished', galla_ip => '192.0.2.7' },
		numeric => ['galla_ban_time'],
	},
	{   file    => 'baphomet',
		program => 'baphomet',
		message => 'galla "sshd" PID 42876 exited with 2',
		expect  => { bph_galla => 'sshd', bph_action => 'exited' },
		numeric => [ 'bph_pid', 'bph_exit_status' ],
	},
	{   file    => 'ereshkigal',
		program => 'ereshkigal',
		message => 'spawned kur "sshd" as PID 97452... /usr/local/bin/kur --foreground --name sshd --backend pf',
		expect  => { eresh_kur => 'sshd', eresh_action => 'spawned' },
		numeric => ['eresh_pid'],
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
# Galla and Kur name a ban target that may be a single address or a whole
# network. The two are separate captures so that geoip only ever sees a real
# address, which is the sort of thing a rule test cannot check because it
# compares captures rather than proving the other one is absent.
#
my $galla = Log::Munger->new( 'rules' => ['galla'] );
my $g_ip = $galla->process_item( 'program' => 'galla-sshd', 'message' => 'banished 192.0.2.7 to Kur ban_time=300' );
is( $g_ip->{'galla_ip'}, '192.0.2.7', 'galla: a bare address lands in galla_ip' );
ok( !exists( $g_ip->{'galla_cidr'} ), 'galla: a bare address sets no galla_cidr' );

my $g_cidr = $galla->process_item( 'program' => 'galla-ids', 'message' => 'banished 198.51.100.0/24 to Kur' );
is( $g_cidr->{'galla_cidr'}, '198.51.100.0/24', 'galla: a network lands in galla_cidr' );
ok( !exists( $g_cidr->{'galla_ip'} ), 'galla: a network sets no galla_ip, so geoip never sees one' );
ok( !exists( $g_cidr->{'galla_ban_time'} ), 'galla: an absent ban_time is not invented' );

# observe mode is the difference between "would have banned" and "banned", so
# it gets its own capture rather than being left in the message text
my $g_observe = $galla->process_item( 'program' => 'galla-k', 'message' => 'would banish 192.0.2.7 to Kur (observe mode) ban_time=300' );
is( $g_observe->{'galla_action'}, 'would banish',  'galla: observe-mode action' );
is( $g_observe->{'galla_mode'},   'observe mode',  'galla: observe mode is flagged' );

# a sighting subject may not be an address at all
is( $galla->process_item( 'program' => 'galla-k', 'message' => 'sighted neti (detection)' )->{'galla_subject'},
	'neti', 'galla: a non-address sighting subject' );
is( $galla->process_item( 'program' => 'galla-k', 'message' => 'sighted 192.0.2.11 (detection)' )->{'galla_ip'},
	'192.0.2.11', 'galla: an address sighting subject still lands in galla_ip' );

my $kur = Log::Munger->new( 'rules' => ['kur'] );
my $k_cidr = $kur->process_item( 'program' => 'kur-sshd', 'message' => 'banned cidr 198.51.100.0/24 expires=0' );
is( $k_cidr->{'kur_cidr'}, '198.51.100.0/24', 'kur: a network ban lands in kur_cidr' );
ok( !exists( $k_cidr->{'kur_ip'} ), 'kur: a network ban sets no kur_ip' );
is( $k_cidr->{'kur_expires'}, 0, 'kur: expires=0 survives the int conversion as 0, not undef' );

# both gates have to work with and without an instance suffix
foreach my $program (qw(kur kur-sshd kur-cidr-persist)) {
	ok( defined( $kur->process_item( 'program' => $program, 'message' => 'stopped' ) ),
		"kur: PROGRAM=$program passes the gate" );
}
foreach my $program (qw(galla galla-sshd galla-sshd-authed)) {
	ok( defined( $galla->process_item( 'program' => $program, 'message' => 'stopped' ) ),
		"galla: PROGRAM=$program passes the gate" );
}

# ...and neither may take the other's lines, nor their supervisors'
is( $kur->process_item( 'program' => 'kurt', 'message' => 'stopped' ),        undef, 'kur: PROGRAM=kurt is not a kur' );
is( $galla->process_item( 'program' => 'gallant', 'message' => 'stopped' ),   undef, 'galla: PROGRAM=gallant is not a galla' );
is( $kur->process_item( 'program' => 'ereshkigal', 'message' => 'stopped' ),  undef, 'kur: the supervisor is not a kur' );
is( $galla->process_item( 'program' => 'baphomet', 'message' => 'stopped' ),  undef, 'galla: the supervisor is not a galla' );

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
	[ 'nslcd goes to nslcd', { PROGRAM => 'nslcd', MESSAGE => 'accepting connections' }, 'nslcd_message' ],
	[ 'pkg goes to pkg', { PROGRAM => 'pkg', MESSAGE => 'nginx upgraded: 1.28.0_2,3 -> 1.28.0_3,3' }, 'pkg_version_from' ],
	# the OpenWRT set, each of which ends in a catch-all
	[ 'dropbear goes to dropbear', { PROGRAM => 'dropbear', MESSAGE => 'Not backgrounding' }, 'dropbear_message' ],
	[ 'odhcpd goes to odhcpd', { PROGRAM => 'odhcpd', MESSAGE => 'Raising SIGUSR1 due to reload' }, 'odhcpd_message' ],
	[ 'netifd goes to netifd', { PROGRAM => 'netifd', MESSAGE => "Network device 'phy0-ap1' link is up" }, 'netifd_link_state' ],
	[ 'lldpd goes to lldpd', { PROGRAM => 'lldpd', MESSAGE => 'unable to get system name' }, 'lldpd_message' ],
	[ 'lldpcli goes to lldpd', { PROGRAM => 'lldpcli', MESSAGE => 'protocol LLDP enabled' }, 'lldpd_protocol' ],
	[ 'a luci login under uhttpd goes to luci', { PROGRAM => 'uhttpd', MESSAGE => '[info] luci: accepted login on / for root from 192.0.2.5' }, 'luci_user' ],
	# sympa's daemons answer to some very generic program names, so each is
	# checked separately rather than trusting one to stand for the rest
	[ 'sympa bulk goes to sympa', { PROGRAM => 'bulk', MESSAGE => 'notice main:: Bulk 6.2.76 Started' }, 'sympa_daemon' ],
	[ 'sympa archived goes to sympa', { PROGRAM => 'archived', MESSAGE => 'notice main:: Archived 6.2.76 Started' }, 'sympa_daemon' ],
	[ 'sympa bounced goes to sympa', { PROGRAM => 'bounced', MESSAGE => 'notice main::sigterm() Signal TERM received, still processing current task' }, 'sympa_function' ],
	[ 'sympa CLI goes to sympa', { PROGRAM => 'sympa/health_check', MESSAGE => 'notice Sympa::DatabaseManager::probe_db() Table one_time_ticket_table created in database sympa' }, 'sympa_function' ],
	# Tor answers to two program names for the same daemon: "Tor" for its own
	# syslog output and "tor" for the stdout systemd captures, which still has
	# Tor's timestamp and level on the front
	[ 'Tor goes to tor', { PROGRAM => 'Tor', MESSAGE => 'We now have enough directory information to build circuits.' }, 'tor_message' ],
	[ 'tor stdout goes to tor', { PROGRAM => 'tor', MESSAGE => 'Jul 28 14:41:30.650 [notice] Opening Socks listener on 127.0.0.1:9050' }, 'tor_listener_addr' ],
	[ 'dbus-daemon goes to dbus', { PROGRAM => 'dbus-daemon', MESSAGE => '[system] Reloaded configuration' }, 'dbus_bus' ],
	# libvirt's modular daemons share one rule, so a second one is checked
	[ 'virtqemud goes to libvirt', { PROGRAM => 'virtqemud', MESSAGE => 'libvirt version: 11.1.0' }, 'libvirt_version' ],
	[ 'libvirtd goes to libvirt', { PROGRAM => 'libvirtd', MESSAGE => "Cannot get interface flags on 'virbr0': No such device" }, 'libvirt_error' ],
	# fwupd's clients log under their own names and write the bare message
	# with none of the daemon's time-and-domain prefix on it
	[ 'fwupd goes to fwupd', { PROGRAM => 'fwupd', MESSAGE => '11:21:52.150 FuEngine             something new' }, 'fwupd_domain' ],
	[ 'fwupdmgr goes to fwupd', { PROGRAM => 'fwupdmgr', MESSAGE => 'Updating lvfs' }, 'fwupd_remote' ],
	[ 'avahi-daemon goes to avahi', { PROGRAM => 'avahi-daemon', MESSAGE => 'Server startup complete. Host name is host.local.' }, 'avahi_message' ],
	# the Ereshkigal suite. Kur and Galla gate on a prefix rather than an exact
	# name, which is the sort of gate that can reach too far, so all four are
	# checked with everything loaded
	[ 'kur-sshd goes to kur', { PROGRAM => 'kur-sshd', MESSAGE => 'banned 192.0.2.7 expires=1785727347' }, 'kur_ip' ],
	[ 'galla-suricata goes to galla', { PROGRAM => 'galla-suricata', MESSAGE => 'banished 192.0.2.7 to Kur ban_time=300' }, 'galla_ip' ],
	[ 'baphomet goes to baphomet', { PROGRAM => 'baphomet', MESSAGE => 'galla "sshd" died, restarting in 1 seconds' }, 'bph_galla' ],
	[ 'ereshkigal goes to ereshkigal', { PROGRAM => 'ereshkigal', MESSAGE => 'added kur "dns"' }, 'eresh_kur' ],
	# nergal and mojo_cape_submit share a message vocabulary and a rule
	[ 'mojo_cape_submit goes to mojo_cape_submit', { PROGRAM => 'mojo_cape_submit', MESSAGE => '0 : Source Host: sensor.example.net' }, 'cape_submit_source_host' ],
	[ 'nergal goes to mojo_cape_submit', { PROGRAM => 'nergal', MESSAGE => '0 : Submitting "sample.msi" submitted as 116' }, 'cape_submit_task_id' ],
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
