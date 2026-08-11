#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Scalar::Util qw(looks_like_number);

BEGIN {
	use_ok('Log::Munger')                  || print "Bail out!\n";
	use_ok('Log::Munger::RuleFileParser')  || print "Bail out!\n";
}

#
# Coverage for message types the shipped rule files used to miss.
#
# The tests embedded in the YAML only exercise patterns. They never see a gate,
# never see two rule files loaded together, and never see a converted value, so
# anything that depends on one of those needs a test out here. That is most of
# what this file is: gates, cross-file behaviour, and the handful of captures
# whose whole point was that they used to come out wrong rather than not at all.
#

#
# dnsmasq: DHCP, TFTP and locally-answered lookups
#
# dnsmasq is three services sharing a process, and under journald it splits its
# output between dnsmasq, dnsmasq-dhcp and dnsmasq-tftp. The gate has to cover
# all of them or every DHCP line on a systemd host is a miss.
#
my $dnsmasq = Log::Munger->new( 'rules' => ['dnsmasq'] );

foreach my $program (qw(dnsmasq dnsmasq-dhcp)) {
	my $ack = $dnsmasq->process_item(
		'item' => { PROGRAM => $program, MESSAGE => 'DHCPACK(eth0) 192.0.2.50 aa:bb:cc:dd:ee:ff myhost' } );
	is( $ack->{'dnsmasq_dhcp_type'},     'DHCPACK',           "dnsmasq/$program: DHCPACK type" );
	is( $ack->{'dnsmasq_dhcp_ip'},       '192.0.2.50',        "dnsmasq/$program: DHCPACK lease ip" );
	is( $ack->{'dnsmasq_dhcp_mac'},      'aa:bb:cc:dd:ee:ff', "dnsmasq/$program: DHCPACK mac" );
	is( $ack->{'dnsmasq_dhcp_hostname'}, 'myhost',            "dnsmasq/$program: DHCPACK client name" );
}

# a DISCOVER that requested no address has no lease IP at all
my $discover = $dnsmasq->process_item(
	'item' => { PROGRAM => 'dnsmasq-dhcp', MESSAGE => 'DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:ff' } );
is( $discover->{'dnsmasq_dhcp_type'}, 'DHCPDISCOVER',      'dnsmasq: DISCOVER with no lease ip' );
is( $discover->{'dnsmasq_dhcp_mac'},  'aa:bb:cc:dd:ee:ff', 'dnsmasq: DISCOVER mac' );
ok( !exists( $discover->{'dnsmasq_dhcp_ip'} ), 'dnsmasq: DISCOVER has no lease ip field' );

# NAK puts a refusal reason where every other type puts the client hostname
my $nak = $dnsmasq->process_item(
	'item' => { PROGRAM => 'dnsmasq-dhcp', MESSAGE => 'DHCPNAK(eth0) 192.0.2.50 aa:bb:cc:dd:ee:ff wrong network' } );
is( $nak->{'dnsmasq_dhcp_type'},   'DHCPNAK',       'dnsmasq: NAK type' );
is( $nak->{'dnsmasq_dhcp_reason'}, 'wrong network', 'dnsmasq: NAK reason, not read as a hostname' );
ok( !exists( $nak->{'dnsmasq_dhcp_hostname'} ), 'dnsmasq: NAK sets no hostname' );

my $tftp = $dnsmasq->process_item(
	'item' => { PROGRAM => 'dnsmasq-tftp', MESSAGE => 'failed sending /srv/tftp/pxelinux.0 to 192.0.2.50' } );
is( $tftp->{'dnsmasq_tftp_action'},    'failed sending',       'dnsmasq: tftp failure action' );
is( $tftp->{'dnsmasq_tftp_file'},      '/srv/tftp/pxelinux.0', 'dnsmasq: tftp file' );
is( $tftp->{'dnsmasq_tftp_client_ip'}, '192.0.2.50',           'dnsmasq: tftp client ip' );

# a blocklist hit: the source is the hosts file that answered, which is what
# separates a blocked lookup from a resolved one
my $blocked = $dnsmasq->process_item(
	'item' => { PROGRAM => 'dnsmasq', MESSAGE => '/etc/pihole/gravity.list ads.example.com is 0.0.0.0' } );
is( $blocked->{'dnsmasq_source'}, '/etc/pihole/gravity.list', 'dnsmasq: local answer names its source' );
is( $blocked->{'dnsmasq_name'},   'ads.example.com',          'dnsmasq: local answer name' );

# "cached-stale" must not be eaten by the plain "cached" pattern
my $stale = $dnsmasq->process_item(
	'item' => { PROGRAM => 'dnsmasq', MESSAGE => 'cached-stale example.com is 93.184.216.34' } );
is( $stale->{'dnsmasq_source'}, 'cached-stale', 'dnsmasq: cached-stale is its own source' );

my $flood = $dnsmasq->process_item(
	'item' => { PROGRAM => 'dnsmasq', MESSAGE => 'Maximum number of concurrent DNS queries reached (max: 150)' } );
ok( looks_like_number( $flood->{'dnsmasq_max_queries'} ), 'dnsmasq: query ceiling is numeric' );

#
# sshd: connections that never reached authentication
#
my $sshd = Log::Munger->new( 'rules' => ['sshd'] );

my $kex = $sshd->process_item( 'message' => 'error: kex_exchange_identification: Connection closed by remote host',
	'program' => 'sshd' );
is( $kex->{'ssh_kex_error'}, 'Connection closed by remote host', 'sshd: kex_exchange_identification' );

my $negotiate = $sshd->process_item(
	'message' => 'Unable to negotiate with 203.0.113.7 port 44444: no matching host key type found. Their offer: ssh-rsa',
	'program' => 'sshd' );
is( $negotiate->{'ssh_src_ip'},         '203.0.113.7',                 'sshd: negotiate failure src ip' );
is( $negotiate->{'ssh_negotiate_error'}, 'no matching host key type found', 'sshd: negotiate failure reason' );
is( $negotiate->{'ssh_peer_offer'},     'ssh-rsa',                     'sshd: negotiate failure peer offer' );

my $bad_proto = $sshd->process_item(
	'message' => q{Bad protocol version identification 'GET / HTTP/1.1' from 203.0.113.7 port 44444},
	'program' => 'sshd' );
is( $bad_proto->{'ssh_bad_protocol'}, 'GET / HTTP/1.1', 'sshd: bad protocol identifier kept verbatim' );
is( $bad_proto->{'ssh_src_ip'},       '203.0.113.7',    'sshd: bad protocol src ip' );

# the auth methods the old alternation left out
my $none = $sshd->process_item( 'message' => 'Failed none for invalid user admin from 203.0.113.7 port 44444 ssh2',
	'program' => 'sshd' );
is( $none->{'ssh_method'},  'none',    'sshd: "none" probe is matched' );
is( $none->{'ssh_invalid'}, 'invalid', 'sshd: "none" probe invalid-user flag' );

my $pam_method = $sshd->process_item(
	'message' => 'Accepted keyboard-interactive/pam for neti from 192.0.2.5 port 54321 ssh2', 'program' => 'sshd' );
is( $pam_method->{'ssh_method'}, 'keyboard-interactive/pam', 'sshd: PAM method name is matched whole' );
is( $pam_method->{'ssh_user'},   'neti',                  'sshd: PAM method user' );

# fatal() puts a prefix on this one
my $timeout = $sshd->process_item( 'message' => 'fatal: Timeout before authentication for 203.0.113.7 port 44444',
	'program' => 'sshd' );
is( $timeout->{'ssh_src_ip'}, '203.0.113.7', 'sshd: timeout with the fatal: prefix' );

# PAM reports the peer as whatever it resolved, so a name goes somewhere other
# than the field the geoip lookup reads
my $pam_named = $sshd->process_item(
	'message' => 'error: PAM: User account has expired for neti from mail.example.net', 'program' => 'sshd' );
is( $pam_named->{'ssh_src_host'}, 'mail.example.net', 'sshd: PAM peer as a hostname' );
ok( !exists( $pam_named->{'ssh_src_ip'} ), 'sshd: a hostname peer does not land in ssh_src_ip' );

#
# exim: SMTP AUTH, TLS and connection handling
#
my $exim = Log::Munger->new( 'rules' => ['exim'] );

my $auth = $exim->process_item(
	'message' => 'login authenticator failed for (helo) [203.0.113.7]: 535 Incorrect authentication data (set_id=admin)',
	'program' => 'exim4' );
is( $auth->{'exim_authenticator'}, 'login',                          'exim: authenticator name' );
is( $auth->{'exim_src_ip'},        '203.0.113.7',                    'exim: auth failure src ip' );
is( $auth->{'exim_auth_error'},    '535 Incorrect authentication data', 'exim: auth failure error' );
is( $auth->{'exim_auth_user'},     'admin',                          'exim: auth failure set_id' );

my $connect_acl = $exim->process_item( 'message' => 'H=(helo) [203.0.113.7] rejected connection in "connect" ACL',
	'program' => 'exim' );
is( $connect_acl->{'exim_acl'},    'connect',     'exim: connect-ACL rejection names the ACL' );
is( $connect_acl->{'exim_src_ip'}, '203.0.113.7', 'exim: connect-ACL rejection src ip' );

# a HELO-time rejection has neither an envelope sender nor a recipient yet
my $helo_reject = $exim->process_item(
	'message' => 'H=(localhost) [203.0.113.7] rejected HELO: syntactically invalid argument', 'program' => 'exim' );
is( $helo_reject->{'exim_reject_verb'},   'HELO',                          'exim: HELO-time rejection verb' );
is( $helo_reject->{'exim_reject_reason'}, 'syntactically invalid argument', 'exim: HELO-time rejection reason' );

# the full host clause, including the port only newer exim logs
my $arrival = $exim->process_item(
	'message' => '1rABCD-0001Ab-2x <= a@b H=mail.example.com (helo.x) [203.0.113.7]:41234 P=esmtp S=1234',
	'program' => 'exim4' );
is( $arrival->{'exim_h_host'}, 'mail.example.com', 'exim: arrival reverse name' );
is( $arrival->{'exim_helo'},   'helo.x',           'exim: arrival claimed HELO' );
ok( looks_like_number( $arrival->{'exim_src_port'} ), 'exim: arrival source port is numeric' );

#
# dhcpd: the interface used to come out with a colon stuck on it, and the
# reason a request failed used to be dropped entirely
#
my $dhcpd = Log::Munger->new( 'rules' => ['dhcpd'] );

my $dry = $dhcpd->process_item(
	'message' => 'DHCPDISCOVER from aa:bb:cc:dd:ee:ff via eth0: network 192.0.2.0/24: no free leases',
	'program' => 'dhcpd' );
is( $dry->{'dhcp_iface'},   'eth0', 'dhcpd: interface has no trailing colon' );
is( $dry->{'dhcp_message'}, 'network 192.0.2.0/24: no free leases', 'dhcpd: pool-exhausted reason is kept' );

# the same interface on a line with nothing appended has to come out identically
my $plain = $dhcpd->process_item( 'message' => 'DHCPDISCOVER from aa:bb:cc:dd:ee:ff via eth0', 'program' => 'dhcpd' );
is( $plain->{'dhcp_iface'}, $dry->{'dhcp_iface'}, 'dhcpd: interface is the same with and without a trailing note' );

my $inform = $dhcpd->process_item( 'message' => 'DHCPINFORM from 192.0.2.50 via eth0', 'program' => 'dhcpd' );
is( $inform->{'dhcp_type'}, 'DHCPINFORM', 'dhcpd: INFORM type' );
is( $inform->{'dhcp_ip'},   '192.0.2.50', 'dhcpd: INFORM names the client by address' );

#
# http access logs: apache's vhost formats
#
my $http = Log::Munger->new( 'rules' => ['http_access_logs'] );

my $vhost = $http->process_item(
	'item' => 'example.com:80 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"' );
is( $vhost->{'http_vhost'},    'example.com', 'http: vhost_combined vhost' );
is( $vhost->{'http_clientip'}, '127.0.0.1',   'http: vhost_combined client ip' );
is( $vhost->{'http_agent'},    'Mozilla/5.0', 'http: vhost_combined user agent' );
ok( looks_like_number( $vhost->{'http_port'} ), 'http: vhost port is numeric' );

# vhost_common has the vhost but no port
my $vhost_common = $http->process_item(
	'item' => 'example.com 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326' );
is( $vhost_common->{'http_vhost'},    'example.com', 'http: vhost_common vhost' );
is( $vhost_common->{'http_clientip'}, '127.0.0.1',   'http: vhost_common client ip' );
ok( !exists( $vhost_common->{'http_port'} ), 'http: vhost_common sets no port' );

# and the un-prefixed forms still work
my $plain_combined = $http->process_item(
	'item' => '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"' );
is( $plain_combined->{'http_clientip'}, '127.0.0.1', 'http: plain combined still matches' );
ok( !exists( $plain_combined->{'http_vhost'} ), 'http: plain combined sets no vhost' );

#
# squid: the two apache-shaped logformats, and cache.log
#
my $squid = Log::Munger->new( 'rules' => ['squid'] );

my $combined = $squid->process_item(
	'item' => '192.0.2.5 - neti [15/Jul/2026:10:00:00 +0000] "GET http://example.com/ HTTP/1.1" 200 1234 "http://ref.example/" "Mozilla/5.0" TCP_MISS:HIER_DIRECT' );
is( $combined->{'squid_client_ip'},   '192.0.2.5',   'squid: combined client ip' );
is( $combined->{'squid_result_code'}, 'TCP_MISS',    'squid: combined result code' );
is( $combined->{'squid_hierarchy'},   'HIER_DIRECT', 'squid: combined hierarchy' );
is( $combined->{'squid_agent'},       'Mozilla/5.0', 'squid: combined user agent' );

my $tunnel = $squid->process_item(
	'item' => '192.0.2.5 - - [15/Jul/2026:10:00:00 +0000] "CONNECT example.com:443 HTTP/1.1" 200 0 TCP_TUNNEL:HIER_DIRECT' );
is( $tunnel->{'squid_method'},      'CONNECT',          'squid: common CONNECT method' );
is( $tunnel->{'squid_url'},         'example.com:443',  'squid: common CONNECT target' );
is( $tunnel->{'squid_result_code'}, 'TCP_TUNNEL',       'squid: common result code' );

# cache.log rides a second, GATED rule: its patterns are far too loose to be
# let loose on every record the way the gateless access rule is
my $alert = $squid->process_item(
	'item' => { PROGRAM => 'squid', MESSAGE => 'kid1| SECURITY ALERT: Host header forgery detected' } );
is( $alert->{'squid_kid'},     'kid1',                          'squid: cache.log kid' );
is( $alert->{'squid_level'},   'SECURITY ALERT',                'squid: cache.log severity' );
is( $alert->{'squid_message'}, 'Host header forgery detected',  'squid: cache.log message' );

# an unrecognised cache.log line still keeps its text rather than being a miss
my $catchall = $squid->process_item( 'item' => { PROGRAM => 'squid', MESSAGE => 'Ready to serve requests.' } );
is( $catchall->{'squid_message'}, 'Ready to serve requests.', 'squid: cache.log catch-all keeps the text' );

# ...but the loose cache patterns must not reach a record from anything else
my $not_squid = $squid->process_item(
	'item' => { PROGRAM => 'sshd', MESSAGE => 'WARNING: this belongs to some other daemon' } );
is( $not_squid, undef, 'squid: the gated cache rule ignores another daemon' );

#
# the squid access rule is gateless, so it is considered for every record. Its
# patterns require the "%Ss:%Sh" tail precisely so that an apache line loaded
# alongside it is not stolen out from under http_access_logs.
#
my $both = Log::Munger->new( 'rules' => [ 'squid', 'http_access_logs' ] );
my $apache = $both->process_item(
	'item' => '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "-" "Mozilla/5.0"' );
is( $apache->{'http_clientip'}, '127.0.0.1', 'apache line goes to http_access_logs even with squid loaded first' );
ok( !exists( $apache->{'squid_client_ip'} ), 'squid does not claim an apache line' );

#
# kernel: the network stack complaining
#
my $kernel = Log::Munger->new( 'rules' => ['kernel'] );

my $syn = $kernel->process_item(
	'message' => 'TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.  Check SNMP counters.',
	'program' => 'kernel' );
is( $syn->{'kernel_syn_action'}, 'cookies', 'kernel: SYN flood action' );
ok( looks_like_number( $syn->{'kernel_syn_port'} ), 'kernel: SYN flood port is numeric' );

my $syn6 = $kernel->process_item(
	'message' => 'TCP: Possible SYN flooding on port [::ffff:192.0.2.1]:80. Sending cookies.', 'program' => 'kernel' );
is( $syn6->{'kernel_syn_local_addr'}, '::ffff:192.0.2.1', 'kernel: SYN flood local address' );

my $conntrack = $kernel->process_item( 'message' => 'nf_conntrack: nf_conntrack: table full, dropping packet',
	'program' => 'kernel' );
is( $conntrack->{'kernel_conntrack_module'}, 'nf_conntrack', 'kernel: conntrack table full' );

# the kernel prints the destination first even though the sentence reads
# "source", so check each address lands in the field named for what it is
my $martian = $kernel->process_item( 'message' => 'IPv4: martian source 192.0.2.1 from 10.0.0.1, on dev eth0',
	'program' => 'kernel' );
is( $martian->{'kernel_martian_kind'},   'source',    'kernel: martian kind' );
is( $martian->{'kernel_martian_dst_ip'}, '192.0.2.1', 'kernel: martian destination address' );
is( $martian->{'kernel_martian_src_ip'}, '10.0.0.1',  'kernel: martian source address' );
is( $martian->{'kernel_martian_iface'},  'eth0',      'kernel: martian interface' );

#
# base: HTTPDATE is documented as the apache access-log timestamp and could not
# match one, because the timezone offset is signed and the INT it was built on
# is not
#
my $base = Log::Munger::RuleFileParser->new->load( 'file' => 'base' );
my $httpdate = $base->{'vars'}{'HTTPDATE'};
foreach my $stamp ( '10/Oct/2000:13:55:36 -0700', '15/Jul/2026:10:00:00 +0000' ) {
	like( $stamp, qr/\A(?:$httpdate)\z/, "base: HTTPDATE matches '$stamp'" );
}

#
# sudo: the command line as sudo actually writes it
#
# Two things the in-YAML pattern tests could not have caught. sudo right-aligns
# the invoking user in an eight-character field, so a real line arrives with
# leading spaces, and it omits TTY= entirely when there was no controlling
# terminal -- which is every cron job and every snmpd extend script. The
# pattern demanded the blob start at TTY=, so on a host where sudo is used
# mostly by daemons it matched nothing at all. The split into sudo_PWD /
# sudo_USER / sudo_COMMAND happens in a decompose, which rule tests never run,
# so it can only be checked here.
#
my $sudo = Log::Munger->new( 'rules' => ['sudo'] );

my $sudo_notty = $sudo->process_item(
	'message' => '   snmpd : PWD=/ ; USER=root ; COMMAND=/usr/local/etc/snmp-extends/bind',
	'program' => 'sudo'
);
is( $sudo_notty->{'sudo_user'},    'snmpd', 'sudo: right-aligned invoking user' );
is( $sudo_notty->{'sudo_PWD'},     '/',     'sudo: kv blob starting at PWD= is still decomposed' );
is( $sudo_notty->{'sudo_USER'},    'root',  'sudo: target user' );
is( $sudo_notty->{'sudo_COMMAND'}, '/usr/local/etc/snmp-extends/bind', 'sudo: command' );
ok( !exists( $sudo_notty->{'sudo_TTY'} ), 'sudo: no tty means no sudo_TTY' );

my $sudo_tty = $sudo->process_item(
	'message' => '    root : TTY=pts/6 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/true',
	'program' => 'sudo'
);
is( $sudo_tty->{'sudo_user'}, 'root',  'sudo: padded user with a tty' );
is( $sudo_tty->{'sudo_TTY'},  'pts/6', 'sudo: tty' );

#
# cron: FreeBSD logs under argv[0]
#
# The gate listed the bare names only, so on FreeBSD -- where cron's syslog
# ident is the full "/usr/sbin/cron" -- not one cron line matched.
#
my $cron = Log::Munger->new( 'rules' => ['cron'] );
my $cron_cmd = $cron->process_item( 'message' => '(root) CMD (/usr/libexec/atrun)', 'program' => '/usr/sbin/cron' );
is( $cron_cmd->{'cron_user'},    'root',                'cron: path-prefixed program still gates through' );
is( $cron_cmd->{'cron_command'}, '/usr/libexec/atrun', 'cron: command' );

#
# pam: OpenPAM
#
# pam.yaml is gateless and was built entirely around Linux-PAM's
# "pam_<module>(<service>:<type>):" header. OpenPAM, which is what FreeBSD and
# macOS ship, has no such header -- it prefixes the calling function instead --
# so every PAM line on a BSD host fell through. The program name on these is
# whichever binary called into PAM, which is the point of checking two.
#
my $pam = Log::Munger->new( 'rules' => ['pam'] );

my $openpam = $pam->process_item(
	'message' => 'in openpam_load_module(): no pam_nologin.so found',
	'program' => '/usr/sbin/cron'
);
is( $openpam->{'pam_function'}, 'openpam_load_module',      'pam: OpenPAM function' );
is( $openpam->{'pam_message'},  'no pam_nologin.so found', 'pam: OpenPAM message' );

my $openpam_mod = $pam->process_item(
	'message' => 'in pam_group(): (pam_group) neither luser nor ruser specified, assuming ruser',
	'program' => 'sshd'
);
is( $openpam_mod->{'pam_module'},  'group', 'pam: module that names itself again is pulled out' );
is( $openpam_mod->{'pam_message'}, 'neither luser nor ruser specified, assuming ruser', 'pam: message without the module prefix' );

#
# postfix: the programs that only ever log a warning or a fatal
#
# Several daemons had no POSTFIX_WARNING in their pattern list, so the only
# lines they ever produce on a broken system -- the ones worth alerting on --
# were the ones that got dropped. The command-line utilities had no rule at
# all, and postfix-script arrives under two different program names depending
# on how the start-up script was invoked.
#
my $postfix = Log::Munger->new( 'rules' => ['postfix'] );

my @postfix_fatals = (
	[ 'postfix/pickup',         'fatal: scan_dir_push: open directory maildrop: No such file or directory' ],
	[ 'postfix/postalias',      'fatal: open database /etc/postfix/aliases.db: Permission denied' ],
	[ 'postfix/postqueue',      'fatal: usage: postqueue -f | postqueue -p' ],
	[ 'postfix/postfix-script', 'fatal: the Postfix mail system is not running' ],
);
foreach my $case (@postfix_fatals) {
	my ( $program, $message ) = @{$case};
	my $fields = $postfix->process_item( 'message' => $message, 'program' => $program );
	is( $fields->{'postfix_message_level'}, 'fatal', "postfix: $program fatal is captured" )
		or diag( defined($fields) ? 'got instead: ' . join( ', ', sort keys %{$fields} ) : 'no match at all' );
}

#
# named: everything that is not a query
#
# named.yaml only knew about queries, transfers and resolution errors, which on
# an authoritative-plus-recursive server is a small minority of what it writes.
# A zone that fails to load is the case that matters -- it is logged once at
# start-up and never again -- and it was going nowhere.
#
my $named = Log::Munger->new( 'rules' => ['named'] );

my $zone_failed = $named->process_item(
	'message' => 'zone 255.in-addr.arpa/IN/internal-view: loading from master file /etc/namedb/empty.db failed: file not found',
	'program' => 'named'
);
is( $zone_failed->{'dns_zone_name'},  '255.in-addr.arpa',      'named: failed zone name' );
is( $zone_failed->{'dns_view'},       'internal-view',         'named: view the zone belongs to' );
is( $zone_failed->{'dns_zone_file'},  '/etc/namedb/empty.db', 'named: zone file it could not read' );
is( $zone_failed->{'dns_zone_error'}, 'file not found',        'named: reason' );

my $zone_status = $named->process_item(
	'message' => 'zone localhost/IN/internal-view: not loaded due to errors.', 'program' => 'named' );
is( $zone_status->{'dns_zone_status'}, 'not loaded due to errors.', 'named: zone status' );

# a zone that loaded must still reach NAMED_ZONE_LOAD rather than being taken
# by the looser status pattern that follows it
my $zone_loaded = $named->process_item( 'message' => 'zone example.com/IN: loaded serial 2024010101', 'program' => 'named' );
ok( looks_like_number( $zone_loaded->{'dns_zone_serial'} ), 'named: a loaded zone still yields a numeric serial' );
ok( !exists( $zone_loaded->{'dns_zone_status'} ), 'named: a loaded zone is not swallowed by NAMED_ZONE_STATUS' );

my $fmt_err = $named->process_item(
	'message' => 'DNS format error from 192.0.2.2#53 resolving a.example.com/AAAA for 198.51.100.9#28116: reply has no answer',
	'program' => 'named'
);
is( $fmt_err->{'dns_src_ip'},    '192.0.2.2',    'named: format error server' );
is( $fmt_err->{'dns_client_ip'}, '198.51.100.9', 'named: client the lookup was for' );
ok( looks_like_number( $fmt_err->{'dns_client_port'} ), 'named: client port is numeric' );

# ...and the same line for an internally generated query, which has no client
my $fmt_err_internal = $named->process_item(
	'message' => 'DNS format error from 192.0.2.2#53 resolving a.example.com/NS for <unknown>: reply has no answer',
	'program' => 'named'
);
is( $fmt_err_internal->{'dns_src_ip'}, '192.0.2.2', 'named: format error with no client still parses' );
ok( !exists( $fmt_err_internal->{'dns_client_ip'} ), 'named: "<unknown>" client sets no address' );

my $cpq = $named->process_item( 'message' => 'clients-per-query increased to 15', 'program' => 'named' );
is( $cpq->{'dns_cpq_direction'}, 'increased', 'named: clients-per-query direction' );
ok( looks_like_number( $cpq->{'dns_clients_per_query'} ), 'named: clients-per-query value is numeric' );

#
# ntpd: the failure a jailed ntpd repeats forever
#
# An ntpd without CAP_SYS_TIME (or inside a FreeBSD jail) logs an ntp_adjtime
# failure on every poll and nothing else, so this one line is the entire log.
#
my $ntpd = Log::Munger->new( 'rules' => ['ntpd'] );
my $adjtime = $ntpd->process_item(
	'message' => 'local_clock: usr/src/contrib/ntp/ntpd/ntp_loopfilter.c line 814: ntp_adjtime: Operation not permitted',
	'program' => 'ntpd'
);
is( $adjtime->{'ntpd_function'}, 'local_clock',            'ntpd: function the call was made from' );
is( $adjtime->{'ntpd_syscall'},  'ntp_adjtime',            'ntpd: the call that failed' );
is( $adjtime->{'ntpd_error'},    'Operation not permitted', 'ntpd: errno text' );
ok( looks_like_number( $adjtime->{'ntpd_source_line'} ), 'ntpd: source line is numeric' );

# 4.2.8p18 capitalised the startup banner
my $ntpd_start = $ntpd->process_item( 'message' => 'ntpd 4.2.8p18-a (1): Starting', 'program' => 'ntpd' );
is( $ntpd_start->{'ntpd_version'}, '4.2.8p18-a', 'ntpd: capitalised "Starting" banner' );

#
# sshd: the shapes FreeBSD and OpenSSH 9.8 introduced
#
# FreeBSD renames OpenSSH's internal symbols to an Fssh_ prefix, so the kex
# error -- the highest-volume line on an exposed host -- did not match there.
# "Disconnected from user <name> <ip>" is the plain form of a line the pattern
# only accepted with an "authenticating" or "invalid" qualifier in front of it.
#
my $sshd_bsd = Log::Munger->new( 'rules' => ['sshd'] );

my $kex_bsd = $sshd_bsd->process_item(
	'message' => 'error: Fssh_kex_exchange_identification: read: Connection reset by peer',
	'program' => 'sshd-session'
);
is( $kex_bsd->{'ssh_kex_error'}, 'read: Connection reset by peer', 'sshd: Fssh_-prefixed kex error' );

my $disconnected = $sshd_bsd->process_item(
	'message' => 'Disconnected from user root 192.0.2.5 port 44398', 'program' => 'sshd-session' );
is( $disconnected->{'ssh_user'},   'root',      'sshd: unqualified "user <name>" disconnect' );
is( $disconnected->{'ssh_src_ip'}, '192.0.2.5', 'sshd: address from the same line' );
ok( !exists( $disconnected->{'ssh_conn_state'} ), 'sshd: no qualifier means no ssh_conn_state' );

my $rexec = $sshd_bsd->process_item(
	'message' => 'fatal: rexec of /usr/libexec/sshd-session failed: No such file or directory', 'program' => 'sshd' );
is( $rexec->{'ssh_rexec_path'}, '/usr/libexec/sshd-session', 'sshd: the sshd-session binary it could not run' );

my $ssh_err = $sshd_bsd->process_item(
	'message' => 'fatal: userauth_pubkey: parse publickey packet: incomplete message [preauth]',
	'program' => 'sshd-session'
);
is( $ssh_err->{'ssh_function'}, 'userauth_pubkey',                    'sshd: generic error function' );
is( $ssh_err->{'ssh_error'},    'parse publickey packet: incomplete message', 'sshd: generic error detail' );
is( $ssh_err->{'ssh_preauth'},  'preauth',                            'sshd: preauth marker' );

#
# dovecot: hyphenated service names
#
# The service name was matched with base WORD, which is \w only, so anything
# from auth-worker or indexer-worker went nowhere.
#
my $dovecot = Log::Munger->new( 'rules' => ['dovecot'] );
my $auth_worker = $dovecot->process_item(
	'message' => 'auth-worker: Fatal: master: service(auth-worker): child 53847 killed with signal 9',
	'program' => 'dovecot'
);
is( $auth_worker->{'dovecot_service'}, 'auth-worker', 'dovecot: hyphenated service name' );
is( $auth_worker->{'dovecot_level'},   'Fatal',       'dovecot: severity' );

#
# nslcd: the request prefix survives even on a line nothing else recognises
#
# Every nslcd line but the startup banner carries a session id and the map plus
# key it was asked about. Those are what say whether a directory outage is
# breaking real logins, so the catch-all peels the prefix off before giving up
# rather than keeping the whole line as prose.
#
my $nslcd = Log::Munger->new( 'rules' => ['nslcd'] );

my $nslcd_sleep = $nslcd->process_item(
	'message' => '[fb867b] <group/member="root"> no available LDAP server found, sleeping 1 seconds',
	'program' => 'nslcd'
);
is( $nslcd_sleep->{'nslcd_request_type'}, 'group/member', 'nslcd: request type with a slash in it' );
is( $nslcd_sleep->{'nslcd_request_arg'},  'root',         'nslcd: request key' );
ok( looks_like_number( $nslcd_sleep->{'nslcd_sleep_seconds'} ), 'nslcd: retry delay is numeric' );

my $nslcd_numeric_key = $nslcd->process_item(
	'message' => '[192b68] <group=1004> no available LDAP server found: Server is unavailable',
	'program' => 'nslcd'
);
is( $nslcd_numeric_key->{'nslcd_request_arg'}, '1004', 'nslcd: unquoted numeric request key' );
is( $nslcd_numeric_key->{'nslcd_error'}, 'Server is unavailable', 'nslcd: LDAP-side reason' );

my $nslcd_unknown = $nslcd->process_item( 'message' => '[045836] <passwd="neti"> no such user', 'program' => 'nslcd' );
is( $nslcd_unknown->{'nslcd_session'}, '045836',      'nslcd: catch-all keeps the session id' );
is( $nslcd_unknown->{'nslcd_message'}, 'no such user', 'nslcd: catch-all keeps the rest of the line' );

#
# pkg: the name/version split
#
# install and deinstall give the package as one "name-version" token, and both
# halves can contain digits and hyphens. The split has to land on the last
# hyphen that starts a version, which is the only thing separating "py311-certifi"
# from "py311" plus a nonsense version.
#
my $pkg = Log::Munger->new( 'rules' => ['pkg'] );

my @pkg_names = (
	[ 'openjdk21-21.0.4+7.1',    'openjdk21',     '21.0.4+7.1' ],
	[ 'py311-certifi-2024.8.30', 'py311-certifi', '2024.8.30' ],
	[ 'fd-find-10.2.0_3',        'fd-find',       '10.2.0_3' ],
	[ 'postfix-3.10.3,1',        'postfix',       '3.10.3,1' ],
);
foreach my $case (@pkg_names) {
	my ( $token, $name, $version ) = @{$case};
	my $fields = $pkg->process_item( 'message' => "$token installed", 'program' => 'pkg' );
	is( $fields->{'pkg_name'},    $name,    "pkg: '$token' name" );
	is( $fields->{'pkg_version'}, $version, "pkg: '$token' version" );
}

# an upgrade puts the resulting version in the same field an install does, so
# "what is on this box now" is one field regardless of how it got there
my $pkg_up = $pkg->process_item( 'message' => 'nginx upgraded: 1.28.0_2,3 -> 1.28.0_3,3', 'program' => 'pkg' );
is( $pkg_up->{'pkg_version_from'}, '1.28.0_2,3', 'pkg: version upgraded from' );
is( $pkg_up->{'pkg_version'},      '1.28.0_3,3', 'pkg: version upgraded to lands in pkg_version' );
ok( !exists( $pkg_up->{'pkg_message'} ), 'pkg: a known shape does not reach the catch-all' );

# the bootstrap binary logs under its own program name
my $pkg_static = $pkg->process_item( 'message' => 'pkg-2.6.2_1 installed', 'program' => 'pkg-static' );
is( $pkg_static->{'pkg_name'}, 'pkg', 'pkg: pkg-static gates through too' );

#
# sympa: the object references buried in the message text
#
# Sympa stringifies its objects into the middle of a sentence, and which list a
# line is about is the thing worth filtering on. Those are lifted out by
# pattern decomposes rather than by the rule patterns, because a reference can
# sit anywhere in the message and one message often carries two -- so none of
# this is reachable from the tests inside the YAML.
#
my $sympa = Log::Munger->new( 'rules' => ['sympa'] );

my $sympa_send = $sympa->process_item(
	'message' => 'notice Sympa::Mailer::store() Done sending message Sympa::Message <1.5.1769403034.x.familytest@example.net_s,90281,2422/s> for Sympa::List <familytest@example.net>',
	'program' => 'bulk'
);
is( $sympa_send->{'sympa_function'},   'Sympa::Mailer::store',    'sympa: sub the message came from' );
is( $sympa_send->{'sympa_list'},       'familytest@example.net', 'sympa: list lifted out of mid-sentence' );
is( $sympa_send->{'sympa_message_id'}, '1.5.1769403034.x.familytest@example.net_s,90281,2422/s',
	'sympa: message id from the same line' );

# a task reference is a "key=value;key=value" body, split a second time
my $sympa_task = $sympa->process_item(
	'message' => 'notice Sympa::Spindle::ProcessTask::_execute() Running task Sympa::Task <date=1769401093;label=ACTION;model=eval_bouncers;context=*>',
	'program' => 'task_manager'
);
is( $sympa_task->{'sympa_task_model'},   'eval_bouncers', 'sympa: task model' );
is( $sympa_task->{'sympa_task_label'},   'ACTION',        'sympa: task label' );
is( $sympa_task->{'sympa_task_context'}, '*',             'sympa: task context' );
ok( looks_like_number( $sympa_task->{'sympa_task_date'} ), 'sympa: task date is numeric' );

my $sympa_req = $sympa->process_item(
	'message' => 'notice Sympa::Spindle::ProcessRequest::_twist() Processing Sympa::Request <action=create_list;context=example.net>',
	'program' => 'sympa_msg'
);
is( $sympa_req->{'sympa_request_action'},  'create_list', 'sympa: request action' );
is( $sympa_req->{'sympa_request_context'}, 'example.net', 'sympa: request context' );

#
# at err and below sympa prints the whole call stack instead of one frame, and
# the innermost frame is the one that actually failed
#
my $sympa_err = $sympa->process_item(
	'message' => 'err main::#84 > Sympa::CLI::run#96 > Sympa::DatabaseManager::probe_db#172 > Sympa::Database::do_query#281 Unable to execute SQL statement',
	'program' => 'sympa/health_check'
);
is( $sympa_err->{'sympa_level'},    'err',                     'sympa: level' );
is( $sympa_err->{'sympa_function'}, 'Sympa::Database::do_query', 'sympa: innermost frame, not the outermost' );
is( $sympa_err->{'sympa_message'},  'Unable to execute SQL statement', 'sympa: message after the stack' );
is( $sympa_err->{'sympa_stack'},
	'main::#84 > Sympa::CLI::run#96 > Sympa::DatabaseManager::probe_db#172 > Sympa::Database::do_query#281',
	'sympa: the whole chain is kept' );
ok( looks_like_number( $sympa_err->{'sympa_line'} ), 'sympa: line number is numeric' );

# sympa answers to some very generic program names, so the absence of a
# catch-all is the thing keeping it from claiming another daemon's lines
foreach my $program (qw(bulk archived bounced task_manager)) {
	my $not_sympa = $sympa->process_item( 'message' => 'started', 'program' => $program );
	is( $not_sympa, undef, "sympa: a non-sympa-shaped line under PROGRAM=$program is left alone" );
}

#
# hostapd: the events an access point actually spends its day logging
#
# hostapd.yaml knew about association and the AP state machine and nothing
# else, which on a working AP is a minority of the traffic -- the 4-way
# handshake completion alone outnumbers every other line it writes. The
# control-event names are enumerated by prefix rather than matched as "a run of
# capitals" so that ordinary prose opening with a capitalised word is not read
# as an event, which is the property worth pinning here.
#
my $hostapd = Log::Munger->new( 'rules' => ['hostapd'] );

my $eapol = $hostapd->process_item(
	'message' => 'phy1-ap1: EAPOL-4WAY-HS-COMPLETED aa:bb:cc:dd:ee:ff', 'program' => 'hostapd' );
is( $eapol->{'hostapd_iface'}, 'phy1-ap1',          'hostapd: interface on a ctrl event' );
is( $eapol->{'hostapd_event'}, 'EAPOL-4WAY-HS-COMPLETED', 'hostapd: event name' );
is( $eapol->{'hostapd_sta'},   'aa:bb:cc:dd:ee:ff', 'hostapd: station' );

my $acs = $hostapd->process_item(
	'message' => 'phy2-ap0: ACS-COMPLETED freq=2462 channel=11', 'program' => 'hostapd' );
is( $acs->{'hostapd_event'},      'ACS-COMPLETED',        'hostapd: ctrl event with no station' );
is( $acs->{'hostapd_event_data'}, 'freq=2462 channel=11', 'hostapd: trailing event data' );

# prose that opens with capitals is NOT an event
my $not_event = $hostapd->process_item(
	'message' => 'WPA-PSK enabled, but PSK or passphrase is not configured.', 'program' => 'hostapd' );
is( $not_event->{'hostapd_message'}, 'WPA-PSK enabled, but PSK or passphrase is not configured.',
	'hostapd: capitalised prose reaches the catch-all whole' );
ok( !exists( $not_event->{'hostapd_event'} ), 'hostapd: ...and is not read as an event named WPA-PSK' );

# the catch-all peels an interface prefix but must not mistake a subsystem tag
# or one of hostapd's own function names for one
my $iface_err = $hostapd->process_item( 'message' => 'phy2-ap0: Unable to setup interface.', 'program' => 'hostapd' );
is( $iface_err->{'hostapd_iface'},   'phy2-ap0',                'hostapd: catch-all keeps the interface' );
is( $iface_err->{'hostapd_message'}, 'Unable to setup interface.', 'hostapd: ...and the rest of the line' );

foreach my $prefixed (
	'nl80211: deinit ifname=phy2-ap0 disabled_11b_rates=0',
	"hostapd_free_hapd_data: Interface phy2-ap0 wasn't started",
	'ACS: Failed to start'
	)
{
	my $fields = $hostapd->process_item( 'message' => $prefixed, 'program' => 'hostapd' );
	ok( !exists( $fields->{'hostapd_iface'} ), "hostapd: '$prefixed' is not read as an interface prefix" );
	is( $fields->{'hostapd_message'}, $prefixed, 'hostapd: ...and survives whole' );
}

# the OpenWRT phy/bss reconfiguration messages, which name a radio not an
# interface and appear on no other kind of host
my $phy_cfg = $hostapd->process_item(
	'message' => 'Set new config for phy phy1: /var/run/hostapd-phy1.conf', 'program' => 'hostapd' );
is( $phy_cfg->{'hostapd_phy'},         'phy1',                        'hostapd: phy being reconfigured' );
is( $phy_cfg->{'hostapd_config_file'}, '/var/run/hostapd-phy1.conf', 'hostapd: config file' );

# ...and the same line with nothing after the colon, which is what an inline
# configuration produces
my $phy_cfg_empty = $hostapd->process_item( 'message' => 'Set new config for phy phy2:', 'program' => 'hostapd' );
is( $phy_cfg_empty->{'hostapd_phy'}, 'phy2', 'hostapd: phy with an empty config path' );
ok( !exists( $phy_cfg_empty->{'hostapd_config_file'} ), 'hostapd: ...and no config file field' );

my $bss = $hostapd->process_item( 'message' => "Remove bss 'phy1-ap1' on phy 'phy1'", 'program' => 'hostapd' );
is( $bss->{'hostapd_bss_action'}, 'Remove',   'hostapd: bss action' );
is( $bss->{'hostapd_bss'},        'phy1-ap1', 'hostapd: bss name, unquoted' );
is( $bss->{'hostapd_phy'},        'phy1',     'hostapd: phy the bss is on' );

#
# kernel: bridge ports and netdev mode changes
#
# Both are ordinary Linux netdev messages rather than anything OpenWRT-specific
# -- a container host running a bridge produces the same ones -- and both were
# missing. The netfilter rule gates on PROGRAM=kernel too, so the check that
# matters is that neither of these has started claiming a firewall line.
#
my $kernel_net = Log::Munger->new( 'rules' => [ 'kernel', 'netfilter' ] );

my $br_port = $kernel_net->process_item(
	'message' => '[ 4391.338436] br-lan: port 10(phy0-ap2) entered disabled state', 'program' => 'kernel' );
is( $br_port->{'kernel_bridge'},       'br-lan',   'kernel: bridge' );
is( $br_port->{'kernel_iface'},        'phy0-ap2', 'kernel: port interface' );
is( $br_port->{'kernel_bridge_state'}, 'disabled', 'kernel: STP state' );
ok( looks_like_number( $br_port->{'kernel_bridge_port'} ), 'kernel: bridge port number is numeric' );

my $promisc = $kernel_net->process_item(
	'message' => 'mwlwifi 0000:01:00.0 phy0-ap2 (unregistering): left allmulticast mode', 'program' => 'kernel' );
is( $promisc->{'kernel_driver'},        'mwlwifi',     'kernel: driver' );
is( $promisc->{'kernel_bus_id'},        '0000:01:00.0', 'kernel: bus id' );
is( $promisc->{'kernel_iface'},         'phy0-ap2',    'kernel: interface' );
is( $promisc->{'kernel_netdev_action'}, 'left',        'kernel: netdev action' );
is( $promisc->{'kernel_netdev_mode'},   'allmulticast', 'kernel: netdev mode' );

# a software device has no driver or bus in front of it
my $promisc_bare = $kernel_net->process_item( 'message' => 'eth0: entered promiscuous mode', 'program' => 'kernel' );
is( $promisc_bare->{'kernel_iface'}, 'eth0', 'kernel: netdev mode with no driver prefix' );
ok( !exists( $promisc_bare->{'kernel_driver'} ), 'kernel: ...sets no driver' );

# with both files loaded, a firewall line still goes to netfilter
my $ufw = $kernel_net->process_item(
	'message' => '[ 4391.338436] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.7 DST=192.0.2.1 PROTO=TCP SPT=44444 DPT=22',
	'program' => 'kernel'
);
ok( exists( $ufw->{'nf_SRC'} ), 'kernel: a firewall line still reaches netfilter' );

#
# dnsmasq: the start-up and reload messages
#
# "read <file> - N names" is how a hosts file being picked up shows, and on
# anything writing hosts files at runtime the count is the thing worth
# watching. None of these matched before.
#
my $dnsmasq_owrt = Log::Munger->new( 'rules' => ['dnsmasq'] );

my $read_hosts = $dnsmasq_owrt->process_item( 'message' => 'read /etc/hosts - 12 names', 'program' => 'dnsmasq' );
is( $read_hosts->{'dnsmasq_hosts_file'}, '/etc/hosts', 'dnsmasq: hosts file read' );
is( $read_hosts->{'dnsmasq_hosts_kind'}, 'names',      'dnsmasq: what was counted' );
ok( looks_like_number( $read_hosts->{'dnsmasq_hosts_count'} ), 'dnsmasq: hosts count is numeric' );

my $using_local = $dnsmasq_owrt->process_item(
	'message' => 'using only locally-known addresses for local', 'program' => 'dnsmasq' );
is( $using_local->{'dnsmasq_resolution'}, 'only locally-known addresses', 'dnsmasq: local-only domain' );
is( $using_local->{'dnsmasq_domain'},     'local',                       'dnsmasq: the domain it applies to' );

my $using_ns = $dnsmasq_owrt->process_item(
	'message' => 'using nameserver 192.0.2.1#53 for domain example.com', 'program' => 'dnsmasq' );
is( $using_ns->{'dnsmasq_server_ip'}, '192.0.2.1',   'dnsmasq: per-domain nameserver' );
is( $using_ns->{'dnsmasq_domain'},    'example.com', 'dnsmasq: per-domain nameserver domain' );
ok( looks_like_number( $using_ns->{'dnsmasq_server_port'} ), 'dnsmasq: nameserver port is numeric' );

#
# dropbear: the SSH server on an embedded box
#
# Field names are deliberately the same shape as sshd.yaml's so a query across
# routers and servers does not have to ask each one differently. Dropbear
# writes the peer as "<address>:<port>" where sshd writes "<address> port
# <port>", which is the bit that needs getting right.
#
my $dropbear = Log::Munger->new( 'rules' => ['dropbear'] );

my $db_pubkey = $dropbear->process_item(
	'message' => "Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:AbCdEf0123456789 from 192.0.2.5:48719",
	'program' => 'dropbear'
);
is( $db_pubkey->{'dropbear_user'},            'root',                  'dropbear: authenticated user' );
is( $db_pubkey->{'dropbear_key_type'},        'ssh-ed25519',           'dropbear: key type' );
is( $db_pubkey->{'dropbear_key_fingerprint'}, 'SHA256:AbCdEf0123456789', 'dropbear: key fingerprint' );
is( $db_pubkey->{'dropbear_src_ip'},          '192.0.2.5',             'dropbear: peer address' );
ok( looks_like_number( $db_pubkey->{'dropbear_src_port'} ), 'dropbear: peer port is numeric' );

my $db_exit = $dropbear->process_item(
	'message' => 'Exit (root) from <192.0.2.5:64040>: Disconnect received', 'program' => 'dropbear' );
is( $db_exit->{'dropbear_user'},        'root',                'dropbear: user on exit' );
is( $db_exit->{'dropbear_src_ip'},      '192.0.2.5',           'dropbear: peer on exit' );
is( $db_exit->{'dropbear_exit_reason'}, 'Disconnect received', 'dropbear: exit reason' );

# "Exit before auth" has to win over the plain "Exit" pattern
my $db_preauth = $dropbear->process_item(
	'message' => "Exit before auth from <203.0.113.7:44444>: (user 'root', 0 fails): Exited normally",
	'program' => 'dropbear'
);
is( $db_preauth->{'dropbear_src_ip'}, '203.0.113.7', 'dropbear: pre-auth exit peer' );
ok( !exists( $db_preauth->{'dropbear_user'} ), 'dropbear: a pre-auth exit names no authenticated user' );

#
# luci: a web login to a router is a root-equivalent authentication event
#
# LuCI is a CGI, not a daemon, so its lines arrive under whichever program was
# serving the request. There is no catch-all: uhttpd's own output, and the
# ucode backtraces a failing LuCI page produces, must be left alone.
#
my $luci = Log::Munger->new( 'rules' => ['luci'] );

foreach my $program (qw(uhttpd dispatcher.uc luci)) {
	my $login = $luci->process_item(
		'message' => '[info] luci: accepted login on /admin/system for root from 192.0.2.5',
		'program' => $program
	);
	is( $login->{'luci_user'},   'root',          "luci: login under PROGRAM=$program" );
	is( $login->{'luci_src_ip'}, '192.0.2.5',     'luci: client address' );
	is( $login->{'luci_path'},   '/admin/system', 'luci: path logged in on' );
}

my $not_luci = $luci->process_item(
	'message' => "Runtime error: Unable to dlopen file '/usr/lib/ucode/ubus.so'", 'program' => 'uhttpd' );
is( $not_luci, undef, 'luci: uhttpd output that is not a LuCI message is left alone' );

done_testing();
