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

done_testing();
