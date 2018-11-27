#!/usr/bin/perl 
#
# Basically derived from PortaOne's RADIUS Accounting
# by Oleksandr Kapitanenko
# (http://www.voip-info.org/tiki-index.php?page=PortaOne+Radius+auth)
#
# RADIUS accounting daemon 
# (c) LANBilling (www.lanbilling.ru)
# by Murashkin Artem <murashkin@lanbilling.ru>
#

use strict;
use Asterisk::Manager;
use Sys::Syslog;
use POSIX;
use Authen::Radius;
use Digest::MD5 qw(md5_hex);

my $debug = 0;

Authen::Radius->load_dictionary;

# Lock file
#
my $lock_file = '/var/run/ast-rad-acc.pid';

# Config vars
#
my $runas_user = 'nobody';

my $ast_hostname = 'localhost';
my $ast_username = 'test';
my $ast_password = 'test';

my $monitor_dir = '/var/spool/asterisk/monitor';

# Read global RADIUS configuratuin from extensions.conf
#
# I havte doing that but Asterisk manager interface can not read global variables
#
my $config_dir = '/etc/asterisk';

# Globals
#
my %channels;
my ($rad_serv, $rad_sec, $rad_port, $nas_ip, $update_timeout);

# Check if already running
#
if( -e $lock_file ) {
   open(PID,$lock_file);
   my $pid=<PID>;
   close PID;
   chomp $pid;
   if( !-e "/proc/$pid" ) {
      print STDERR "Lock file present, but no process with pid=$pid.\n";
      die "Can't delete lock file $lock_file\n" if !unlink $lock_file;
      print STDERR "Lock file has been removed.\n";
   } else {
      die "Lockfile present, another copy is punning pid=$pid\n";
   }
}

load_config();
my ($name, $passwd, $uid, $gid) = getpwnam($runas_user) or die "$runas_user not in passwd file";;

# Become daemon
#
my $pid;
if( !defined($pid = fork()) ) {
	die "cannot fork: $!";
} elsif ($pid) {
	# Create lockfile, and finish parent process
	#
	open(PID, "> $lock_file") || die "ast-rad-acc.pl: Unable to create lockfile $lock_file\n";
	print PID "$pid";
	close PID;
	chown $uid, $gid, $lock_file;
	exit;
} else {
        # daemon
        setpgrp();
        select(STDERR); $| = 1;
        select(STDOUT); $| = 1;
	openlog('ast-rad-acc', 'cons,pid', 'daemon');
        syslog('notice', "RADIUS accounting for Asterisk started");
}

# Install signall handler
#
$SIG{INT} = \&safe_exit;
$SIG{QUIT} = \&safe_exit;
$SIG{TERM} = \&safe_exit;
$SIG{HUP} = \&load_config;
$SIG{ALRM} = \&send_update if $update_timeout>0;
alarm 60 if $update_timeout>0;
# Drop privileges
#
setuid($uid);
$< = $uid;
$> = $uid;

my $astman = new Asterisk::Manager;
$astman->user($ast_username);
$astman->secret($ast_password);
$astman->host($ast_hostname);

my $ast_connected = 1;
while( 1 ) {
	if( $astman->connect ) {
		$ast_connected = 1;
		syslog('info', 'Connected to Asterisk!');
		$astman->setcallback('DEFAULT', \&status_callback);
		eval { $astman->eventloop; };
		syslog('err',$@) if $@;
	} else {
		syslog('err', 'Could not connect to Asterisk!') if $ast_connected;
		$ast_connected = 0;
	}
	sleep 1;
}

sub status_callback {
	my (%event) = @_;

	return unless defined(%event);
        if($debug){
        	foreach (keys %event) {
                	syslog('debug', "$_: ". $event{$_} . "\n" );
		}
		syslog('debug', "\n");
	}


	if (defined $channels{$event{'Channel'}} && ! (ref($channels{$event{'Channel'}}) =~ /HASH.*/)){
		syslog('info',"Channel $event{'Channel'} deleted, because no hash entry found ($channels{$event{'Channel'}}).");
		delete $channels{$event{'Channel'}};
		return;
	}   
	for ($event{'Event'}) {
# Variable read example
#                print STDERR $astman->sendcommand( Action => 'Getvar', Channel => $event{'Channel'}, Variable => 'DNID' );
		$event{'CallerID'} = $1 if defined $event{'CallerID'}  && $event{'CallerID'} =~ /<(\d*)>/;
		/newchannel/i && do {
			my $call_origin = "originate";
			$call_origin = "answer" if $event{'State'} =~ /^Ring$/i;

			my $call_type = "VoIP";
                        $call_type = "Telephony" if $event{'Channel'} =~ /^(Zap)|(VPB)|(phone)|(Modem)|(CAPI)|(mISDN)|(Console)/;
# session-protocol 
# other, cisco, h323, multicast, sipv2, sdp, frf11-trunk, cisco-switched, MarsAnalog, C1000Isdn, aal2-trunk
			my $protocol = 'other';
			$protocol = 'sipv2' if $event{'Channel'} =~ /^SIP/i;
			$protocol = 'h323' if $event{'Channel'} =~ /^h323/i;
			$channels{$event{'Channel'}} = { 
				'CHANNEL' => $event{'Channel'},
				'CALLERID' => $event{'CallerID'},
				'UNIQUEID' => $event{'Uniqueid'},
				'CALL_ORIGIN' => $call_origin,
				'CALL_TYPE' => $call_type,
				'CALL_PROTOCOL' => $protocol,
				'CALL_ID' => $event{'Uniqueid'},
				'NAS_IP_Address' => $nas_ip,
				'RADIUS_Server' => $rad_serv,
				'RADIUS_Acct_Port' => $rad_port,
				'RADIUS_Secret' => $rad_sec 
			};
			$channels{$event{'Channel'}}{'CHANNEL'} = $1 if $channels{$event{'Channel'}}{'CHANNEL'} =~ /^AsyncGoto\/(.*)$/;
			$channels{$event{'Channel'}}{'CALL_START'} = time() unless defined $channels{$event{'Channel'}}{'CALL_START'};
			
			if ( (defined $event{'CallerID'})&&(!defined $channels{$event{'Channel'}}{'CALLERID'}) )
			{
				$channels{$event{'Channel'}}{'CALLERID'} = $event{'CallerID'};
			}
		};



		/^link$/i && do {
			return unless $channels{$event{'Channel1'}};
			return unless $channels{$event{'Channel2'}};
			if (ref($channels{$event{'Channel1'}}) =~ /HASH.*/){
				$channels{$event{'Channel1'}}{'DSTCHANNEL'} = $event{'Channel2'} unless defined  $channels{$event{'Channel1'}}{'DSTCHANNEL'};
				$channels{$event{'Channel1'}}{'LINK_START'} = time() unless defined $channels{$event{'Channel1'}}{'LINK_START'};
				$channels{$event{'Channel1'}}{'CALL_ID'} = $event{'Uniqueid1'} unless defined $channels{$event{'Channel1'}}{'CALL_ID'};
			}else {
				syslog('debug',"Bad hash element ".$channels{$event{'Channel1'}});
			}
			if (ref($channels{$event{'Channel2'}}) =~ /HASH.*/){
				$channels{$event{'Channel2'}}{'DSTCHANNEL'} = $event{'Channel1'} unless defined  $channels{$event{'Channel2'}}{'DSTCHANNEL'};;
				$channels{$event{'Channel2'}}{'LINK_START'} = time() unless defined $channels{$event{'Channel2'}}{'LINK_START'};
				$channels{$event{'Channel2'}}{'CALL_ID'} = $event{'Uniqueid1'} unless defined $channels{$event{'Channel2'}}{'CALL_ID'};
			}else { 
                                syslog('debug',"Bad hash element ".$channels{$event{'Channel2'}});
			}
		};

		/^unlink$/i && do {

			return unless $channels{$event{'Channel1'}};
			return unless $channels{$event{'Channel2'}};
			if(ref($channels{$event{'Channel1'}}) =~ /HASH.*/){
				$channels{$event{'Channel1'}}{'LINK_END'} = time();
			} else {
				syslog('debug',"Unlink: no hash entry for $event{'Channel1'}");
			}
			
			if(ref($channels{$event{'Channel2'}}) =~ /HASH.*/){
				$channels{$event{'Channel2'}}{'LINK_END'} = time();
			} else {
				syslog('debug',"Unlink: no hash entry for $event{'Channel2'}");
			}
			
		};

		
		/userevent/i && $event{'UserEvent'} =~ /_sip_auth/i && do {
			$channels{$event{'Channel'}}{'User-Name'} = $event{'User-Name'} if defined $event{'User-Name'};
			$channels{$event{'Channel'}}{'DNID'} = $event{'DNID'} if defined $event{'DNID'};
			$channels{$event{'Channel'}}{'Last_Update'} = time();
			send_acc('Start', %{$channels{$event{'Channel'}}}) if defined $channels{$event{'Channel'}}{'DNID'};
		};

		/hangup/i && do {

			if (defined $channels{$event{'Channel'}}{'DSTCHANNEL'} && 
			    defined $channels{$event{'Channel'}}{'Last_Update'} && 
			    (ref($channels{$channels{$event{'Channel'}}{'DSTCHANNEL'}}) =~ /HASH.*/)){
			 
			  if($channels{$event{'Channel'}}{'DSTCHANNEL'} ne $event{'Channel'}){

				my $chname = $channels{$event{'Channel'}}{'DSTCHANNEL'};
				my %tmpchan = %{$channels{$chname}};
				delete $channels{$chname};
				$channels{$event{'Channel'}}{'DSTCHANNEL'} = $channels{$chname}{'DSTCHANNEL'} if defined $channels{$chname}{'DSTCHANNEL'};
				%{$channels{$chname}}=%{$channels{$event{'Channel'}}};
				delete $channels{$event{'Channel'}};
				%{$channels{$event{'Channel'}}}=%tmpchan;					
				undef %tmpchan;
				undef $chname;
			  }	


			}
			
			my $channel = $event{'Channel'};
			return unless $channels{$channel};
			return unless $channels{$channel}{'RADIUS_Server'};
			$channels{$channel}{'CALL_END'} = time();
			if (defined $channels{$channel}{'LINK_START'}){
				$channels{$channel}{'LINK_END'} = time() unless defined $channels{$channel}{'LINK_END'};
			}else{
				$channels{$channel}{'LINK_START'} = 0;
				$channels{$channel}{'LINK_END'} = 0;
			}
			$channels{$channel}{'CAUSE'} = 16;
			$channels{$channel}{'CAUSE'} = $event{'Cause'} if defined $event{'Cause'};
			send_acc('Stop', %{$channels{$channel}}) if defined $channels{$channel}{'Last_Update'};
			delete $channels{$channel};
		};

		/rename/i && do {

			if(defined $event{'Newname'} && defined $event{'Oldname'})
			{
				delete $channels{$event{'Newname'}} if defined $channels{$event{'Newname'}};
				if (defined $channels{$event{'Oldname'}}){
					%{$channels{$event{'Newname'}}} = %{$channels{$event{'Oldname'}}} if ref($channels{$event{'Oldname'}}) =~ /HASH.*/;
					delete $channels{$event{'Oldname'}};
				}
			}
		};

                /shutdown/i && do {
			die 'ast-rad-acc: Asterisk disconnect';	
                };

                /Reload/i && do {
                        load_config();
                };
	}
}

sub send_update {

	 my $curtime = time();
	 foreach (keys %channels) {	
	 	next unless (ref($channels{$_}) =~ /HASH.*/)&&(defined $channels{$_}{'Last_Update'});
	 	if (($curtime-$channels{$_}{'Last_Update'})>=$update_timeout)
	 	{
	 		$channels{$_}{'Last_Update'} = $curtime;
	 		send_acc('Update',%{$channels{$_}});
	 	}
	}
	alarm 5;
}


sub send_acc {
	my ($acc_type,%cdr) = @_;
my $r = new Authen::Radius(Host => $cdr{'RADIUS_Server'}."\:".$cdr{'RADIUS_Acct_Port'}, Secret => $cdr{'RADIUS_Secret'});
#syslog('notice', $cdr{'RADIUS_Server'}."\:".$cdr{'RADIUS_Acct_Port'}."   ".$cdr{'RADIUS_Secret'});
if( !defined $r ) {
	syslog('crit', "RADIUS host '$cdr{'RADIUS_Server'}' ERROR");
	return;
}

$r->clear_attributes();

my $confid = uc(md5_hex($cdr{'CHANNEL'}));
$confid =~ s/(\w{8})(\w{8})(\w{8})(\w{8})/$1 $2 $3 $4/;
	
if ($acc_type eq 'Start')
{
	$r->add_attributes ({ Name => 'Acct-Status-Type', Value => 'Start' },
        { Name => 'h323-setup-time', Value => format_date($cdr{'CALL_START'}) },
	{ Name => 'h323-call-type', Value => $cdr{'CALL_TYPE'} },
	{ Name => 'h323-call-origin', Value => $cdr{'CALL_ORIGIN'} },
        { Name => 'h323-voice-quality', Value => '0' },
        { Name => 'Cisco-AVPair', Value => "session-protocol=$cdr{'CALL_PROTOCOL'}" },
        { Name => 'Cisco-AVPair', Value => "call-id=$cdr{'CALL_ID'}" }
        );
        
        $r->add_attributes ( { Name => 'h323-remote-address', Value => $cdr{'Remoteip'} } ) if defined $cdr{'Remoteip'};
        $r->add_attributes ( { Name => 'h323-gw-id', Value => $cdr{'DSTCHANNEL'} } ) if defined $cdr{'DSTCHANNEL'};
} else {
if ($acc_type eq 'Stop')
{
	$r->add_attributes (
        { Name => 'Acct-Status-Type', Value => 'Stop' },
	{ Name => 'h323-setup-time', Value => format_date($cdr{'CALL_START'}) },
        { Name => 'h323-connect-time', Value => format_date($cdr{'LINK_START'}) },
        { Name => 'h323-disconnect-time', Value => format_date($cdr{'LINK_END'}) },
        { Name => 'h323-disconnect-cause', Value => $cdr{'CAUSE'} },
        { Name => 'Acct-Session-Time', Value => $cdr{'LINK_END'} - $cdr{'LINK_START'} },
	{ Name => 'Cisco-AVPair', Value => "session-protocol=$cdr{'CALL_PROTOCOL'}" },
        { Name => 'Cisco-AVPair', Value => "call-id=$cdr{'CALL_ID'}" }
        );
        $r->add_attributes ( { Name => 'h323-remote-address', Value => $cdr{'Remoteip'} } ) if defined $cdr{'Remoteip'};
        $r->add_attributes ( { Name => 'h323-gw-id', Value => $cdr{'DSTCHANNEL'} } ) if defined $cdr{'DSTCHANNEL'};
} else {
if ($acc_type eq 'Update')
{
	$r->add_attributes ({ Name => 'Acct-Status-Type', Value => 'Alive' });

} else {
	syslog('err', "Bad ACC_STATUS_TYPE specified");
	return;
}}}

$r->add_attributes (
        { Name => 'NAS-IP-Address', Value => $cdr{'NAS_IP_Address'} },
	{ Name => 'NAS-Port-Name', Value => $cdr{'CHANNEL'} },
        { Name => 'User-Name', Value => $cdr{'User-Name'} },
        { Name => 'Calling-Station-Id', Value => $cdr{'CALLERID'} },
        { Name => 'Called-Station-Id', Value => $cdr{'DNID'} },
        { Name => 'h323-conf-id', Value => $confid }
        
);

$r->send_packet (ACCOUNTING_REQUEST) and my $type = $r->recv_packet;
syslog('crit', "No responce from RADIUS server") if !defined $type;
}

#
# sample '09:16:05 GMT Sat Dec 11 2004'
#
sub format_date {
	my ($date) = @_;
	my $old_locale = setlocale(LC_TIME);
	setlocale(LC_TIME, 'POSIX');
        my $str_date = strftime "%H:%M:%S.000 UTC %a %b %e %Y", gmtime($date);
        setlocale(LC_TIME, $old_locale);
	return $str_date; 
}

# Signal Handlers
#
sub safe_exit {
   my($sig) = @_;
   syslog('crit', "Caught a SIG$sig - shutting down");
   
   $astman->disconnect if $ast_connected;     
   unlink $lock_file or syslog('crit', "Unable to create lockfile $lock_file\n");
   closelog();     
   exit;
}

sub load_config {

	my $glob = 0;
	my $conf;
	open($conf, "<$config_dir/extensions.conf") || die "Can't open config file: $!\n";
	while (<$conf>)
	{
		
		next if ($_ =~ /^\s*;.*/);
		
		
		if ($_ =~ /^\s*\[globals\]\s*/)
		{
			$glob=1;
			next;
		}
		
		if (($glob)&&($_ =~ /^\s*\[.*\]\s*/))
		{
			$glob=0;
			next;
		}
		
		next if (!$glob);
		
		
		$rad_serv = $1 if ($_ =~ /^\s*RADIUS_Server\s*=\s*(.*)/);
		$rad_sec = $1 if ($_ =~ /^\s*RADIUS_Secret\s*=\s*(.*)/);
		$nas_ip = $1 if ($_ =~ /^\s*NAS_IP_Address\s*=\s*(.*)/);
		$rad_port = $1 if ($_ =~ /^\s*RAIUS_Acct_Port\s*=\s*(\d+)/);
		$update_timeout = $1 if ($_ =~ /^\s*Acct_Update_Timeout\s*=\s*(\d+)/);
	}
	close($conf);
	
	if (!defined $rad_serv)
	{
		syslog('crit', "Can't find RADIUS_Server in extensions.conf");
		die "Can't find RADIUS_Server in extensions.conf";
	}
	
	if (!defined $rad_sec)
	{
		syslog('crit', "Can't find RADIUS_Secret in extensions.conf");
		die "Can't find RADIUS_Secret in extensions.conf";
	}
	if (!defined $nas_ip)
	{
		syslog('crit', "Can't find NAS_IP_Address in extensions.conf");
		die "Can't find NAS_IP_Address in extensions.conf";
	}
	
	if (!defined $rad_port)
	{
		syslog('crit', "Can't find RAIUS_Acct_Port in extensions.conf");
		die "Can't find RAIUS_Acct_Port in extensions.conf";
	}
	if ( !defined $update_timeout )
	{
		$update_timeout = 0;
	}
	
	syslog('notice', "extensions.conf loaded");
}
