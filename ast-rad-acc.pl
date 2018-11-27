#!/usr/bin/perl 
##########################################################################
#                                                                        #
# Perl Script for Radius Accounting                                      #
# Switzernet(c)2011                                                      #
#                                                                        #
##########################################################################
# my modules
use strict;
use warnings;
use Asterisk::Manager;
use Sys::Syslog;
use POSIX;
use Config::IniFiles;
use Authen::Radius;
use DBI;
use Switch;
use threads;
use threads::shared;
##########################################################################
# Setting
my $lock_file = '/var/run/ast-rad-acc.pid';
my $lock_control = '/var/run/ast-control.pid';
my $runas_user = 'root';
my $monitor_dir = '/var/spool/asterisk/monitor';
my $config_dir = '/etc/astrad/config';
##########################################################################
# Globals
my %channels;
my ($ast_hostname,$ast_username,$ast_password);
my ($rad_serv, $rad_sec, $nas_ip);
my ($DB_NAME_Rad,$DB_HOST_Rad,$DB_USER_Rad,$DB_PASS_Rad,$dbh_Rad,$Rad_connected);
my ($CustomerType,$lconf,$astman,$ast_connected,$thr);
my $t_event : shared;
##########################################################################
#                             Initialization                             #
##########################################################################
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
##########################################################################
# set C locale
POSIX::setlocale(LC_ALL, "C");
##########################################################################
# Become daemon
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
	syslog('notice', "Ast-Rad ast-rad-acc: accounting for Asterisk started");
}

##########################################################################
# Install signall handler
$SIG{INT} = \&safe_exit;
$SIG{QUIT} = \&safe_exit;
$SIG{TERM} = \&safe_exit;
$SIG{HUP} = \&load_config;
##########################################################################
# Drop privileges
setuid($uid);
$< = $uid;
$> = $uid;
##########################################################################
# Signal Handlers
sub safe_exit {
    my($sig) = @_;
    syslog('crit', "Ast-Rad: Caught a SIG$sig - shutting down");
    $astman->disconnect if $ast_connected;  
    $dbh_Rad->disconnect if $Rad_connected;    
    unlink $lock_file or syslog('crit', "Ast-Rad: Unable to create lockfile $lock_file\n");
    closelog();     
    exit;
}
##########################################################################
#                                FUNCTION                                #
##########################################################################
# Load config
sub load_config {
    my $conf=Config::IniFiles->new(-file => "$config_dir/switzer.conf");
    return 0 if !defined $conf ;
    $rad_serv     = $conf->val('MASTER_RD','RADIUS_SERVER');
    $rad_sec      = $conf->val('MASTER_RD','RADIUS_SECRET');
    $nas_ip       = $conf->val('GLOBAL','NAS_IP');    
    $DB_NAME_Rad  = $conf->val('ASTER_DB','DB_NAME');
    $DB_HOST_Rad  = $conf->val('ASTER_DB','DB_HOST');
    $DB_USER_Rad  = $conf->val('ASTER_DB','DB_USER');
    $DB_PASS_Rad  = $conf->val('ASTER_DB','DB_PASS');      
    $ast_hostname = $conf->val('Manager','AMI_PERMIT');
    $ast_username = $conf->val('Manager','AMI_USER');
    $ast_password = $conf->val('Manager','AMI_SECRET');
return 1;
}
##########################################################################
# sample '09:16:05 GMT Sat Dec 11 2004'
sub format_date_gmt {
    my ($date) = @_;
    return strftime "%H:%M:%S GMT %a %b %e %Y", gmtime($date);
}

##########################################################################
# sample '2004-12-11 09:16:05'
sub format_date_sql {
    my ($date) = @_;
    
    if ($date eq 0) {
        return "NULL";
    } else {
        return strftime("%Y-%m-%d %H:%M:%S", localtime($date));
    }
}
##########################################################################
# Astrad Rad. DB connect 
sub Rad_connect {
my $cop=0;
$Rad_connected = 1;
while( 1 ) {
    $cop++;
    $dbh_Rad = DBI->connect_cached("DBI:mysql:$DB_NAME_Rad;host=$DB_HOST_Rad", $DB_USER_Rad, $DB_PASS_Rad);
    if( $dbh_Rad ) {
        $Rad_connected = 1;
        $cop=0;
        syslog('info', 'Ast-Rad: Connected to Astrad Rad. DB!');
        return 1;
        } else {
            if ($Rad_connected) {
                syslog('err', 'Ast-Rad: Could not connect to Astrad Rad. DB!');
                $cop=1;
                }
            $Rad_connected = 0;
            syslog('info', "Ast-Rad: Connection to Astrad Rad. DB -> SLEEP $cop");
            $cop++ if $cop;
            return 0 if ($cop>=3);
            }
        sleep 1;
    }
}
##########################################################################
# Insert into the Failed radius packets Table 
sub Failed_radius_packet {
    my (%data) = @_;
    return 0 if (!Rad_connect());
    $data{'CDR(CustomerType)'}="" if (!defined($data{'CDR(CustomerType)'}));    
    my $request="INSERT INTO radius_packets_Failed (
                h323_connect_time, h323_disconnect_time, acct_session_time, h323_disconnect_cause, nas_ip_address, user_name, calling_station_id,
                called_station_id, call_id, h323_setup_time, h323_conf_id, h323_remote_address, call_profile, creation_date, reception_date, last_send, send_counter, status) 
                VALUES 
                ('".format_date_sql($data{'LINK_START'})."','".format_date_sql($data{'LINK_END'})."','$data{'Acct_Session_Time'}',
                '$data{'H323_disconnect_cause'}','$data{'NAS_IP_Address'}','$data{'ACCOUNTCODE'}','$data{'CALLERID'}','$data{'DNID'}','$data{'CALL_ID'}',
                '".format_date_sql($data{'CALL_START'})."','$data{'H323_ID'}','$data{'H323_remote_address'}','$data{'CDR(CustomerType)'}','".format_date_sql($data{'creation_date'})."',
                '".format_date_sql($data{'reception_date'})."','".format_date_sql($data{'last_send'})."','$data{'send_counter'}','$data{'STATUS'}')";        
    my $sth = $dbh_Rad->prepare($request);
    if ($sth->execute()) {
        $sth->finish;
        syslog('info', "Ast-Rad: Request = $request");
        return 1;
        }
return 0;
}
##########################################################################
# thread control
sub AMI_control {
syslog('info', 'Ast-Rad: Thread: Start AMI Control');
my ($l_event,$cop) = (0,0);
while ( 1 ) {
    $l_event = time();
    syslog('info', "Ast-Rad: Thread: Time Events -> Last = $t_event | Now = $l_event");
    if ($l_event - $t_event > 400) {
        syslog('crit', "Ast-Rad: Thread: Asterisk PBX is probably restarted !");
        safe_exit();
        }
    $cop=0 if ($l_event - $t_event < 4);
    $cop++;
    syslog('info', "Ast-Rad: Thread: AMI Control sleep $cop");
    sleep 2;
    }
}
##########################################################################
# AMI connect
sub AMI_connect {
$astman = new Asterisk::Manager;
$astman->user($ast_username);
$astman->secret($ast_password);
$astman->host($ast_hostname);
$t_event = time();
my $cop=0;
$ast_connected = 1;
while( 1 ) {
    $cop++;
    if( $astman->connect ) {
        $ast_connected = 1;
        $cop=0;
        syslog('info', 'Ast-Rad: Connected to Asterisk!');
        $thr = threads->new(\&AMI_control);
        $astman->setcallback('DEFAULT', \&status_callback);
        eval { $astman->eventloop; };
        } 
    else { 
        if ($ast_connected) {
            syslog('err', 'Ast-Rad: Could not connect to Asterisk!');
            $cop=1;
            }
        $ast_connected = 0;
        syslog('info', "Ast-Rad: SLEEP $cop");
        $cop++ if $cop;
        return 0 if ($cop>=3);
        }
    sleep 1;
    }
}
##########################################################################
# 
sub status_callback {
	my (%event) = @_;
	return unless defined(%event);
        $t_event = time();
	foreach (keys %event) {
		syslog('debug', "$_: ". $event{$_} . "\n" );
	}
	syslog('debug', "\n");

	for ($event{'Event'}) {
		$event{'CallerIDNum'} = $1 if defined $event{'CallerIDNum'} && $event{'CallerIDNum'} =~ /(\d*)/;

		/Newchannel/i && do {
			syslog('crit', "Event\n");
			foreach (keys %event) {
				syslog('crit', "$_ => $event{$_}\n");
			}

			$channels{$event{'Channel'}} = { 
				'CALLERID' => $event{'CallerIDNum'},
				'UNIQUEID' => $event{'Uniqueid'},
				'CALL_START' => time(),
				'CALL_ORIGIN' => 'originate',
				'LINK_START' => time(),
				'LINK_END' => time(),
				'CALL_TYPE' => 'VoIP',
				'CALL_PROTOCOL' => 'sipv2',
				'CALL_ID' => $event{'Uniqueid'},
				'RADIUS_Server' => $rad_serv,
				'RADIUS_Secret' => $rad_sec,
				'NAS_IP_Address' => $nas_ip,
				'Remoteip' => $nas_ip
			};

			$channels{$event{'Channel'}}{'Remoteip'} = $1 if ($event{'Channel'} =~ /^SIP\/(\d+\.\d+\.\d+\.\d+)-/i);
		};

		/Newexten/i && do {
			if( defined $event{'Application'} && $event{'Application'} eq 'Set') {
				my ( $_var, $_val ) = split(/=/, $event{'AppData'});
				if($_var eq 'CDR(accountcode)') {
					$channels{$event{'Channel'}}{'ACCOUNTCODE'} = $_val;
				} else {
					$channels{$event{'Channel'}}{$_var} = $_val;
				}

				#if($_var eq 'CDR(CustomerType)') {
                                #        $CustomerType= $_val;
                                #}
			}
			
			if (defined $event{'Extension'} && $event{'Extension'} =~ /^(\d+)$/) {
				$channels{$event{'Channel'}}{'DNID'} = $1;
			}
		};

		/^Link$/i && do {
			my $channel1 = $event{'Channel1'};
			my $channel2 = $event{'Channel2'};
			return unless $channels{$channel1};
			$channels{$channel1}{'LINK_START'} = time();
			$channels{$channel2}{'LINK_START'} = time();

			syslog('info', 'Link without uniqueid') unless $channels{$channel1}{'UNIQUEID'};
			syslog('info', 'Link without channeld') unless $channel1;
			syslog('info', 'Link on undefined channel') unless $channels{$channel1};

			return unless($channel1 && $channels{$channel1} && $channels{$channel1}{'UNIQUEID'});
		};

		/Unlink/i && do {
			my $channel = $event{'Channel1'};
			return unless $channels{$channel};
			$channels{$event{'Channel1'}}{'LINK_END'} = time();
			$channels{$event{'Channel2'}}{'LINK_END'} = time();

			syslog('info', 'UnLink without uniqueid') unless $channels{$channel}{'UNIQUEID'};
			syslog('info', 'UnLink without channeld') unless $channel;
			syslog('info', 'UnLink on undefined channel') unless $channels{$channel};

			return unless($channel && $channels{$channel} && $channels{$channel}{'UNIQUEID'});
		};

		/Hangup/i && do {
			my $channel = $event{'Channel'};
			return unless $channels{$channel};
			$channels{$channel}{'CALL_END'} = time();
			$channels{$channel}{'CAUSE'} = 16;
			$channels{$channel}{'CAUSE'} = $event{'Cause'} if defined $event{'Cause'};
			$channels{$channel}{'CAUSE'} = 0 if !defined $event{'Cause'} || $event{'Cause'} eq "";

			send_acc('Stop',%{$channels{$channel}});
			delete $channels{$channel};
		};

		/Newstate/i && do {
			if( defined $event{'State'} && $event{'State'} eq 'Up') {
				send_acc('Start',%{$channels{$event{'Channel'}}});
			}
		};

		/Dial/i && do {
			my $channel1 = $event{'Source'};
			my $channel2 = $event{'Destination'};
			syslog('crit', "DIAL: $channel1 -> $channel2");

			syslog('crit', "H323 dec: $channels{$channel1}{'H323_ID'}");
#			my ($a,$b,$c,$d) = ($1,$2,$3,$4) if $channels{$channel1}{'H323_ID'} =~ /([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)/;
#			$channels{$channel1}{'H323_ID'}=sprintf("%08X %08X %08X %08X",$a,$b,$c,$d);
			$channels{$channel1}{'H323_ID'}=sprintf("%08X %08X %08X %08X",$1,$2,$3,$4) if $channels{$channel1}{'H323_ID'} =~ /(\d+)-(\d+)-(\d+)-(\d+)/;;
			syslog('crit', "H323 hex: $channels{$channel1}{'H323_ID'}");

			$channels{$channel1}{'VLEG'} = $channel2;
			$channels{$channel1}{'CALL_ORIGIN'} = 'answer';
#			$channels{$channel1}{'CALL_ID'} = $channels{$channel1}{'MYCALLID'} if defined $channels{$channel1}{'MYCALLID'};
			$channels{$channel1}{'CALL_ID'} = $event{'Uniqueid1'} if !defined $channels{$channel1}{'CALL_ID'};
			$channels{$channel1}{'ACCOUNTCODE'} = $channels{$channel1}{'CALLERID'} if !defined $channels{$channel1}{'ACCOUNTCODE'}; 

#			$channels{$channel2}{'CLEG'} = $channel1;
			$channels{$channel2}{'CALL_ID'} = $channels{$channel1}{'CALL_ID'};
			$channels{$channel2}{'ACCOUNTCODE'} = $channels{$channel1}{'ACCOUNTCODE'};
			$channels{$channel2}{'CALLERID'} = $channels{$channel1}{'CALLERID'};
			$channels{$channel2}{'DNID'} = $channels{$channel1}{'VDNID'};
			$channels{$channel2}{'H323_ID'} = $channels{$channel1}{'H323_ID'};
		};

		/Shutdown/i && do {
			syslog('info', "Asterisk Shutdown");
			safe_exit();

		};

		/Reload/i && do {
			syslog('info', "Asterisk Reload");
        		load_config();
		};

	}
}
##########################################################################
# 
sub send_acc {
	my ($acc_type,%cdr) = @_;
	my $cause="null";
	my $remote;
	my $duration=0;
	my $date=0;

        return if $cdr{'H323_ID'} =~ /(\d+)-(\d+)-(\d+)-(\d+)/;;
	
	my $r = new Authen::Radius(Host => $cdr{'RADIUS_Server'}, Secret => $cdr{'RADIUS_Secret'}, Service => 'radius-acct');

	if( !defined $r ) {
		syslog('crit', "RADIUS host $cdr{'RADIUS_Server'} ERROR");
		return;
	}

	$r->clear_attributes();
	#print ("\nSend Acc : Type=$acc_type H323_ID=$cdr{'H323_ID'}\n");
	switch($acc_type) {
		case 'Start' {
			$r->add_attributes (
				{ Name => 'Acct-Status-Type', Value => 'Start' },
				{ Name => 'h323-call-origin', Value => $cdr{'CALL_ORIGIN'} },
			);
		} 
		case 'Stop' {
#			TODO why?
			$cause = $cdr{'CAUSE'}-6;
			$cause = 0 if $cause<0;

			$r->add_attributes (
				{ Name => 'Acct-Status-Type', Value => 'Stop' },
				{ Name => 'h323-call-origin', Value => $cdr{'CALL_ORIGIN'} },
				{ Name => 'h323-connect-time', Value => format_date_gmt($cdr{'LINK_START'}) },
				{ Name => 'h323-disconnect-time', Value => format_date_gmt($cdr{'LINK_END'}) },
				{ Name => 'Acct-Session-Time', Value => $cdr{'LINK_END'} - $cdr{'LINK_START'} },
				{ Name => 'h323-disconnect-cause', Value => $cause }
			);
			$duration=$cdr{'LINK_END'} - $cdr{'LINK_START'};
		} else {
			syslog('crit', "Bad ACC_STATUS_TYPE specified: $acc_type");
			return;
		}
	}

	$r->add_attributes (
		{ Name => 'h323-call-type', Value => $cdr{'CALL_TYPE'} },
		{ Name => 'Cisco-AVPair', Value => "session-protocol=$cdr{'CALL_PROTOCOL'}" },
		{ Name => 'NAS-IP-Address', Value => $cdr{'NAS_IP_Address'} },
		{ Name => 'User-Name', Value => $cdr{'ACCOUNTCODE'} },
		{ Name => 'Calling-Station-Id', Value => $cdr{'CALLERID'} },
		{ Name => 'Called-Station-Id', Value => $cdr{'DNID'} },
		{ Name => 'Cisco-AVPair', Value => "call-id=$cdr{'CALL_ID'}" },
		{ Name => 'h323-setup-time', Value => format_date_gmt($cdr{'CALL_START'}) },
		{ Name => 'Cisco-AVPair', Value => "h323-conf-id=$cdr{'H323_ID'}" }
	);

	if (defined $cdr{'Remoteip'} && $cdr{'Remoteip'} ne $cdr{'NAS_IP_Address'}) {
		$r->add_attributes ( { Name => 'h323-remote-address', Value => $cdr{'Remoteip'} } );
		$remote=$cdr{'Remoteip'};
	} else {
		if ($cdr{'CALL_ORIGIN'} eq "originate") {
			$r->add_attributes ( { Name => 'h323-remote-address', Value => 'sip-ua' } );
			$remote='sip-ua';
		} else {
			$r->add_attributes ( { Name => 'h323-remote-address', Value => $cdr{'NAS_IP_Address'} } );
			$remote=$cdr{'NAS_IP_Address'};
		}
	}
	$date=time;

	if ($acc_type eq 'Start') {
		$r->send_packet (ACCOUNTING_REQUEST);
	} else {
		$r->send_packet (ACCOUNTING_REQUEST) and my $type = $r->recv_packet;
		
		my %data = %cdr;
		$data{'Acct_Session_Time'}=$duration;
        	$data{'H323_disconnect_cause'}=$cause;
        	$data{'H323_remote_address'}=$remote;
		$data{'creation_date'}=$date;
		$data{'last_send'}=time;
		$data{'send_counter'}=1;
		
		if (!defined $type) {
			$data{'reception_date'}=0;
                	$data{'STATUS'}=0;
			syslog('crit', "Ast-Rad: No response from RADIUS server !");
		        Failed_radius_packet(%data);
		} else {
			$data{'reception_date'}=time;
			$data{'STATUS'}=1;
			syslog('crit', "Ast-Rad: Good response from RADIUS server");
		}
	}
}
##########################################################################
#                                 main()                                 #
##########################################################################
# Load Radius dictionary
Authen::Radius->load_dictionary;
$lconf=0;
while ( 1 ) {
    if (!$lconf && !load_config()) {
        syslog('crit', "Ast-Rad: Config file error!");
        next;
        }
    $lconf=1;
    if (!AMI_connect()) {
        syslog('crit', "Ast-Rad: Error in Astrerisk Manager connection");
        $lconf=0;
        sleep 1; 
        }
}
##########################################################################
#                                  END                                   #
##########################################################################
