package Epowner::Epo;

use strict;
use warnings;

#=================================
# Config SAVE
#=================================

sub config_save {
        my $this = shift;

        my $file        = $this->{config_file};
        my $dsa_agent   = $this->{dsa_agent};
        my $agent_dsa_filename_private = $this->{config_file} . "_" . $this->{agent_dsa_filename_private};

        print "[*] Saving Agent and Server configuration\n" if $this->{verbose};
        print "      [+] Agent/Server configuration saved to '$file' !\n" if $this->{verbose};

        # Save DSA key
        $dsa_agent->write_priv_key($agent_dsa_filename_private);
        print "      [+] Agent PRIVATE dsa key saved to '$agent_dsa_filename_private' !\n" if $this->{verbose};

	$this->config_save_writefile();

}


sub config_save_seqnum_only {
        # Change of last minute. Only to avoid console output
	my $this = shift;
        $this->config_save_writefile();
}



sub config_save_writefile {

	my $this = shift;

	my $file 	= $this->{config_file};
	my $dsa_agent 	= $this->{dsa_agent};
	my $agent_dsa_filename_private = $this->{config_file} . "_" . $this->{agent_dsa_filename_private};

        # Create config file
        open (CONFIG, ">$file") or die "[-] ERROR config_save: Can't open configuration file '$file'. $!\n";
        print CONFIG << "EOF";
#---------------------------------------------#
#    ePowner - Agent & Server configuration   #
#---------------------------------------------#

# Server settings
\$this->{server_host}               = "$this->{server_host}";
\$this->{server_port}               = "$this->{server_port}";
\$this->{server_pubkeyhash}         = "$this->{server_pubkeyhash}";
\$this->{server_is_dba}             = $this->{server_is_dba};
\$this->{srv_exec_mode}             = $this->{srv_exec_mode};
\$this->{srv_exec_priv}             = $this->{srv_exec_priv};
\$this->{server_servername}         = "$this->{server_servername}";
\$this->{server_mssql_whoami}       = '$this->{server_mssql_whoami}';
\$this->{server_db_folder}          = '$this->{server_db_folder}';
\$this->{server_install_folder}     = '$this->{server_install_folder}';
\$this->{server_tomcat_folder}      = '$this->{server_tomcat_folder}';
\$this->{server_apache_folder}      = '$this->{server_apache_folder}';

# Web Console admin account
\$this->{admin_username}            = "$this->{admin_username}";
\$this->{admin_password}            = "$this->{admin_password}";

# Attacker agent settings
\$this->{agent_hostname}            = "$this->{agent_hostname}";
\$this->{agent_ip}                  = "$this->{agent_ip}";
\$this->{agent_mac}                 = "$this->{agent_mac}";
\$this->{agent_guid}                = "$this->{agent_guid}";
\$this->{agent_seqnum}              = $this->{agent_seqnum};

# AES-128 Key (extracted from orion.keystore)
\$this->{aes_symkey_keystore}       = "$this->{aes_symkey_keystore}";

# Various strings generated during --register
\$this->{common_prefix}             = "$this->{common_prefix}";
\$this->{deploy_evil_product_id}    = "$this->{deploy_evil_product_id}";


# States 

\$this->{state_registered}          = $this->{state_registered};

# --srv-exec --setup-nondba already ran ?
\$this->{state_exec_nondba_setup}   = $this->{state_exec_nondba_setup};

# --add-admin already ran ?
\$this->{state_add_admin}           = $this->{state_add_admin};

# --cli-deploy used ?
\$this->{state_cli_deploy}          = $this->{state_cli_deploy};

# End of file
EOF
        close CONFIG;

}





#=================================
# Config RESTORE
#=================================
sub config_restore {

        my $this = shift;

        my $file 		= $this->{config_file};
        my $dsa_agent   	= $this->{dsa_agent};
        my $agent_dsa_filename_private = $this->{config_file} . "_" . $this->{agent_dsa_filename_private};


        open (CONFIG, "$file") or die "[-] ERROR: Can't open configuration file '$file'. $!\n" .
                                                   "    Use '--register' parameter to register a new agent to the ePo server and then create\n" .
                                                   "    a new configuration file, or specify an alternate filename using '--config <filename>'\n";
        my $config = join "", <CONFIG>;
        close CONFIG;
        eval $config;
        die "Couldn't interpret the configuration file ($file) that was given.\nError details follow: $@\n" if $@;

        print "[*] Restoring Agent and Server configuration from '$file'\n" if $this->{verbose};

        # Load DSA priv key
        $this->{dsa_agent} = Crypt::OpenSSL::DSA->read_priv_key( $agent_dsa_filename_private );
        print "      [+] Agent PRIVATE dsa key loaded from '$agent_dsa_filename_private' !\n" if $this->{verbose};

	# increment our seq num to be sure we use a value >= than the value expected by epo
	# if the code fails somewhere without saving the current seq number, our next requests
	# will be ignored by the ePo server (HTTP code 503 - Server Busy)
	#$this->{agent_seqnum}+=20;

}




1;
