package Epowner::Epo;

use LWP;
use HTTP::Request::Common qw(POST);

use strict;
use warnings;


sub tomcat_update_response_rule {

	# tomcat_login must be used first !
	my $this = shift;
	my $filter= shift ; # "epowner";

	# User qgent already initialised by tomcat_login(). Both functions share the same UA for cookie jar
	my $ua = $this->{browser};


        # Init table
        my $req = HTTP::Request->new(GET => "https://$this->{server_host}:$this->{server_consoleport}//core/orionTab.do?sectionId=orion.automation&tabId=response.tab.rules");
        print "      [+] GET  /core/orionTab.do?sectionId=orion.automation&tabId=response.tab.rules : " if $this->{verbose};
	my $res = $ua->request($req);
        if ( ! $res->is_success) {
                print "Request failed with code " . $res->code . "..\n" if $this->{verbose};
                return 0;
        }
        print "OK\n" if $this->{verbose};


	# search our response  rule
	$req = HTTP::Request->new(GET => "https://$this->{server_host}:$this->{server_consoleport}/core/loadTableData.do?datasourceAttr=response.ruleDatasource&filter=ALL_EVENTS&secondaryFilter=&tableCellRendererAttr=response.ruleCellRenderer&count=35&sortProperty=name&quickSearch=$filter&id=ruleTable");
	print "      [+] GET  /core/loadTableData.do : " if $this->{verbose};
	$res = $ua->request($req);
        if ( ! $res->is_success) {
                print "Request failed with code " . $res->code . "..\n" if $this->{verbose};
                return 0;
        }
	print "OK\n" if $this->{verbose};


	# extracte rule uid
	my $uid = $res->content;
	$uid =~ s/^.*"uid" : "([0-9]+)",.*$/$1/;
	if ($uid !~ /^[0-9]+$/){
		print "      [-] Failed to find UID of our response rule ... \n" if $this->{verbose};
		return 0;
	}


        # Call Edit form
        #===================
	$req = POST "https://$this->{server_host}:$this->{server_consoleport}/response/editRule.do",,
    		Content_Type => 'form-data',
    		Content => [ 	"orion.user.security.token" => $this->{security_token},  
				"UIDs" => $uid];
        print "      [+] POST /response/editRule.do : " if $this->{verbose};
        $res = $ua->request($req);
        if($res->code eq 302){
                print "OK\n" if $this->{verbose};
        }else{
                print "failure ..\n" if $this->{verbose};;
                return 0;
        }


        # display rule
        $req = HTTP::Request->new(GET => "https://$this->{server_host}:$this->{server_consoleport}/response/displayRuleDescription.do");
        print "      [+] GET  /response/displayRuleDescription.do : " if $this->{verbose};
        $res = $ua->request($req);
        if ( ! $res->is_success) {
                print "Request failed with code " . $res->code . "..\n" if $this->{verbose};;
                return 0;
        }
        print "OK\n" if $this->{verbose};



	# /core/orionTableUpdateState.do
        $req = HTTP::Request->new(POST => "https://$this->{server_host}:$this->{server_consoleport}/core/orionTableUpdateState.do");
        $req->content_type('application/x-www-form-urlencoded');
        $req->content("orion.user.security.token=$this->{security_token}&dataSourceAttr=response.ruleDatasource&tableId=ruleTable&columnWidths=680%2C203%2C274%2C365%2C477&sortColumn=name&sortOrder=0&showFilters=true&currentIndex=0&ajaxMode=standard");
        print "      [+] POST /core/orionTableUpdateState.do : " if $this->{verbose};
        $res = $ua->request($req);
        if($res->code eq 200){
                print "OK\n" if $this->{verbose};
        }else{
                print "Request failure ..\n" if $this->{verbose};;
		return 0;
        }


        # /response/updateRuleDescription.do
        $req = HTTP::Request->new(POST => "https://$this->{server_host}:$this->{server_consoleport}/response/updateRuleDescription.do");
        $req->content_type('application/x-www-form-urlencoded');
        $req->content("orion.user.security.token=$this->{security_token}&wizardCurrentPage=description&name=" . $this->{common_prefix} . "&description=&language=en&enabled=true&orion.wizard.step=final");
	print "      [+] POST /response/updateRuleDescription.do : " if $this->{verbose};
        $res = $ua->request($req);
        if($res->code eq 302){
                print "OK\n" if $this->{verbose};
        }else{
                print "Request failure ..\n" if $this->{verbose};
                return 0;
        }


	# save rule
        $req = HTTP::Request->new(GET => "https://$this->{server_host}:$this->{server_consoleport}/response/response/saveRule.do?orion.user.security.token=$this->{security_token}");
        print "      [+] GET  /response/response/saveRule.do : " if $this->{verbose};
        $res = $ua->request($req);
        if ($res->code ne 302 and $res->code ne 200 ) {
                print "Request failed with code " . $res->code . "..\n" if $this->{verbose};
                return 0;
        }
        print "OK\n" if $this->{verbose};


	return 1;

}



1;
