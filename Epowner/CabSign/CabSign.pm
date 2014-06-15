#!/usr/bin/perl -w
package Epowner::CabSign::CabSign;

#
# Cabinet file signature ePolicy Orchestrator ONLY
# 

use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::DSA;
use Digest::SHA qw(sha1 sha256);
use MIME::Base64;

sub new{
        my $this = {};

        my ($class) = @_; # get the parameters

	$this->{'dsa_priv'} ='';		# Perl DSA Object
	$this->{'dsa_pub'} ='';		# key in string format
	$this->{'rsa_priv'} ='';		# Perl RSA Object
	$this->{'rsa_pub_hash'} ='';	# string

	$this->{'mcafee_tag'} = "McAfee ePolicy Orchestrator\x00";

	$this->{'cab_content'} = '';
	$this->{'cab_content_signed'} = '';

	bless $this, $class;
	return $this
}

sub read_cabfile {

        my $this = shift;
        my $filename = shift;

        if(not -e $filename){
                print "[-] ERROR (read_cabfile): file '$filename' not found\n";
                exit;
        }

	# Read Cabfile
	my $cab_content;
	open(FILE,$filename) || die "$filename: $!";
	read(FILE,$cab_content,-s FILE); # Suck in the whole file
	close(FILE);
	
	$this->{'cab_content'} = $cab_content;

}

sub write_cabfile_signed{
        my $this = shift;
        my $filename = shift;

        # Write Cabfile
        open(FILE,">$filename") || die "[-] ERROR (write_cabfile_signed): $filename: $!";
        print FILE $this->{'cab_content_signed'};
	close(FILE);
}

sub sign_cab {

	my $this = shift;

	my $cab_content = $this->{'cab_content'};

	# Add tags
	$cab_content =
	        $cab_content .
        	"\x2C\x00\x00\x00" .
	        $this->{'mcafee_tag'} .
	        "\x00" x 8 .
	        "TFU\x00" .
	        "\x9c\x01\x00\x00" .
	        $this->{'dsa_pub'} ;

	# DSA Signature
	#==================
	#print "      [+] Generating DSA Signature\n";
	my $hash_sha1  = sha1($cab_content );

	my $sig   = $this->{'dsa_priv'}->do_sign($hash_sha1) or die "      [-] ERROR: Wrong DSA parameters\n";
	my $sig_r = $sig->get_r();
	my $sig_s = $sig->get_s();

	# Create final DSA signature structure
	my $dsa_signature =
		pack("C", (4 + length($sig_r) + length($sig_s))) ."\x00\x00\x00" .      # size of signature struct
		"\x00" . pack("C", length($sig_r) * 8) . $sig_r .                       # r_len + r
		"\x00" . pack("C", length($sig_s) * 8) . $sig_s ;                       # s_len + s


	# RSA Signature
	#==================
	$this->{'rsa_priv'}->use_sha256_hash();
	my $rsa_signature = $this->{'rsa_priv'}->sign($cab_content);


	# Signed cab file
	#=================
	my $cab_content_signed =
		$cab_content .
		$dsa_signature .		# DSA Signature
		"\x2C\x00\x00\x00" .
		$this->{'rsa_pub_hash'} .	# RSA PUB HASH
		pack("V", length($rsa_signature)) .
		$rsa_signature ;

	$this->{'cab_content_signed'} = $cab_content_signed;
}


sub load_dsa_pub_from_file {
        my $this = shift;
        my $filename = shift;

        if(not -e $filename){
                print "[-] ERROR (load_dsa_pub_from_file): file '$filename' not found\n";
                exit;
        }

        my $buf ='';
        open FILE, "$filename" or die "Couldn't open file: $!";
        while (<FILE>){  $buf .= $_;}
        close FILE;

	$this->{'dsa_pub'} = $buf;

}


sub load_dsa_priv_from_file {
	my $this = shift;
	my $filename = shift;

        if(not -e $filename){
                print "[-] ERROR (load_dsa_priv_from_file): file '$filename' not found\n";
                exit;
        }

	my $buf ='';
	open FILE, "$filename" or die "Couldn't open file: $!";
	while (<FILE>){  $buf .= $_;}
	close FILE;


	my @dsa_array = split(//,$buf);
	my ($dsa_p, $dsa_q, $dsa_g, $dsa_pub, $dsa_priv);
	# Extract p, q, g, priv and pub
	for(my $i=2;$i<130; $i++){   $dsa_p    .= $dsa_array[$i] }
	for(my $i=132;$i<152; $i++){ $dsa_q    .= $dsa_array[$i] }
	for(my $i=154;$i<282; $i++){ $dsa_g    .= $dsa_array[$i] }
	for(my $i=284;$i<412; $i++){ $dsa_pub  .= $dsa_array[$i] }
	for(my $i=415;$i<435; $i++){ $dsa_priv .= $dsa_array[$i] }
	# Create and set up DSA object 
	$this->{'dsa_priv'} = Crypt::OpenSSL::DSA->new();;
	my $dsa_srv_priv = $this->{'dsa_priv'};
	$dsa_srv_priv->set_pub_key($dsa_pub);
	$dsa_srv_priv->set_priv_key($dsa_priv);
	$dsa_srv_priv->set_p($dsa_p);
	$dsa_srv_priv->set_q($dsa_q);
	$dsa_srv_priv->set_g($dsa_g);
	
}

sub load_rsa_priv_from_file {
        my $this = shift;
        my $filename = shift;

        if(not -e $filename){
                print "[-] ERROR (load_rsa_priv_from_file): file '$filename' not found\n";
                exit;
        }

	my $key_string;
	open(FILE,$filename) || die "$filename: $!";
	read(FILE,$key_string,-s FILE); 
	close(FILE);

        $this->{'rsa_priv'} = Crypt::OpenSSL::RSA->new_private_key($key_string);;
}

sub load_rsa_pub_from_file {
        my $this = shift;
        my $filename = shift;
	
        if(not -e $filename){
                print "[-] ERROR (load_rsa_pub_from_file): file '$filename' not found\n";
                exit;
        }

        my $key_string;
        open(FILE,$filename) || die "$filename: $!";
        read(FILE,$key_string,-s FILE); 
        close(FILE);

	my $hash = encode_base64(sha256($key_string), "");

	# save the hash
        $this->{'rsa_pub_hash'} = $hash;

}





1;
