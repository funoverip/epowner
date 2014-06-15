package Epowner::Epo;

use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha256);
use MIME::Base64;

use strict;
use warnings;




sub rsa_hash256_pub_key_from_file {
        my $this = shift;
        my $filename = shift;

        if(not -e $filename){
                print "[-] ERROR (rsa_hash_pub_key_from_file): file '$filename' not found\n";
                exit;
        }

        my $key_string;
        open(FILE,$filename) || die "$filename: $!";
        read(FILE,$key_string,-s FILE);
        close(FILE);

        my $hash = encode_base64(sha256($key_string), "");

        # save the hash
        return $hash;

}



1;
