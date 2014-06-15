package Epowner::Epo;

use Crypt::Rijndael;

use strict;
use warnings;



#============================================================#
# AES-ECB decryption                                         #
#============================================================#
sub aes_ecb_decrypt {
	my $this = shift;
	my $encrypted = shift;
	my $aes_key = shift;

	my $aes = Crypt::Rijndael->new( $aes_key, Crypt::Rijndael::MODE_ECB() );
        my $decrypted = $aes->decrypt($encrypted);
        
	my $last_byte = unpack("C",substr($decrypted,-1)); # take the last byte (contains the padding length)
        my $aes_key_len = length($aes_key);

	if($last_byte < $aes_key_len){
        	# ok, $last_byte contains the padding length
                $decrypted = substr($decrypted, 0, length($decrypted) - $last_byte);
	}

	return $decrypted;
}



1;
