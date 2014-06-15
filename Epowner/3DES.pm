

package Epowner::Epo;

use Crypt::TripleDES;

use strict;
use warnings;

#============================================================#
# McAfee 3DES encryption                                     #
#============================================================#
sub mcafee_3des_encrypt {

	# McAfee 3DES = XOR8 + 3DES + tags

	my $input = shift;
	my $key_hex = shift;

        # padding to 3DES block size (3DES block len is 8)
        my $padding_len = length($input)%8;
        $input .=  "\x00" x (8 - $padding_len) ;

        # XOR8
        $input = xor8_encode($input, 0x54);

        # Encrypt
        my $des = new Crypt::TripleDES;
        my $data_encrypted = $des->encrypt3 ($input, $key_hex );
        $data_encrypted =
                "\x45\x50\x4f\x00" .                    # tag ?
                "\x02\x00\x00\x00" .                    # tag ?
                pack("V", length($data_encrypted)) .    # len of encrypted data
		$data_encrypted ;


	return $data_encrypted;
}

#============================================================#
# McAfee 3DES decryption                                     #
#============================================================#
sub mcafee_3des_decrypt {

        # McAfee 3DES = XOR8 + 3DES + tags

        my $input = shift;
        my $key_hex = shift;

	# skip tags
	$input = substr($input, 12);
	
	# decrypt
	my $des = new Crypt::TripleDES;
        my $data_decrypted = $des->decrypt3 ($input, $key_hex );

        # XOR8
        $data_decrypted = xor8_decode($data_decrypted, 0x54);

        return $data_decrypted;
}


1;
