package Epowner::Epo;

use Crypt::OpenSSL::DSA;
use Digest::SHA qw(sha1 sha1_hex);

use strict;
use warnings;


#============================================================#
# Create a McAfee DSA  Signature                             #
#============================================================#
sub dsa_sign {
	my $buf = shift;	# to encrypt
	my $dsa_priv = shift;	# dsa object

        my $hash  = sha1($buf);
        my $sig   = $dsa_priv->do_sign($hash) or die "      [-] ERROR: Wrong DSA parameters\n";
        my $sig_r = $sig->get_r();
        my $sig_s = $sig->get_s();

        # Create final signature structure
        my $signature =
                pack("C", (4 + length($sig_r) + length($sig_s))) ."\x00\x00\x00" .      # size of signature struct
                "\x00" . pack("C", length($sig_r) * 8) . $sig_r .                       # r_len + r
                "\x00" . pack("C", length($sig_s) * 8) . $sig_s ;                       # s_len + s

	return $signature;
}


1;
