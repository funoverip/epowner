package Epowner::Epo;


use IO::Uncompress::Inflate qw(inflate $InflateError) ;
use IO::Compress::Deflate qw(deflate $DeflateError) ;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use Archive::Extract;

use strict;
use warnings;


#============================================================#
# Compress (Deflate)                                         #
#============================================================#
sub compress_deflate {
	my $input = shift;
	my $data_compressed;
	deflate \$input => \$data_compressed or die "[-] ERROR (compress_deflate) :deflate failed: $DeflateError\n";
	#print "input len: " . length($input) . "\noutput len:" . length($data_compressed) . "\n";

	# Add ePo stuffs
        $data_compressed =
                pack("V", length($input)) .                 # len uncompreesed
                pack("V", length($data_compressed) ) .      # len compressed
                $data_compressed ;

	return $data_compressed;
}

#============================================================#
# Uncompress (inflate)                                       #
#============================================================#
sub uncompress_inflate {
	my $input = shift;
	my $output;
	inflate \$input => \$output or die "[-] ERROR (uncompress_inflate) : inflate failed: $InflateError\n";
	return $output;
}


#============================================================#
# Create a ZIp file recursively                              #
#============================================================#
sub compress_zip_tree {
	my $this    = shift;
	my $folder  = shift;
	my $zipfile = shift;

	my $zip = Archive::Zip->new(); 

	# Add a tree
	$zip->addTree($folder);

	# Save the Zip file 
	unless ( $zip->writeToFileNamed($zipfile) == AZ_OK ) { die "[-] ERROR: (compress_zip_tree): can\'t write to '$zipfile'\n"; } 
}


#============================================================#
# Unzip a file                                               #
#============================================================#
sub uncompress_zip {
        my $this    = shift;
	my $zipfile = shift;
        my $dest_folder  = shift;

	my $extractor = Archive::Extract->new( archive => $zipfile );
	$extractor->extract( to => $dest_folder);
}

1;
