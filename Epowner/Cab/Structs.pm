#!/usr/bin/perl -w

package Epowner::Cab::Cab;



sub cheader_init {
	my $this = shift;
	my $nfolders = shift;
	my $nfiles = shift;
	my $flags = shift;
	my $setID = shift;
	my $cabID = shift;

	$this->{'cheader'} =
		"MSCF" .		# sign
		"\x00\x00\x00\x00" .	# res1
		"SIZE" .		# size
		"\x00\x00\x00\x00" .    # res2
		"OFFI"	.		# offsetfile
		"\x00\x00\x00\x00" .    # res3
		"\x03" .		# versionMIN
		"\x01" .		# versionMAJ
		pack("v", $nfolders) .	# nfolders
		pack("v", $nfiles) .	# nfiles
		pack("v", $flags) .	# flags
		pack("v", $setID) .	# setID
		pack("v", $cabID) .	# cabID
		"";
	return 1;
}


sub cheader_size {
        my $this = shift;
        my $size = shift;
	$size = pack("V", $size);
	$this->{'cheader'} =~ s/SIZE/$size/g;
}

sub cheader_offsetfiles {
        my $this = shift;
        my $offset = shift;
        $offset = pack("V", $offset);
        $this->{'cheader'} =~ s/OFFI/$offset/g;
}

sub cfolder_init {

#        dword offsetdata;
#        word ndatab;
#        word typecomp;

	my $this = shift;
	my $ndatab = shift;

	 $this->{'cfolder'} =
		"OFDA" .		# offsetdata
		 pack("v", $ndatab) .	# ndatab	
		 pack("v", 0) .		# typecomp (-> 0 = no compr)
	"";

}
sub cfolder_offsetdata {
        my $this = shift;
        my $offset = shift;
        $offset = pack("V", $offset);
        $this->{'cfolder'} =~ s/OFDA/$offset/g;
}

sub cfile_init {

#struct cfile
#{
#        dword usize;
#        dword uoffset;
#        word index;
#        word date;
#        word time;
#        word fattr;
#        byte name[MAXSIZE];
#};


	my $this = shift;
	my $usize = shift;
	my $index = shift;
	my $filename = shift;

	 $this->{'cfile'} =
		pack("V", $usize) .	# usize
		"UOFF" .		# uoffset
		pack("v", $index) .	# index
		"\x97\x41" .		# date   #97 41  d7 7b 20 00 
		"\xd7\x7b" .		# time 
		"\x20\x00" .		# fattr	TODO 
		$filename .		# filename
		"\x00" .		# nullbyte
	"";

}

sub cfile_uoffset {
        my $this = shift;
        my $offset = shift;
        $offset = pack("V", $offset);
        $this->{'cfile'} =~ s/UOFF/$offset/g;
}


sub cdata_init {

	#struct cdata
	#{
	#        dword checksum;
	#        word ncbytes;
	#        word nubytes;
	#};

	my $this = shift;
	my $checksum = shift || 0;

        $this->{'cdata'} =
                pack("V", $checksum) .  # checksum
		"NC" .			# ncbytes
		"NU";			# nubytes
}

# set number of compressed bytes in datablock
sub cdata_ncbytes {
        my $this = shift;
        my $ncbytes = shift;
        $ncbytes = pack("v", $ncbytes);
        $this->{'cdata'} =~ s/NC/$ncbytes/g;
}

# set number of uncompressed bytes in datablock
sub cdata_nubytes {
        my $this = shift;
        my $nubytes = shift;
        $nubytes = pack("v", $nubytes);
        $this->{'cdata'} =~ s/NU/$nubytes/g;
}

1;
