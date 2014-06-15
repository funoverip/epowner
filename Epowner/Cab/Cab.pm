#!/usr/bin/perl -w
package Epowner::Cab::Cab;

# very simple makecab code. Only support one file in cab

use File::Basename;

use Epowner::Cab::Structs;
use Epowner::Cab::Helpers;


sub new{
        my $this = {};

        my ($class, $lcab_path, $cabextract_path) = @_; # get the parameters

	$this->{'cheader'}	= '';
	$this->{'cfolder'}	= '';
	$this->{'cfile'}	= '';
	$this->{'cdata'}	= '';

	$this->{'cabextract_path'} = $cabextract_path || '';
	$this->{'lcab_path'}       = $lcab_path || '';

	bless $this, $class;
	return $this
}


sub makecab {
        my $this = shift;
        my $filename = shift;	# input file
        my $outfile = shift;	# guess what
        my $remove_path = shift || 0;

        if(not -e $filename){
                print "[-] ERROR (makecab): file '$filename' not found\n";
                exit;
        }

	my $lcab = $this->{lcab_path};
	unlink $outfile; #if any ..

        system("$lcab -n $filename $outfile 2>&1 1>/dev/null");

        if (not -f $outfile){
                print "[-] ERROR (makecab): lcab failure.. ($lcab -n $filename $outfile)\n";
                exit;
        }	

}


sub extractcab {
        my $this = shift;
        my $cabfile_path = shift;
        my $outfile = shift;


	my ($out_name,$out_path) = fileparse($outfile);

	# ePo sometimes use LZX compression :(
	# lets use cab extract...
	my $cabextract = $this->{cabextract_path};
	
	unlink $outfile; #if any ..
	system("$cabextract -q -F catalog.xml -L -d $out_path $cabfile_path 2>/dev/null");

	if (not -f $outfile){
		print "[-] ERROR (extractcab): cabextract failure.. ($cabextract -q -F catalog.xml -L -d $out_path $cabfile_path)\n";
		exit;
	}
	
}




sub extractcab_UNCOMPLETE {
        my $this = shift;
        my $cabfile_path = shift;
        my $outfile = shift;

	# read cab file
        my $cab_content='';
        open (IN, "$cabfile_path") or die "cab in: $!\n";
        read (IN,$cab_content, -s IN);
        close IN;

	
        my $cdata_size                  = 8;    # default length when flags = 0x0000
        # flags
        my $cheader_flags               = unpack ("v",substr($cab_content, 30, 2));
        if($cheader_flags & 0x004)      { $cdata_size+=1; }

        # offsets
        my $first_cfile_offset          = unpack ("V",substr($cab_content,16,4));
	my $first_cfolder_offset        = $first_cfile_offset - 8; # in real situation, this could be wrong
	my $first_cdata_offset          = unpack ("v",substr($cab_content, $first_cfolder_offset   ,4));

        # compression info
        my $compression_type_offset     = $first_cfolder_offset + 6;
        my $compression_type            = unpack ("v",substr($cab_content, $compression_type_offset ,2));

        my $cdata_ncbytes               = unpack ("v",substr($cab_content, $first_cdata_offset + 4 ,2));
        my $cdata_nubytes               = unpack ("v",substr($cab_content, $first_cdata_offset + 6 ,2));


        # CDATA content
        my $cdata_content               = substr($cab_content, $first_cdata_offset + $cdata_size ,$cdata_ncbytes);

	#print "cheader_flags       : $cheader_flags\n";
	print "first_cfile_offset  : $first_cfile_offset\n";
	print "first_cfolder_offset: $first_cfolder_offset\n";
	print "first_cdata_offset  : $first_cdata_offset\n";
	print "compression type    : $compression_type\n";
	print "ncbytes             : $cdata_ncbytes\n";
	print "nubytes             : $cdata_nubytes\n";


	#----------------------------------------------------------
	# HO ! ePo use LZX compression (not always).
	# No LZX Perl module available and I start to be tired ...
	#----------------------------------------------------------

        #my $buf = $cdata_content;
        #for(my $i=0;$i<length($buf); $i++){
        #        printf "\\x%02x", (unpack("C",substr($buf,$i,1)) );
        #        if ($i ne 0 and ($i+1)%16 eq 0){
        #                print "\n";
        #        }
        #}
        #print "\n";

	



}


sub makecab_WEAK_IMPLEMENTATION {
	my $this = shift;
	my $filename = shift;
	my $outfile = shift;
	my $remove_path = shift || 0;

	if(not -e $filename){
		print "[-] ERROR: file '$filename' not found\n";
		exit;
	}

	my $file = $filename;

	if ($remove_path){
		my  ($name,$path) = fileparse($file);
		$file = $name;
	}

	my $nof = 1;

	# HEADER INIT
	$this->cheader_init(1,$nof,0,1234,0);
	$this->cheader_offsetfiles(0x2C);

	my $nod = $this->number_of_datablocks($filename);

	# HEADER SIZE PART 1
	my $mysize2 = 0x2C + $nof*16;
	$mysize2 += length($file) + 1;
	$mysize2 += $nod*8;

	# FOLDER
        $this->cfolder_init( $nod );
	my $offsetdata = 16 + length($file) + 1;
	$this->cfolder_offsetdata(0x2C + $offsetdata);

	
        # file size
        my $mysize = $this->sizefile($filename);


	# DATABLOCKS	
	$this->cdata_init( 0 );
	# we assume "mysize < DATABLOCKSIZE"
	if ($mysize >= 32768) { print "cab error: mysize >= 32768\n"; exit;}
	$this->cdata_ncbytes( $mysize );
        $this->cdata_nubytes( $mysize );
        $mysize2 += $mysize; 


	# HEADER SIZE PART 2
        $this->cheader_size( $mysize2 );
        $mysize += $this->sizefile($filename);

	# FILES
	$this->cfile_init( $this->sizefile($filename) , 0, $file);
	$this->cfile_uoffset(  0 );

	# WRITE
	open (OUT, ">$outfile") or die "$outfile: $!\n";
	#cheaderwrite
	print OUT $this->{'cheader'};
	print OUT $this->{'cfolder'};
	print OUT $this->{'cfile'};
	print OUT $this->{'cdata'};

	my $cabin='';
	open (IN, "$filename") or die "cab in: $!\n";	
	read (IN,$cabin, -s IN);

	print OUT $cabin;
	close OUT;
	close IN;
}



1;
