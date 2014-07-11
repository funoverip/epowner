package Epowner::Epo;

use LWP;
use HTML::TokeParser::Simple;

use strict;
use warnings;

# git-issue-1
IO::Socket::SSL::set_ctx_defaults(SSL_verify_mode => SSL_VERIFY_NONE);
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;


sub tomcat_login {
	my $this = shift;
	my $username = shift;
	my $password = shift;



	# init browser
	$this->{browser} = LWP::UserAgent->new (ssl_opts => { verify_hostname => 0, SSL_verify_mode => SSL_VERIFY_NONE });
	my $ua = $this->{browser};
	$ua->cookie_jar( {} );

 
	# Create a request and get cookie
	#=================================
  	my $req = HTTP::Request->new(GET => "https://$this->{server_host}:$this->{server_consoleport}/core/orionSplashScreen.do");
  	print "      [+] GET  /core/orionSplashScreen.do : " if $this->{verbose};
	my $res = $ua->request($req);
  	if ( ! $res->is_success) {
		print "Request failed with code " . $res->code . "..\n" if $this->{verbose};
		return 0;
	}
	print "OK\n" if $this->{verbose};



	# Do Login
	#===================
	$req = HTTP::Request->new(POST => "https://$this->{server_host}:$this->{server_consoleport}/core/j_security_check");	
	$req->content_type('application/x-www-form-urlencoded');
	$req->content("j_username=$username&j_password=$password");
  	print "      [+] POST /core/j_security_check : " if $this->{verbose};
	$res = $ua->request($req);
	if($res->code eq 302){
		print "OK\n" if $this->{verbose};
	}else{
		print "Authentication failure ..\n" if $this->{verbose};
		return 0;
	}

	
	# Go back to SplashScreen.do and get SSO cookie  + Security Token
	#================================================================
        $req = HTTP::Request->new(GET => "https://$this->{server_host}:$this->{server_consoleport}/core/orionSplashScreen.do");
        print "      [+] GET  /core/orionSplashScreen.do : " if $this->{verbose};
	$res = $ua->request($req);
        if ( ! $res->is_success) {
                print "Request failed with code " . $res->code . "..\n" if $this->{verbose};;
                return 0;
        }
        print "OK\n" if $this->{verbose};

	# Parse HTML , extract token
	my $content = $res->content;
	my $parser = HTML::TokeParser::Simple->new(\$content);
	
	while ( my $tag = $parser->get_tag('input') ) {
 		 my $name = $tag->get_attr('name');
  		next unless defined $name and $name eq 'orion.user.security.token';
  		$this->{security_token} = $tag->get_attr('value');
	}
	if($this->{security_token} eq ''){
		print "      [-] Could not get Tomcat security token from HTML response ..\n" if $this->{verbose};;
		return 0;
	}

	print "      [+] Logged in !\n" if $this->{verbose}; 


	return 1;
}




1;
