package Epowner::Epo;

use Text::SimpleTable;

use strict;
use warnings;



sub mode_sql_banner{
	my $this = shift;
	$this->print_info_l1("[*] Call to ModeSQL\n");
}



#====================================================================
# MANUAL SQL QUERY - WITHOUT OUTPUT (ex: insert, update, delete,..)
#====================================================================
sub mode_sql_query_without_results{

        my $this = shift;
        my $query = shift;  # SQL statement

        # banner mode
        $this->mode_sql_banner();
        $this->print_info_l2("    Parameters: ");
        print "SQL query: $query\n";

        # get query results
        my $sqli = $this->sql_prepare_non_select($query);
        $this->sql_execute($sqli);

	$this->print_ok ("[*] Done\n");

        return 1;
}



#====================================================================
# MANUAL SQL QUERY - WITH OUTPUT (ex: select statements)
#====================================================================
sub mode_sql_query_with_results{

	my $this = shift;
	my $query = shift;  # SQL statement

	# banner mode
        $this->mode_sql_banner();
        $this->print_info_l2("    Parameters: ");
        print "SQL query: $query\n";

	# get query results
	my $sqli = $this->sql_prepare_select($query);
	my @results = $this->sql_execute($sqli);
 
        if(@results ne 0){
		# draw result
                $this->print_ok ("[*] Got data !\n");
                my $t = Text::SimpleTable->new( [100, 'Result'] );
                foreach my $res (@results){     
                        $t->row($res || "N/A");
                }
                $this->print_data ($t->draw());
        }else{
                $this->print_err ("[-] No data were found..\n");
        }
 
        return 1;
}

1;
