package Epowner::Epo;

use Term::ANSIColor;

use strict;
use warnings;


sub print_warn {
	my $this = shift;
	my $str = shift;
	if ($this->{use_color})	{ print colored("$str", 'bold magenta'); }
	else 			{ print "$str";  }
}

sub print_err {
	my $this = shift;
        my $str = shift;
        if ($this->{use_color}) { print colored("$str", 'bold red'); }
        else                    { print "$str";  }
}

sub print_ok {
	my $this = shift;
        my $str = shift;
        if ($this->{use_color}) { print colored("$str", 'bold green');}
        else                    { print "$str";  }
}

sub print_info {
	my $this = shift;
        my $str = shift;
        if ($this->{use_color}) { print colored("$str", 'bold blue');}
        else                    { print "$str";  }
}


sub print_info_l1 {
        my $this = shift;
        my $str = shift;
        if ($this->{use_color}) { print colored("$str", 'cyan');}
        else                    { print "$str";  }
}

sub print_info_l2 {
        my $this = shift;
        my $str = shift;
        if ($this->{use_color}) { print colored("$str", 'magenta');}
        else                    { print "$str";  }
}


sub print_data {
	my $this = shift;
        my $str = shift;
        if ($this->{use_color}) { print colored("$str", 'cyan');}
        else                    { print "$str";  }
}


sub print_red {
        my $str = shift || '';
        print colored("$str", 'red');
}

sub print_cyan {
	my $str = shift || '';
	print colored("$str", 'cyan');
}

sub print_blue {
        my $str = shift || '';
        print colored("$str", 'blue');

}
1;
