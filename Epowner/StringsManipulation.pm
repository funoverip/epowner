package Epowner::Epo;

use strict;
use warnings;


#=================================
# Generate_guid function
#=================================
sub generate_guid {

        my @chars=('0'..'9', 'A'..'F');
        my $guid;
        # Sample: {82222222-83F7-48EB-83D4-5DAC1DBF8B19}
        foreach (1..8)  { $guid.=$chars[rand @chars]; } $guid .= "-";
        foreach (1..4)  { $guid.=$chars[rand @chars]; } $guid .= "-";
        foreach (1..4)  { $guid.=$chars[rand @chars]; } $guid .= "-";
        foreach (1..4)  { $guid.=$chars[rand @chars]; } $guid .= "-";
        foreach (1..12) { $guid.=$chars[rand @chars]; }
        $guid = "{" . $guid . "}";
        return $guid;
}



#=================================
# XOR string
# param1 : str
# param2 : xor key(one byte)
#=================================
sub xor_str{
        my $buf = shift;
        my $key = shift;
        my $out;
        for(my $i=0;$i<length($buf); $i++){
                $out .= chr(unpack("C",substr($buf,$i,1)) ^ $key) ;
        }
        return $out;
}




#=================================
# XOR8 string
# param1 : str
# param2 : xor initial key
#=================================
sub xor8_encode {
        my $buf         = shift;
        my $initkey     = shift;
        my $out;
        my $key = $initkey;
        for(my $i=0;$i<length($buf); $i++){
                my $byte = unpack("C",substr($buf,$i,1)) ^ $key ;
                $out .= chr($byte);
                if(($i+1)%8 eq 0){      $key = $initkey; }
                else{                   $key = $byte;    }
        }
        return $out;
}

#=================================
# XOR8 string
# param1 : str
# param2 : xor initial key
#=================================
sub xor8_decode {
        my $buf         = shift;
        my $initkey     = shift;

        my $out='';
	my $byte = 0;
        my $key = $initkey;

        for(my $i=0;$i<length($buf); $i++){
                if($i%8 eq 0){      $key = $initkey; }
                else{               $key = $byte;    }
		$byte = unpack("C",substr($buf,$i,1)) ;
		$out .= chr($byte ^ $key);
        }
        return $out;
}


#=================================
# Generate random string
#=================================
sub random_string {
        my $length_of_randomstring=shift;
        my @chars=('a'..'z','A'..'Z','0'..'9','_');
        my $random_string;
        foreach (1..$length_of_randomstring){  $random_string.=$chars[rand @chars]; }
        return $random_string;
}

#=========================================
# Generate random string (upper case only)
#=========================================
sub random_string_upper {
        my $length_of_randomstring=shift;
        my @chars=('A'..'Z');
        my $random_string;
        foreach (1..$length_of_randomstring){  $random_string.=$chars[rand @chars]; }
        return $random_string;
}


#=========================================
# Generate random string (lower alphanum only)
#=========================================
sub random_string_alphanum_lower {
        my $length_of_randomstring=shift;
        my @chars=('a'..'z', '0'..'9');
        my $random_string;
        foreach (1..$length_of_randomstring){  $random_string.=$chars[rand @chars]; }
        return $random_string;
}
1;
