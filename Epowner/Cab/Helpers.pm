#!/usr/bin/perl -w
package Epowner::Cab::Cab;

sub sizefile{
	my $this = shift;
	my $filename = shift;
	my $fs = -s $filename;
	return $fs;
}

sub number_of_datablocks {
        my $this = shift;
        my $filename = shift;

	my $size = $this->sizefile($filename);

	return int($size / 32768) + 1;
}



1;
