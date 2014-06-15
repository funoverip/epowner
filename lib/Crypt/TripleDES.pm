#!/usr/bin/perl 
##
## Crypt::TripleDES -- Pure Perl Triple DES encryption.
##
## Copyright (c) 1999, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: TripleDES.pm,v 0.24 1999/10/13 23:26:15 root Exp root $

package Crypt::TripleDES; 
use Crypt::PPDES; 
use vars qw( $AUTOLOAD $VERSION); 
( $VERSION )  = '$Revision: 0.24 $' =~ /\s(\d+\.\d+)\s/; 

sub AUTOLOAD { 
    my ( $self, @args ) = @_; 
    my $key = $AUTOLOAD;  $key =~ s/.*://;
    if ( $key eq "encrypt3" ) { 
        return $self->decrypt3 ( @args, 1 ); 
    } 
}

sub new { return bless {}, shift } 

sub decrypt3 { 

    my ( $self, $plaintext, $passphrase, $flag ) = @_; 
    my %keyvecs;
    $passphrase .= ' ' x (16*3); 

    for ( 0..2 ) {  
        my @kvs = Crypt::PPDES::des_set_key( pack( "H*", substr($passphrase, 16*$_, 16 )));
        $keyvecs{$_} = \@kvs;
    }

    my $size = length ( $plaintext );
    my $tail = 8 - ( $size % 8 ); $tail = 0 if $tail > 7;
       $plaintext .= chr(32) x $tail; 
       $size = length ( $plaintext );
    my $cyphertext = "";

    for ( 0 .. (($size)/8) -1 ) { 
     my $pt = substr( $plaintext, $_*8, 8 );
        $pt = Crypt::PPDES::des_ecb_encrypt( $flag ? $keyvecs{0} : $keyvecs{2}, $flag, $pt );
        $pt = Crypt::PPDES::des_ecb_encrypt( $keyvecs{1}, (not $flag), $pt );
        $pt = Crypt::PPDES::des_ecb_encrypt( $flag ? $keyvecs{2} : $keyvecs{0}, $flag, $pt );
        $cyphertext .= $pt; 
    } 

    return substr ( $cyphertext, 0, $size );

}

sub debug { 
    my ( @mess ) = @_; 
    open D, ">>debug"; 
    print D "@mess\n"; 
    close D; 
}

"True Value";

=head1 NAME

Crypt::TripleDES - Triple DES encyption. 

=head1 SYNOPSIS

 my $des = new Crypt::TripleDES; 
 my $cyphertext = $des->encrypt3 ( $plaintext, $passphrase );
 my $plaintext = $des->decrypt3 ( $cyphertext, $passphrase );

=head1 DESCRIPTION

This module implements 3DES encryption in ECB mode. The code is based on
Eric Young's implementation of DES in pure perl. It's quite slow because of
the way Perl handles bit operations and is not recommended for use with
large texts.

=head1 METHODS 

=over 4

=item B<new>  

The constructor. 

=item B<encrypt3> $plaintext, $passphrase

Encrypts the plaintext string using the passphrase. Whitespace characters
are appended to the string if its length is not a multiple of eight. User
applications can correct for this by storing plaintext size with the
cyphertext. The passphrase is an ASCII character string of upto 48
characters.

=item B<decrypt3> $cyphertext, $passphrase

Inverse of encrypt3(). 

=back 

=head1 AUTHOR

 Vipul Ved Prakash, mail@vipul.net    
 Eric Young, eay@psych.psy.uq.oz.au

 Patches: 
 Jonathan Mayer <jmayer@cobaltnet.com>

=cut


