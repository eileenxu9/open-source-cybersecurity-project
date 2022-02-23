#!/usr/bin/perl
# This program allows you to select the interface to use as the listening interface and saves
# the interface name to a settings file to be read in by webcap.pl as an input.  This is very
# handy as the interface names, especially in Windows, can be quite long and have punctutation
# characters in them, making them hard to specify manually.
# I have modified it to save the selected interface to a settings file.
#  use strict; 
  use warnings; 
  use Net::PcapUtils; 
  $, = ' '; 
  $|++;
  $settings = "c:\\webcap\\interface.txt";
  open (SETTINGSFILE,">$settings");
  my ( $error, %description ); 
  my @adapter = Net::Pcap::findalldevs( \$error, \%description ); 
  @adapter > 0 or die "No adapter installed !\n"; 
  my $i = 1; 
  if ( @adapter > 1 ) {  #Change 1 to 0 if you want prompt even if only 1 adapter
    
   print "\nThis utility needs to be run before running webcap for the first time\n";
   print "and then when you change the network adapters in your system or want to\n";
   print "capture from a different adapter.\n\n";
   print "It outputs the selected adapter to a settings file.  Webcap reads\n";
   print "this file at startup.\n\n";
   print "Here are the adapters found:\n\n"; 
   print $i++, " - $description{$_}\n $_\n" foreach @adapter; 
   do { 
     print "\nPlease select the number of the adapter to set as the capture device:"; 
     $i = <STDIN>; 
     chomp $i; 
   } until ( $i =~ /^(\d)+$/ and 0 < $i and $i <= @adapter ); 
  }
  print "\nSet to Listen to $description{$adapter[$i-1]}\n\n";
  print "...which is referenced by the system as:\n\n".$adapter[ $i - 1]."\n";
  print SETTINGSFILE ($adapter[ $i - 1]);
  close SETTINGSFILE;
