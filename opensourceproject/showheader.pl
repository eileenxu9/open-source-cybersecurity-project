#!/usr/bin/perl -w
# #######################################################################
#
use Net::PcapUtils;    #packet cap module to allow use of WinPcap/LibPcap
my $settingfile = "c:\\webcap\\interface.txt"; #name of file with cap dev
open (SETTINGS, $settingfile) or die "Cannot open setting file: $!";
#
# #######################################################################
sub process_pkt       #Packet processing routine 
{
   my ($user_data,$header, $packet) = @_;
   my $minipacket = substr($packet,0,54); 
   print ("\n## raw: ###\n");
   print ($minipacket);
   print ("\n==Byte# / Hex / Dec / Bin==\n");
   for ($i=0;$i<55;$i++)
     {
       $hexval = unpack('H2',substr($packet,$i,1)); 
       $decval = hex(unpack('H2',substr($packet,$i,1)));
       printf ("%03s-%02s-%03s-%08b\n", $i, $hexval, $decval, $decval); 
     }
}
# ######################################################################  
# Main part of program
while (<SETTINGS>)   #Read in the input adapter. PickInterface.pl to set
 {
  $interface = $_;
 }
close SETTINGS;
# Here we are invoking the NetPcap module and looping through forever.
Net::PcapUtils::loop(\&process_pkt, 
                       SNAPLEN => 65536,    #Size of data to get from packet
                       PROMISC => 1,       #Put in promiscuous mode
		       FILTER => 'tcp',    #only pass TCP packets
                       DEV => $interface, );
