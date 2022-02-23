#!/usr/bin/perl -w
  # ##########################################################################
  #
  use Net::PcapUtils;    #packet capture module to allow use of WinPcap or LibPcap
  my $settingfile = "c:\\webcap\\interface.txt"; #name of file to read our listening
  open (SETTINGS, $settingfile) or die "Cannot open setting file: $!";
  #
  # ##########################################################################
  sub process_pkt       #Packet processing routine.
  {
     print("Got a packet!\n");
  }
  # ##########################################################################  
  while (<SETTINGS>)    #Read in the input adapter.  It was saved to a file when 
                  #PickInterface.pl was run.
   {
    $interface = $_;
   }
  close SETTINGS;
  # Here we are invoking the NetPcap module and looping through forever.
  Net::PcapUtils::loop(\&process_pkt, 
                       SNAPLEN => 1541,   #Size of data to get from packet
                       PROMISC => 1,      #Promiscuous means look at ALL packets
                       DEV => $interface, );
