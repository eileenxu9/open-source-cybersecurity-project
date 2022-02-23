#!/usr/bin/perl -w
  # ##########################################################################
  #
  use Net::PcapUtils;    #packet capture module to allow use of WinPcap or LibPcap
  #
  # ##########################################################################
  sub process_pkt       #Packet processing routine.
  {
     print("Got a packet!\n");
  }
  # ##########################################################################  
  # Main part of program
  # Here we are invoking the NetPcap module and looping through forever.
  Net::PcapUtils::loop(\&process_pkt, 
                       SNAPLEN => 65535,   #Size of data to get from packet
                       PROMISC => 1,);    #Promiscuous means look at ALL packets
