#!/usr/bin/perl -w
# ##########################################################################
# Title:         webcap.pl
# Purpose:       Captures all web sites accessed by PCs seen via a SPAN port,
#                hub, or tap to a text-based log.
# Authors:       Eileen Xu, Megha Suresh, Advait Shewade, Arin Shah 
# ##########################################################################
#
use Net::PcapUtils;    #packet capture module to allow use of WinPcap or LibPcap
use Time::HiRes qw(gettimeofday); #Time module to provide time resolution < seconds
my $loopforever = 0;
my $firstrun = 1;     #variable to indicate 1st run through program for init. setup
my $origdate = 0;     #variable to store date to compare for date change
my $sep = ",";        #variable to allow field separator to be easily changed
my $loglocation = "c:\\webcap\\"; #Location to write logs to
my $settingfile = "c:\\webcap\\interface.txt"; #name of file to read our listening
                                               #interface.  run PickInterface.pl to set.
open (SETTINGS, $settingfile) or die "Cannot open setting file: $!";
#
# ##########################################################################
sub get_time          #Time processing.  Mash up DateTime and Time::HiRes to get 
{                     #what we want (sys time + nanoseconds)
 @HiResTime = gettimeofday();   
 ($sec,$min,$hour,$day,$month,$year)=localtime($HiResTime[0]);
 # Month starts with 0 for Jan, so add one.
 $month = $month + 1;
 # Year is offset from 1900, so add 1900 to make it actual.
 $year = $year + 1900;
 my $time = sprintf "%02d/%02d/%4d %02d:%02d:%02d:%06d",                     $month,$day,$year,$hour,$min,$sec,$HiResTime[1];
}
# ##########################################################################
sub process_pkt       #Packet processing routine.
{
 my $time = &get_time;  #Call get_time subroutine to get the current time
 my ($user_data, $header, $packet) = @_;
 my $len = length $packet;
 # Extract Source and Destination IP addresses  
 my $src_1st_octet = hex(unpack('H2',substr($packet,26,1)));
 my $src_2nd_octet = hex(unpack('H2',substr($packet,27,1)));
 my $src_3rd_octet = hex(unpack('H2',substr($packet,28,1)));
 my $src_4th_octet = hex(unpack('H2',substr($packet,29,1)));   
 my $dst_1st_octet = hex(unpack('H2',substr($packet,30,1)));
 my $dst_2nd_octet = hex(unpack('H2',substr($packet,31,1)));
 my $dst_3rd_octet = hex(unpack('H2',substr($packet,32,1)));
 my $dst_4th_octet = hex(unpack('H2',substr($packet,33,1)));
 #Extract the source and destination ports
 my $srcport = hex(unpack('H4',substr($packet,34,2)));
 my $dstport = hex(unpack('H4',substr($packet,36,2)));
 # Extract the http data
 my $httpdata = substr($packet,54,$len-54);
 #Extract the "host", i.e.: www.google.com
 my $startofhost = index($httpdata,"Host:")+6;
 my $endofhostlength = (index($httpdata,"\r\n",$startofhost) - $startofhost);
 my $host = substr($httpdata,$startofhost,$endofhostlength);
 #Extract the URI, which is the resource being requested from the host, example "/"
 my $startofuri = index($httpdata,"GET ")+4;
 my $endofurilength = (index($httpdata,"HTTP/",$startofuri)-4); #skip back past the newline and return characters
 my $uri = substr($httpdata,$startofuri,$endofurilength);
 # This section handles file output.  We want the filename to contain the date and we  
 #want a new file to be created when the date changes.   
  if ($firstrun == 1)      # If 1st run, OPEN logfile and set original date variable
    {
      $formatdate = sprintf "%04d%02d%02d",
                              $year,$month,$day;
      $logdate = $loglocation.$formatdate."_webcap\.txt";
      open (LOGFILE,">>$logdate");
      $origdate = $formatdate;
      $firstrun = 0;
    }
  if ($firstrun == 0)      # If not 1st run, collect curr date & compare to orig date.  
                           #If date changed output to new file     
    {
      my $newdate = sprintf "%04d%02d%02d",$year,$month,$day;
      if ($newdate ne $origdate)
        {
          $logdate = $loglocation.$newdate."_webcap\.txt";
          open (LOGFILE,">>$logdate");
          $origdate = $newdate;
        }
    }
  # We don't want to log access to devices on the Intranet, so check destination IP 
  # range.  We will check for "10" in the first octet, "192.168" in the first two octets,
  # or "172" in the first octet and the range of 16-31 in the second octet.
$nooutput = 0;
$intranet = $dst_1st_octet.$dst_2nd_octet;
if (($intranet eq "192168") || ($dst_1st_octet eq "10"))
   {
      $nooutput = 1;  # Set to 1 to prevent output
   }
if (($dst_1st_octet eq "172") && (($dst_2nd_octet > 15) && ($dst_2nd_octet < 32)))
   {
      $nooutput = 1;
   }      
# Next we will output the packet information we wanted to the logfile.  That info is:
# Date/Time, SRC IP, SRC Prt, DEST IP, DEST Prt, Requested URL (Host + URI).
if ($nooutput == 0) #If = 1 then don't output it, as it's an Intranet access
   {
      print LOGFILE ($time.$sep.$src_1st_octet."\.".$src_2nd_octet."\.".$src_3rd_octet."\.".$src_4th_octet.$sep.$srcport.$sep);
      print LOGFILE ($dst_1st_octet."\.".$dst_2nd_octet."\.".$dst_3rd_octet."\.".$dst_4th_octet.$sep.$dstport.$sep.$host.$uri."\n");
   }
} 
# ##########################################################################  
# Main part of program
my ( $error, %description ); 
my @adapter = Net::Pcap::findalldevs( \$error, \%description ); 
@adapter > 0 or die "No adapter installed !\n";
while (<SETTINGS>)    #Read in the input adapter.  It was saved to a file when 
                      #PickInterface.pl was run.
 {
   $interface = $_;
 }
close SETTINGS;
# Here we are invoking the NetPcap module and looping through forever.
Net::PcapUtils::loop(\&process_pkt, 
                     SNAPLEN => 65536,                   #Size of data to get from packet
                     PROMISC => 1,                      #Promiscuous = ALL packets
                     FILTER => 'tcp[20:4] = 0x47455420', #This is a BPF capture filter.  
                                                        # TCP and "GET"
                     DEV => $interface, );              #This is the int. to capture from
