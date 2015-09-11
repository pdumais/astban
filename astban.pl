#!/usr/bin/perl

use Net::Pcap;
use Socket;

# WARNING: configure this
my $to = "pat\@localhost";
my $pbxPort = 5070;
my $device = "eth0";
my $exemptNet = "192.168"; # This will exclude local interface as well.
my $maxfailcount = 10 ; # ban after that number of errors in a row.





my $err;
my %peers = ();
my $filterString = "udp port $pbxPort";

open(my $logFile, '>>', "/var/log/astban.log") or die "Can't open log file";


print "Listening on interface: $device\r\n";

$pid = fork();
if ($pid !=0)
{
    exit 0;
}

print $logFile localtime() . " astban started\r\n";
$logFile->flush();

my $pcap = Net::Pcap::open_live($device, 2048, 0, 0, \$err);
Net::Pcap::compile($pcap, \$filter, $filterString, 1, $net);
Net::Pcap::setfilter($pcap, $filter);

Net::Pcap::loop($pcap, -1, \&packetHandler, 0);




sub packetHandler 
{
    my($userData, $header, $packet) = @_;

    # Note that this is not bulletproof UDP parsing, we don't check fragmentation
    # nor for duplicate sequence numbers. This is just a quick&dirty implementation.
    my $IHL = ord(substr($packet,14,1)) &0x0F;
    my $udpStart = 14+($IHL*4);
    #my $payloadStart = $tcpStart+((((ord(substr($packet,$tcpStart+12,1))&0xF0)>>4)-1)*4);
    my $payloadStart = $udpStart+8;
    my $payload = substr($packet,$payloadStart);

    #@p = map(sprintf("%x",ord),split //,substr($packet,$tcpStart));
    #print "dump: @p\r\n\r\n";


    my $destination  = sprintf("%d.%d.%d.%d",
                               ord(substr($packet, 30, 1)),
                               ord(substr($packet, 31, 1)),
                               ord(substr($packet, 32, 1)),
                               ord(substr($packet, 33, 1)));
    $payload =~ /^SIP\/2.0 ([0-9]*) /;
    $code = $1;
    if ($payload =~ /^call-id:[ *|](.*)[\r|]$/im)
    {
        $callid = $1;
    }
    if ($payload =~ /^cseq:[ *|].* (.*)[\r|]$/im)
    {
        $method = $1;
    }


    if ($code)
    {
        if ($destination !~ /^$exemptNet/)
        {
            if (!exists($peers{$destination}))
            {
                $peers{$destination} = { 'failcount' => 0 , 'banned' => 0};
            }

            #only filter for REGISTER and INVITE since we can get some errors for Notify and OPTIONS. it doesn't count.
            if ($method =~ /REGISTER/i | $method =~ /INVITE/i)
            {
                # if error response code is an error code and sent to a node outside of the network, flag it.
                if ($code >=400)
                {
                    {
                       $peers{$destination}{'failcount'}++;
                    }
                }
                else
                {
                    # reset the counter if we got something good, it means we are a friend
                   $peers{$destination}{'failcount'} = 0;
                }
            }
            print $logFile localtime() . " Match: $code, method: $method, dest: $destination callid: [$callid], fail:". $peers{$destination}{'failcount'} ."\r\n";
   
            if (($peers{$destination}{'failcount'} >= $maxfailcount) && ($peers{$destination}{'banned'} == 0))
            {
                $peers{$destination}{'banned'} = 1;
                print $logFile localtime() . " ERROR: Too many failures for host. Banning\r\n";
                my $iptables = "iptables -A INPUT -s $destination -p udp --destination-port $pbxPort -j DROP";
                system($iptables);    

                open($m, "|/usr/sbin/sendmail -t");
                print $m "To: $to\n";
                print $m "From: root\@localhost\n";
                print $m "Subject: Astban is banning $destination\n\n";
                print $m "That guy was causing nothing but trouble!";
                close($m);
            }
            $logFile->flush();
        }
    }
}
