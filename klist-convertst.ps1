param(
    [string]$inputfile,
    [string]$outputfile
)

#Path to DLL's for dumping
$wd = $(get-location).Path

$path = "$wd\Kerberos.NET.dll"
$path2 = "$wd\Microsoft.Extensions.Logging.Abstractions.dll"
$path3 = "$wd\System.Buffers.dll"


$null = [System.Reflection.Assembly]::LoadFrom($path2)
$tmp = [System.Reflection.Assembly]::LoadFrom($path)
$null = [System.Reflection.Assembly]::LoadFrom($path3)

Add-Type -AssemblyName "System.Collections"

#path to text file with ticket
#$p = "c:\users\Administrator\desktop\so.txt"
#$p = "C:\Users\Administrator\Desktop\klist-convertv2\pp05.txt"
$p = $inputfile
#path to the output cache file
$outpath = $outputfile

function convertDatestring($tmpstring){

   $i = $tmpstring.indexof(':')
   $tmptime = $($tmpstring.Substring($i + 2)).split('(')[0]
   $da = get-date -Date $tmptime
   $t = [int][double]($da.ToUniversalTime() - [datetime]'1970-01-01').TotalSeconds
   return $t

}

function Convert-HexStringToBytes {
   [CmdletBinding()]
   param(
       [Parameter(Mandatory = $true)]
       [string] $HexString
   )

   $bytes = [byte[]]::new($HexString.Length / 2)
   for ($i = 0; $i -lt $HexString.Length; $i += 2) {
       $bytes[$i / 2] = [byte]::Parse($HexString.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
   }

   return $bytes
}


enum TicketFlags
   {

    # <summary>
       # Reserved. Indicates the absense of flags.
       # </summary>
       None = -1

       # <summary>
       # Reserved for future extension.
       # </summary>
       Reserved = 1 -shl 31

       # <summary>
       # Tells the ticket-granting service that it can issue a new TGT—based on the
       # presented TGT—with a different network address based on the presented TGT.
       # </summary>
       Forwardable = 1 -shl 30

       # <summary>
       # Indicates either that a TGT has been forwarded or that a ticket was issued from a forwarded TGT.
       # </summary>
       Forwarded = 1 -shl 29

       # <summary>
       # Tells the ticket-granting service that it can issue tickets with a network address that
       # differs from the one in the TGT.
       # </summary>
       Proxiable = 1 -shl 28

       # <summary>
       # Indicates that the network address in the ticket is different from the one in the TGT
       # used to obtain the ticket.
       # </summary>
       Proxy = 1 -shl 27

       # <summary>
       # Indicates the requested ticket may be post-dated for use in future.
       # </summary>
       #[Description("May Post-date")]
       MayPostDate = 1 -shl 26

       # <summary>
       # Indicates the requested ticket is post-dated for use in the future.
       # </summary>
       #[Description("Post-dated")]
       PostDated = 1 -shl 25

       # <summary>
       # This flag indicates that a ticket is invalid, and it must be validated by the KDC before use.
       # Application servers must reject tickets which have this flag set.
       # </summary>
       Invalid = 1 -shl 24

       # <summary>
       # Used in combination with the End Time and Renew Till fields to cause tickets with long life
       # spans to be renewed at the KDC periodically.
       # </summary>
       Renewable = 1 -shl 23

       # <summary>
       # Indicates that a ticket was issued using the authentication service (AS) exchange and
       # not issued based on a TGT.
       # </summary>
       Initial = 1 -shl 22

       # <summary>
       # Indicates that the client was authenticated by the KDC before a ticket was issued.
       # This flag usually indicates the presence of an authenticator in the ticket.
       # It can also flag the presence of credentials taken from a smart card logon.
       # </summary>
       #[Description("Pre-Authenticated")]
       PreAuthenticated = 1 -shl 21

       # <summary>
       # This flag was originally intended to indicate that hardware-supported authentication
       # was used during pre-authentication. This flag is no longer recommended in the Kerberos
       # V5 protocol. KDCs MUST NOT issue a ticket with this flag set. KDCs SHOULD NOT preserve
       # this flag if it is set by another KDC.
       # </summary>
       #[Description("Hardware Authenticated")]
       HardwareAuthentication = 1 -shl 20

       # <summary>
       # Application servers MUST ignore the TRANSITED-POLICY-CHECKED flag.
       # </summary>
       #[Description("Transit Policy-Checked")]
       TransitPolicyChecked = 1 -shl 19

       # <summary>
       # The KDC MUST set the OK-AS-DELEGATE flag if the service account is trusted for delegation.
       # </summary>
       #[Description("Ok as Delegate")]
       OkAsDelegate = 1 -shl 18

       # <summary>
       # Indicates the client supports FAST negotiation.
       # </summary>
      # [Description("Encrypted Pre-Authentication")]
       EncryptedPreAuthentication = 1 -shl 16

       # <summary>
       # Indicates the ticket is anonymous.
       # </summary>
       Anonymous = 1 -shl 15
   }




$fullfile = get-content $p
$totallines = $fullfile.Length
$ticketfilelines = $totallines - 14

$first = Get-Content -TotalCount 14 -path $p

$ticketfile = Get-Content -tail $ticketfilelines -path $p | ForEach-Object { $_.Substring(6) }


$servicename = $($first[0] -split ':')[1].Trim()
$username = $($first[2] -split ':')[1].Trim()
$realm = $($first[3] -split ':')[1].Trim()


$un  = New-Object System.Collections.Generic.List[string]
$un.add($username)


$user = [Kerberos.NET.Entities.PrincipalName]::new([Kerberos.NET.Entities.PrincipalNameType]::NT_PRINCIPAL,$realm,$un)

$servname = New-Object System.Collections.Generic.List[string]
$servname.add($servicename)
$server = [Kerberos.NET.Entities.PrincipalName]::new([Kerberos.NET.Entities.PrincipalNameType]::NT_SRV_INST, $realm,$servname)

#$kerbkeytmp = [byte[]](0x7f,0x77,0x5c,0x86,0xf6,0x6e,0x6a,0x70,0xb2,0xc2,0xc6,0x29,0xe0,0x0d,0xa0,0xa7,0xf0,0xd6,0xb3,0x70,0x93,0xb5,0x44,0x6c,0xd8,0x80,0x77,0x08,0x35,0xbb,0xcc,0x68)
#$kerbkey = [System.ReadOnlyMemory[byte]]::new([byte[]](0x7f,0x77,0x5c,0x86,0xf6,0x6e,0x6a,0x70,0xb2,0xc2,0xc6,0x29,0xe0,0x0d,0xa0,0xa7,0xf0,0xd6,0xb3,0x70,0x93,0xb5,0x44,0x6c,0xd8,0x80,0x77,0x08,0x35,0xbb,0xcc,0x68))

$q = $first[8].IndexOf('-')
$kerbkeytmp = $($first[8].Substring($q  +2)) -replace '[^0-9A-Fa-f]', ''
$kerbkeybytes = Convert-HexStringToBytes -HexString $kerbkeytmp

$kerbkey = [System.ReadOnlyMemory[byte]]::new([byte[]]($kerbkeybytes))

$encryptionType = [Kerberos.NET.Crypto.EncryptionType]::AES256_CTS_HMAC_SHA1_96
#$keyValuePair = new-object [System.Collections.Generic.KeyValuePair[EncryptionType, [System.ReadOnlyMemory[byte]]]

$keyValuePair = [System.Collections.Generic.KeyValuePair[Kerberos.NET.Crypto.EncryptionType, [System.ReadOnlyMemory[byte]]]]::new($encryptionType, $kerbkey)



$starttimetmp = convertDateString($first[9])
$authtimetmp = $starttime
$endtimetmp = convertDateString($first[10])
$renewtimetmp = ConvertDateString($first[11])

$epoch = [datetime]'1970-01-01T00:00:00Z'

$authtime = $epoch.AddSeconds($starttimetmp)
$starttime = $epoch.AddSeconds($starttimetmp)
$endtime = $epoch.AddSeconds($endtimetmp)
$renewtime = $epoch.AddSeconds($renewtimetmp)

$iskey = $false

#$tflags = [ticketflags]::Initial -bor [ticketflags]::Renewable -bor [ticketflags]::Forwardable -bor [ticketflags]::PreAuthenticated
#$tflagsline = $first[6]
#if ($tflagsline -match 'TicketFlags\s+:\s+\((0x[0-9a-fA-F]+)\)') {
#    $tflags = [UInt32]::Parse($matches[1].Substring(2), 'HexNumber')
#}

#($test -split '[`(`)]')[1]
$tflagsline = $first[6]
$tflagshex = ($tflagsline -split '[()]')[1]
$tflags = [Convert]::ToUInt32($tflagshex, 16)
$tflags = [ticketflags]::Forwardable -bor [ticketflags]::Renewable -bor [ticketflags]::PreAuthenticated -bor [ticketflags]::OkAsDelegate

$krbinfo = [Kerberos.NET.Entities.KrbCredInfo]::new()
$krbenckey = [Kerberos.NET.Entities.KrbEncryptionKey]::new()
$krbenckey.EType = $encryptionType
$krbenckey.KeyValue = $kerbkey

$krbinfo.Key = $krbenckey
$krbinfo.SRealm = $realm
$krbinfo.AuthTime = $authtime
$krbinfo.EndTime = $endtime
$krbinfo.RenewTill = $renewtime
$krbinfo.Flags = $tflags
$krbinfo.PName = $user
$krbinfo.StartTime = $starttime




$tfile = $ticketfile -replace '[^0-9A-Fa-f]', ''
$hs = ''
$j = 0
$i = $ticketfilelines - 1
for($j; $j -lt $i; $j++) { $y = $tfile[$j]; $r = $y.substring(0,32); $hs += $r.Trim() }


#$hs += $tfile[$ticketfilelines - 1]
$tmp = $ticketfile[$ticketfilelines - 1]
$tmpl = $tmp.length
$hs += $($tmp.substring(0,$tmpl)) -replace '[^0-9A-Fa-f]', ''

$bbytes = Convert-HexStringToBytes -HexString $hs
$c = [System.ReadOnlyMemory[byte]]::new($bbytes)
$d = [Kerberos.NET.Entities.KrbTicket]::DecodeApplication($c)

$KRBCRED = [Kerberos.NET.Entities.KrbCred]::WrapTicket($d, $krbinfo)
$cpart = $krbcred.Validate()
$z = $KRBCRED.tickets[0]
$zinfo = $cpart.TicketInfo[0]
$zinfo.realm = $realm

$ticketcacheentry = [Kerberos.NET.TicketCacheEntry]::ConvertKrbCredToCacheEntry($cpart, $z, $zinfo)

$cache = [Kerberos.NET.Client.Krb5CredentialCache]::new()
$kdcClientOffset = [Kerberos.NET.Client.Krb5CredentialCacheTag]::KdcClientOffset


$cache.version = 4
$cache.DefaultPrincipalName = $user
$ttype = $cache.GetType()
$method = $ttype.GetMethod("Add", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
$method.Invoke($cache,@($ticketcacheentry))

[System.IO.File]::WriteAllBytes($outpath, $cache.GetType().GetMethod("Serialize", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance).Invoke($cache,@()))
