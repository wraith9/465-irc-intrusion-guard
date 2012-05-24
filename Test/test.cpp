#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <psapi.h>
#include <windows.h>
#include <strsafe.h>
#include <WinDNS.h>

using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

typedef BOOL (WINAPI *DNS_GET_CACHE_DATA_TABLE)(PDNS_RECORD*);

/* Note: could also use malloc() and free() */
int PrintModules( DWORD processID );
void killProcess( DWORD processID );

int cleanGraveyard(LPCTSTR path);
PWSTR getNameForAddr(IP4_ADDRESS addr);

int main()
{

    // Declare and initialize variables
    PMIB_TCPTABLE pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
	 DWORD size = 0;

	 DWORD result;

    char szLocalAddr[128];
    char szRemoteAddr[128];
    struct in_addr IpAddr;

    int i;

    if (cleanGraveyard(TEXT("C:\\graveyard\\")) != 0) {
       printf("Unable to clean the graveyard\n");
       return 1;
    }

    pTcpTable = (MIB_TCPTABLE *) MALLOC(sizeof (MIB_TCPTABLE));
    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    dwSize = sizeof (MIB_TCPTABLE);
// Make an initial call to GetTcpTable to
// get the necessary size into the dwSize variable

    if ((result = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE *) MALLOC(dwSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }
    }

// Make a second call to GetTcpTable to get
// the actual data we require
    if ((result = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0)) == NO_ERROR) {
        printf("\tNumber of entries: %d\n", (int) pTcpTable->dwNumEntries);
        for (i = 0; i < (int) pTcpTable->dwNumEntries; i++) {
			MIB_TCPROW_OWNER_MODULE module = ((PMIB_TCPTABLE_OWNER_MODULE)pTcpTable)->table[i];
            IpAddr.S_un.S_addr = module.dwLocalAddr;
			cout << module.OwningModuleInfo <<  endl;
            strcpy_s(szLocalAddr, sizeof (szLocalAddr), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr = module.dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof (szRemoteAddr), inet_ntoa(IpAddr));

			printf("\tTCP[%d] PID: %d\n", i, module.dwOwningPid);
            printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);
            printf("\tTCP[%d] Local Port: %d \n", i, ntohs((u_short)module.dwLocalPort));
            printf("\tTCP[%d] Remote Addr: %s\n", i, szRemoteAddr);
            printf("\tTCP[%d] Remote Port: %d\n", i, ntohs((u_short)module.dwRemotePort));

			if (module.dwOwningPid == 3456) {
				 PrintModules(module.dwOwningPid);
				 exit(1);
			}
		}
    } else {
        printf("\tGetTcpTable failed with %d\n", dwRetVal);
        FREE(pTcpTable);
        return 1;
    }

    if (pTcpTable != NULL) {
        FREE(pTcpTable);
        pTcpTable = NULL;
    }

    return 0;    
}

int PrintModules( DWORD processID )
{
    HMODULE hMods;
    HANDLE hProcess;
    DWORD cbNeeded;
	
    // Print the process identifier.

    printf( "\nProcess ID: %u\n", processID );

    // Get a handle to the process.

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );
    if (NULL == hProcess)
        return 1;

   // Get a list of all the modules in this process.

    if( EnumProcessModules(hProcess, &hMods, sizeof(hMods), &cbNeeded)) {
			TCHAR executeName[MAX_PATH];
            TCHAR executePath[MAX_PATH];
			char *executeNameChar;
			 
			GetModuleBaseName( hProcess, hMods, executeName, sizeof(executeName)/sizeof(TCHAR) );
			executeNameChar = (char *)malloc( MAX_PATH );
			wcstombs_s(NULL, executeNameChar, MAX_PATH, executeName, sizeof(executeName) / sizeof(TCHAR) );
			cout << executeNameChar << endl;

            if ( GetModuleFileNameEx( hProcess, hMods, executePath, sizeof(executePath) / sizeof(TCHAR))) {
				char  *pmbbuf   = (char *)malloc( MAX_PATH );
				wcstombs_s(NULL, pmbbuf, MAX_PATH, executePath, sizeof(executePath) / sizeof(TCHAR) );
				cout<< pmbbuf << endl;
			}
    }
	//http://msdn.microsoft.com/en-us/library/windows/desktop/ms682621(v=vs.85).aspx
	//http://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx
    CloseHandle( hProcess );

    return 0;
}

void killProcess( DWORD processID ) {
	HANDLE hProcess = OpenProcess( PROCESS_TERMINATE, FALSE, processID );
	if (hProcess == NULL) {
		return;
	}

	TerminateProcess(hProcess, 0);
	CloseHandle(hProcess);
}

// Returns the number of files remaining in the graveyard directory specified
// by path or -1 on error. Use GetLastError() for additional error information.
// Technically, a truly successful return value is 0.
int cleanGraveyard(LPCTSTR path) {
   int undeleted = 0;
   TCHAR abspath[MAX_PATH];
   HANDLE hFind;
   WIN32_FIND_DATA wfd;

   // For some unknown reason, 0 indicates failure in Windows APIs
   if (CreateDirectory(path, NULL) == 0) {
      if (GetLastError() != ERROR_ALREADY_EXISTS) {
         return -1;
      }
   }

   if (StringCchCopy(abspath, MAX_PATH, path) != S_OK) {
      return -1;
   }

   if (StringCchCat(abspath, MAX_PATH, TEXT("*")) != S_OK) {
      return -1;
   }

   if ((hFind = FindFirstFile(abspath, &wfd)) == INVALID_HANDLE_VALUE) {
      if (GetLastError() == ERROR_FILE_NOT_FOUND) {
         // There are no files in the graveyard directory
         return 0;
      }
      // Should NEVER get here, I'm pretty sure
      return -1;
   }

   do {
      // Compute the absolute path of the file
      if (FAILED(StringCchCopy(abspath, MAX_PATH, path))) {
         return -1;
      }

      if (FAILED(StringCchCat(abspath, MAX_PATH, wfd.cFileName))) {
         return -1;
      }

      // Delete the file if it is neither . nor ..
      if (lstrcmp(TEXT("."), wfd.cFileName) != 0 &&
          lstrcmp(TEXT(".."), wfd.cFileName) != 0 &&
          DeleteFile(abspath) == 0) {
         // We'll still keep trying to delete whatever is left, but we'll let
         // the user know we weren't entirely successful when we return.
         undeleted++;
      }
   } while (FindNextFile(hFind, &wfd) != 0);

   if (FindClose(hFind) == 0) {
      // Getting here would be heartbreaking, honestly
      return -1;
   }

   if (GetLastError() != ERROR_NO_MORE_FILES) {
      // Find failed for a reason besides "no files left"
      return -1;
   }

   return undeleted;
}

// Takes an IPv4 address in network byte order and returns the domain name that
// maps to it. If the return value is NULL, either no name was found or an error
// occurred. If it is not NULL, the return value MUST be freed by the caller.
PWSTR getNameForAddr(IP4_ADDRESS addr) {
   HMODULE hDnsAPI;
   DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable;
   PDNS_RECORD pTable = NULL, pTableIter, pCacheList = NULL, pCacheListIter;
   PWSTR name = NULL;
   bool found = false;

   // We only need this DLL in this function, so only load it when we're here
   // and free it when we're done
   if ((hDnsAPI = LoadLibrary(TEXT("dnsapi.dll"))) == NULL) {
      return NULL;
   }

   if ((DnsGetCacheDataTable = (DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hDnsAPI, "DnsGetCacheDataTable")) == NULL) {
      FreeLibrary(hDnsAPI);
      return NULL;
   }

   // Turns out you can actually tell if this thing succeeds
   if (!DnsGetCacheDataTable(&pTable)) {
      FreeLibrary(hDnsAPI);
      return NULL;
   }

   // Iterate over the entire DNS cache data table. It doesn't actually have
   // any resource record data, but it's easiest to use the DNS_RECORD type.
   pTableIter = pTable;
   while (!found && pTableIter) {

      // Query the local cache directly
      if (!DnsQuery(pTableIter->pName, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY,
           NULL, &pCacheList, NULL)) {

         ///// TEST CODE /////
         //printf("%ls : ", pTableIter->pName);

         // Iterate over the A record cache entries to try to find a
         // matching IP address
         pCacheListIter = pCacheList;
         while (pCacheListIter) {

            ///// TEST CODE /////
            //struct in_addr v4addr;
            //v4addr.S_un.S_addr = pCacheListIter->Data.A.IpAddress;
            //printf("%s, ", inet_ntoa(v4addr));

            if (pCacheListIter->Data.A.IpAddress == addr) {
               size_t namesize;

               // Being extra paranoid by explicitly allowing for the null
               // character in the limiting argument
               if (SUCCEEDED(StringCbLength(pCacheListIter->pName,
                     (STRSAFE_MAX_CCH - 1) * sizeof(TCHAR), &namesize))) {

                  // Include space for the null character
                  namesize += sizeof(TCHAR);
                  name = (PWSTR)MALLOC(namesize);
                  if (FAILED(StringCbCopy(name, namesize,
                        pCacheListIter->pName))) {
                     FREE(name);
                     name = NULL;
                  }
               }

               // Even if we couldn't copy the domain name into the return
               // value, we still need to return--there's not much we can do
               found = true;
               break;
            }
            pCacheListIter = pCacheListIter->pNext;
         }

         ///// TEST CODE /////
         //printf("\n");

         DnsRecordListFree(pCacheList, DnsFreeRecordList);
         pCacheList = NULL;
      }
      pTableIter = pTableIter->pNext;
   }

   DnsRecordListFree(pTable, DnsFreeRecordList);

   FreeLibrary(hDnsAPI);

   return name;
}