#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <psapi.h>
#include <windows.h>

using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */
int PrintModules( DWORD processID );
void killProcess( DWORD processID );

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