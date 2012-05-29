#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <psapi.h>
#include <windows.h>
#include <WinSock2.h>
#include <strsafe.h>
#include <vector>
#include <string>
#include <WinDNS.h>

using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define MAX_BUFF_SIZE 1024
#define MAX_IP_SIZE 128

#define LAN_ADDRESSES_SIZE 6

struct Process_Info {
	DWORD id;
	string remoteAddr;
	u_short port;
	string name;
	string path;
};

string lanAddresses[LAN_ADDRESSES_SIZE] = {
	"127.0.0.1",
    "192.168.",
    "172.16.0.",
    "10.0.0.",
    "169.254.",
	"0.0.0.0"
};

#define BROWSER_NAMES_SIZE 5
string browserNames[BROWSER_NAMES_SIZE] = {
	"iexplore.exe",
    "chrome.exe",
    "firefox.exe",
    "opera.exe",
    "safari.exe"
};

char *IRCStrings[] = {
      //standard irc strings
      "PING",
      "PONG",
      "NICK",
      "KICK",
      "NOTICE",
      "VERSION",
      "QUOTE",
      "RAW",
      "PRIVMSG",
      "JOIN",
      "BAN",
      "IRC",
      "UNREAL",
      "[bot]-",
      //if ircd is modded standard strings may 
      //be missing but these shouldn't be
      "001",
      "332",
      "372",
      "375",
      "376",
      "422",
      "433",
      "436",
      {NULL}
   };

typedef BOOL (WINAPI *DNS_GET_CACHE_DATA_TABLE)(PDNS_RECORD*);

/* Note: could also use malloc() and free() */
int PrintModules( DWORD processID );
void killProcess( DWORD processID );

int cleanGraveyard(LPCTSTR path);
PWSTR getNameForAddr(IP4_ADDRESS addr);

void BlockHost(TCHAR *szShitList[]);
PMIB_TCPTABLE get_tcp_table();
void read_tcp_table(PMIB_TCPTABLE pTcpTable);
bool is_browser_process(string ProcessName);
bool is_lan_address(string remoteAddr);
string get_process_path(DWORD processID);
string get_process_name(DWORD processID);
int select_call(SOCKET ConnectSocket);
bool is_irc_packet(char *recvbuf);
bool is_irc_process(string remoteAddr, u_short port);
void find_bad_process(vector<struct Process_Info> *process_vec);
void read_dns_catche();

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

bool is_lan_address(string remoteAddr) {
	for (int i = 0; i < LAN_ADDRESSES_SIZE; ++i) {
		if (remoteAddr.find(lanAddresses[i]) != string::npos)
			return true;
	}
	return false;
}

bool is_browser_process(string ProcessName) {
	for (int i = 0; i < BROWSER_NAMES_SIZE; ++i) {
		if (ProcessName.find(browserNames[i]) != string::npos)
			return true;
	}
	return false;
}

void read_tcp_table(PMIB_TCPTABLE pTcpTable) {
    string remoteAddr;
	u_short port;
    struct in_addr IpAddr;
	string processName;
	vector<struct Process_Info> process_vec;
	struct Process_Info proc_info;


	printf("\tNumber of entries: %d\n", (int) pTcpTable->dwNumEntries);
    for (int i = 0; i < (int) pTcpTable->dwNumEntries; i++) {
		MIB_TCPROW_OWNER_MODULE module = ((PMIB_TCPTABLE_OWNER_MODULE)pTcpTable)->table[i];
        IpAddr.S_un.S_addr = module.dwRemoteAddr;
        remoteAddr = string(inet_ntoa(IpAddr));
		port = ntohs((u_short)module.dwRemotePort);
		cout << "\tTCP[" << i << "] PID: " << module.dwOwningPid << endl;
		cout << "\tTCP[" << i << "] Remote Addr: " << remoteAddr << endl;
		cout << "\tTCP[" << i << "] Remote Port: " << port<< endl;

		if (!is_lan_address(remoteAddr)) {
			processName = get_process_name(module.dwOwningPid);
			if (!processName.empty()) {
				if (!is_browser_process(processName)) {
					proc_info.id = module.dwOwningPid;
					proc_info.remoteAddr = remoteAddr;
					proc_info.port = port;
					proc_info.name = processName;
					proc_info.path = get_process_path(module.dwOwningPid);
					cout << "\tTCP[" << i << "] Process Name: " << processName << endl;
					process_vec.push_back(proc_info);
				}
			}
		}
	}

	if (!process_vec.empty()) {
		find_bad_process(&process_vec);
		if (!process_vec.empty()) {
			for (int i = 0; i < process_vec.size(); ++i)
				cout << process_vec.at(i).name << " " << process_vec.at(i).remoteAddr << " " << process_vec.at(i).port << endl;
			exit(1);
			//block the these process
		}
	}

}

void find_bad_process(vector<struct Process_Info> *process_vec) {
	for (unsigned int i = 0; i < process_vec->size(); ++i) {
		if (!is_irc_process(process_vec->at(i).remoteAddr, process_vec->at(i).port)) {
			process_vec->erase(process_vec->begin() + i);
			--i;
		}
	}
}

PMIB_TCPTABLE get_tcp_table() {
	PMIB_TCPTABLE pTcpTable;
    DWORD dwSize = 0;
	DWORD size = 0;
	DWORD result;

    pTcpTable = (MIB_TCPTABLE *) MALLOC(sizeof (MIB_TCPTABLE));
    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        exit(1);
    }

    dwSize = sizeof (MIB_TCPTABLE);
	// Make an initial call to GetTcpTable to
	// get the necessary size into the dwSize variable
    if ((result = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE *) MALLOC(dwSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            exit(1);
        }
    }

	// Make a second call to GetTcpTable to get
	// the actual data we require
    if ((result = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0)) == NO_ERROR) {
		return pTcpTable;
	} else {
        printf("\tGetTcpTable failed with %d\n", result);
        FREE(pTcpTable);
        return NULL;
    }
}

string get_process_name(DWORD processID) {
	HMODULE hMods;
    HANDLE hProcess;
    DWORD cbNeeded;
	TCHAR name[MAX_PATH];
	string processName;

	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );
    if (NULL == hProcess)
        return processName;

    if( EnumProcessModules(hProcess, &hMods, sizeof(hMods), &cbNeeded)) {
		if (GetModuleBaseName(hProcess, hMods, name, sizeof(name)/sizeof(TCHAR)) > 0) {
			wstring arr_w(name);
			processName = string(arr_w.begin(), arr_w.end());
			return processName;
		}
	}
	CloseHandle( hProcess );
	return processName;
}

string get_process_path(DWORD processID) {
    HMODULE hMods;
    HANDLE hProcess;
    DWORD cbNeeded;
	TCHAR path[MAX_PATH];
	string processPath;

    // Get a handle to the process.
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );
    if (NULL == hProcess)
        return processPath;

    if( EnumProcessModules(hProcess, &hMods, sizeof(hMods), &cbNeeded)) {
		if (GetModuleFileNameEx(hProcess, hMods, path, sizeof(path) / sizeof(TCHAR)) > 0) {
			//char  *pmbbuf   = (char *)malloc( MAX_PATH );
			//wcstombs_s(NULL, pmbbuf, MAX_PATH, executePath, sizeof(executePath) / sizeof(TCHAR) );
			//string b = StringType(executePath);
			wstring arr_w(path);
			processPath = string(arr_w.begin(), arr_w.end());
			return processPath;
		}
    }
	//http://msdn.microsoft.com/en-us/library/windows/desktop/ms682621(v=vs.85).aspx
	//http://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx
    CloseHandle( hProcess );

    return processPath;
}

bool is_irc_process(string remoteAddr, u_short port) {
	// Declare and initialize variables.
	WSADATA wsaData;
    int iResult;

    SOCKET connectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService;
	char szTemp[MAX_BUFF_SIZE] = {0};
	char szNick[MAX_BUFF_SIZE] = {0};
	char sendbuf[MAX_BUFF_SIZE] = {0};
	int szIsIRC = 0;
	int szCheckCon = 1;
	int sendbuflen = 0;
	char recvbuf[MAX_BUFF_SIZE] = {0};
    int recvbuflen = MAX_BUFF_SIZE;
	int dwRand;
	int selectRtn;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != NO_ERROR) {
      printf("WSAStartup failed: %d\n", iResult);
      exit(1);
    }

	connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        exit(1);
    }

	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(remoteAddr.c_str());
    clientService.sin_port = htons(port);

	iResult = connect(connectSocket, (SOCKADDR*) &clientService, sizeof(clientService) );
    if ( iResult == SOCKET_ERROR) {
        closesocket (connectSocket);
		cout << remoteAddr.c_str() << endl;
        printf("Unable to connect to server: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

	srand(GetTickCount());
	dwRand = rand() % 10000 + 1000;

	sprintf_s(szNick, "[bot]-%d", dwRand);
	sprintf_s(szTemp, "NICK %s\r\n", szNick);
    memcpy_s(sendbuf, sizeof(sendbuf), szTemp, strlen(szTemp));
	sendbuflen = strlen(szTemp);
	
	sprintf_s(szTemp, "USER %s d d %s\r\n", szNick, szNick);
	memcpy_s(sendbuf + sendbuflen, sizeof(sendbuf), szTemp, strlen(szTemp));
	sendbuflen += strlen(szTemp);
	sendbuf[sendbuflen] = '\0';

	cout << remoteAddr << endl;
	cout << sendbuf << endl;

    iResult = send(connectSocket, sendbuf, sendbuflen, 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed: %d\n", WSAGetLastError());
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }
	
	while (true) {
		if (selectRtn = select_call(connectSocket)) {
			iResult = recv(connectSocket, recvbuf, recvbuflen, 0);
			if (iResult > 0) {
				printf("Bytes received: %d\n", iResult);
				for (int i = 0; i < iResult; ++i)
					printf("%c", recvbuf[i]);
				cout << endl;
				if (is_irc_packet(recvbuf))
					return true;

			} else if (iResult == 0) {
				return false;
			} else {
				perror("recv failed");
				exit(1);
			}
		} else if (selectRtn == 0) {
			cout << "Time Out" << endl;
			return false;
		} else if (selectRtn == -1) {
			perror("select failed");
		}
    }

	closesocket(connectSocket);
    WSACleanup();

	return 0;
}

bool is_irc_packet(char *recvbuf) {
	char *pch;

	for (int i = 0; IRCStrings[i] != NULL; ++i) {
		pch = strstr(recvbuf, IRCStrings[i]);
		if (pch != NULL)
			return true;
	}
	return false;
}

void read_dns_catche() {
	PDNS_RECORD pEntry = (PDNS_RECORD) MALLOC(sizeof(DNS_RECORD));
	cout << sizeof(DNS_RECORD) << endl;
    HINSTANCE hLib = LoadLibrary(TEXT("DNSAPI.dll"));

    // Get function address
    DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable = (DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hLib, "DnsGetCacheDataTable");
	
    int stat = DnsGetCacheDataTable(pEntry);
    printf("stat = %d\n", stat);
    pEntry = pEntry->pNext;
    while(pEntry) {
		if (pEntry->wType == 5) {
			wprintf(L"%s : %s\n", pEntry->pName, pEntry->Data.CNAME.pNameHost);
		}
        pEntry = pEntry->pNext;
    }
    FREE(pEntry);
}

void BlockHost(TCHAR *szShitList[])
{
	FILE *fHosts;
	TCHAR  szSystem[MAX_PATH], szAppend[MAX_PATH];
	ZeroMemory(&szSystem, MAX_PATH);
	ZeroMemory(&szAppend, MAX_PATH);
	
	GetSystemDirectory(szSystem, MAX_PATH);
	wcsncat_s(szSystem, L"\\drivers\\etc\\hosts", MAX_PATH);

	_wfopen_s(&fHosts, szSystem, L"r");
	if (!fHosts)
		return;

	
	wcsncpy_s(szAppend, L"", MAX_PATH);
	wprintf(L"%s\n", szSystem);

	
	for(int i = 0; szShitList[i]; ++i) {
		wcsncat_s(szAppend, L"1.1.1.1\t", MAX_PATH);
		wcsncat_s(szAppend, szShitList[i], MAX_PATH);
		wcsncat_s(szAppend, L"\n", MAX_PATH);
	}
	//fprintf(fHosts, "%s", szAppend);
	wprintf(L"%s\n", szAppend);
	fclose(fHosts);
	exit(1);
	
}

int select_call(SOCKET ConnectSocket) {
	fd_set fd;
	timeval tv;
	int selectRtn;

	FD_ZERO(&fd);
	FD_SET(ConnectSocket, &fd);
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	if ((selectRtn = select(ConnectSocket + 1, &fd, NULL, NULL, &tv)) == 1)
		return 1;
	else if (selectRtn == 0)
		return 0;
	else {
		printf("select failed: %d\n", WSAGetLastError());
		return -1;
	}
}
