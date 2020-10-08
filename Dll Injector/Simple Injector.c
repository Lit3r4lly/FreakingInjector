#include "Includes.h"

/*
	Copyright (c) 2020 Ori
*/

/*
	This function making some very simple dll injection method
	In:
		processId - the processID of the target process
		dllPath - the path of the injected dll

	Out:
		success / failure (by TRUE\\FALSE codes)
*/

int simpleInjectionMethod(int processId, char* dllPath) {
	HANDLE hProcess			= 0;
	HANDLE hThread			= 0;
	LPVOID dllPathAddress	= 0;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		// failed to create handle with the process
		return FALSE;
	}

	dllPathAddress = VirtualAllocEx(
		hProcess,
		NULL,
		strlen(dllPath) + 1,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	if (!dllPathAddress) {
		// failed to allocate mem
		CloseHandle(hProcess);
		return FALSE;
	}

	if (WriteProcessMemory(hProcess, dllPathAddress, (LPCVOID)dllPath, strlen(dllPath) + 1, 0) == 0) {
		// failed to write process memory

		VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	hThread = CreateRemoteThread(
		hProcess,
		0, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"),
		dllPathAddress,
		0, 0
	);
	if (hThread == NULL) {
		// failed to create the remote thread

		VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}
