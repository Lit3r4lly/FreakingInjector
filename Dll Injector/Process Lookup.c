#include "Includes.h"
/*
	Copyright (c) 2020 Ori
	
	This function finding processID by process name
	In:
		processName - the name of the target process

	Out:
		the processID of the target process
*/

int getPidByProcessName(char* processName) {
	WCHAR processImage[MAX_PROCESS_NAME_LEN] = { 0 };
	DWORD processId = 0;
	PROCESSENTRY32 ProcessEntry = { 0 };
	HANDLE hSnapshot = NULL;

	swprintf(processImage, MAX_PROCESS_NAME_LEN, L"%hs", processName);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open snapshot");
		return FALSE;
	}

	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		if (!wcscmp(ProcessEntry.szExeFile, processImage)) {
			CloseHandle(hSnapshot);

			processId = ProcessEntry.th32ProcessID;
			return processId;
		}
	}
	else {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	while (Process32Next(hSnapshot, &ProcessEntry)) {
		if (!wcscmp(ProcessEntry.szExeFile, processImage)) {
			CloseHandle(hSnapshot);

			processId = ProcessEntry.th32ProcessID;
			return processId;
		}
	}

	return FALSE;
}