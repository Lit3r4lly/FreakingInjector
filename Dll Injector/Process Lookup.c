#include "Includes.h"

int getPidByProcessName(char* processName) {
	WCHAR processImage[MAX_PROCESS_NAME_LEN] = { 0 };
	DWORD m_dwPid = 0;
	PROCESSENTRY32 ProcessEntry;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (strlen(processName) <= MAX_PROCESS_NAME_LEN) {
		swprintf(processImage, MAX_PROCESS_NAME_LEN, L"%hs", processName);
	}
	else {
		return FALSE;
	}

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		if (!wcscmp(ProcessEntry.szExeFile, processImage)) {
			CloseHandle(hSnapshot);

			m_dwPid = ProcessEntry.th32ProcessID;
			return m_dwPid;
		}
	} else {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	while (Process32Next(hSnapshot, &ProcessEntry)) {
		if (!wcscmp(ProcessEntry.szExeFile, processImage)) {
			CloseHandle(hSnapshot);

			m_dwPid = ProcessEntry.th32ProcessID;
			return m_dwPid;
		}
	}

	return FALSE;
}