#include "Includes.h"

int getPidByProcessName(char* processName) {
	WCHAR			processImage[MAX_PROCESS_NAME_LEN]	= { 0 };
	DWORD			m_dwPid								= 0;
	PROCESSENTRY32	ProcessEntry						= { 0 };
	HANDLE			hSnapshot							= NULL;

	if (strlen(processName) <= MAX_PROCESS_NAME_LEN) {
		swprintf(processImage, MAX_PROCESS_NAME_LEN, L"%hs", processName);
	}
	else {
		// failed to cast string to WCHAR
		return FALSE;
	}

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		// failed to create snapshot
		return FALSE;
	}

	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		if (!wcscmp(ProcessEntry.szExeFile, processImage)) {
			CloseHandle(hSnapshot);

			m_dwPid = ProcessEntry.th32ProcessID;
			return m_dwPid;
		}
	} else {
		// failed cause process name was [System Process]
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

	// didnt found processId
	return FALSE;
}