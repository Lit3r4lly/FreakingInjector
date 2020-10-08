#pragma once

#define PAGE_SIZE 0x1000

// some declarations for iat resolving
typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

// params for loader shellcode function
typedef struct loaderData
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

} loaderData;

int manualMappingInjectionMethod(int processId, char* dllPath);
BYTE* getDllContent(char* dllPath);
DWORD __stdcall loaderShellcode(loaderData* loaderParams);
void stubFunction();