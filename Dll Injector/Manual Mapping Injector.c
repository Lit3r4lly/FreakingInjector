#include "Includes.h"
/*
	Copyright (c) 2020 Ori

	This injection method working on manual mapping injection,
	manual mapping injection is a dll injection method that inject by her self and map the pe headers of the dll.
	Manual mapping has couple of levels: 
	1) Open the dll
	2) Parse the dll
	3) Write headers and sections to the process memory
	4) Write shellcode that has the following: relocations and import resolutions
	5) Create remote thread that will trigger the shelcode
*/

/*
	This function considered as the "main" function of the injection method
	In: 
		processID - the processID of the target process
		dllPath - the path of the dll that should injected

	Out:
		success / failure (by TRUE\\FALSE codes)
*/

int manualMappingInjectionMethod(int processId, char* dllPath) {
	BYTE *pSrcDllData						= NULL;
	IMAGE_DOS_HEADER *pDosHeader			= NULL;
	IMAGE_NT_HEADERS *pOldNtHeader			= NULL;
	IMAGE_OPTIONAL_HEADER *pOldOptHeader	= NULL;
	IMAGE_FILE_HEADER *pOldFileHeader		= NULL;
	IMAGE_SECTION_HEADER *pSectionHeader	= NULL;
	BYTE *pTargetAddr						= NULL;

	unsigned int i						= 0;
	HANDLE hProcess						= NULL;
	LPTHREAD_START_ROUTINE entryPoint	= 0;

	unsigned int loaderShellcodeSize	= 0;
	loaderData loaderParams				= { 0 };
	PVOID loaderMemory					= 0;

	HANDLE hThread = NULL;

	// starting analysis the dll
	pSrcDllData = getDllContent(dllPath);
	if (!pSrcDllData) {
		return FALSE;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pSrcDllData;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Invalid executable(dll) file \nNote: there is no MZ signature at the start of the file\n");
		
		free(pSrcDllData);
		return FALSE;
	}

	pOldNtHeader = (PIMAGE_NT_HEADERS)(pSrcDllData + pDosHeader->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("[!] Dll didnt compiled to 64 bit \nNote: compile it again to 64 bit (injector support only 64 bit)\n");

		free(pSrcDllData);
		return FALSE;
	}
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		// failed to create handle with the process
		return FALSE;
	}

	// allocating memory in the target process for writing the dll
	// first trying to allocate in the image base of the process for unusing rva and some extra offsets
	pTargetAddr = (BYTE*)VirtualAllocEx(hProcess, (void*)pOldOptHeader->ImageBase, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pTargetAddr == NULL) {
		// trying to allocate in other address (not directly to the image base)
		
		pTargetAddr = (BYTE*)VirtualAllocEx(hProcess, NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pTargetAddr == NULL) {
			printf("[!] Failed to allocate memory in the target process \n");

			free(pSrcDllData);
			CloseHandle(hProcess);
			return FALSE;
		}
	}

	// writing the headers into the process memory
	if (!WriteProcessMemory(hProcess, pTargetAddr, pSrcDllData, pOldNtHeader->OptionalHeader.SizeOfHeaders, NULL)) {
		printf("[!] Failed to write the headers into the process\n");

		VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
		free(pSrcDllData);
		CloseHandle(hProcess);
		return FALSE;
	}

	// writing sections into the process memory
	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (i = 0; i != pOldFileHeader->NumberOfSections; i++, pSectionHeader++) {
		if (!WriteProcessMemory(hProcess, pTargetAddr + pSectionHeader->VirtualAddress, pSrcDllData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, NULL)) {
			printf("[!] Failed to write the sections into the process\n");

			VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
			free(pSrcDllData);
			CloseHandle(hProcess);
			return FALSE;
		}
	}

	// setting loader params for starting relocating and resolving iat
	loaderParams.ImageBase = pTargetAddr;
	loaderParams.NtHeaders = (PIMAGE_NT_HEADERS)(pTargetAddr + pDosHeader->e_lfanew);

	loaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)(pTargetAddr + pOldNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	loaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(pTargetAddr + pOldNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	loaderParams.fnLoadLibraryA = LoadLibraryA;
	loaderParams.fnGetProcAddress = GetProcAddress;

	// getting the loader shellcode size
	loaderShellcodeSize = (unsigned int)stubFunction - (unsigned int)loaderShellcode;

	// allocate memory for the loader (params + shellcode)
	loaderMemory = VirtualAllocEx(hProcess, NULL, loaderShellcodeSize + sizeof(loaderData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (loaderMemory == NULL) {
		printf("[!] Failed to allocate memory in the target process for the loader \n");

		free(pSrcDllData);
		VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// write params and loader into target process memory
	WriteProcessMemory(hProcess, loaderMemory, &loaderParams, sizeof(loaderData), NULL);
	WriteProcessMemory(hProcess, (void*)((loaderData*)loaderMemory + 1), loaderShellcode, loaderShellcodeSize, NULL);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderData*)loaderMemory + 1), loaderMemory, 0, NULL);

	if (hThread == NULL) {
		printf("[!] Creating remote thread failed \n");

		VirtualFreeEx(hProcess, loaderMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
		free(pSrcDllData);
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	free(pSrcDllData);
	VirtualFreeEx(hProcess, loaderMemory, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}

/*
	This function read the dll file content
	In:
		dllPath - the path of the injected dll

	Out:
		the dll file content \\ failure
*/

BYTE* getDllContent(char* dllPath) {
	BYTE* pSrcDllData = NULL;
	FILE* pFile = NULL;
	long fileSize = 0;

	pFile = fopen(dllPath, "rb");
	if (pFile == NULL) {
		printf("[!] Failed to open the dll file \n");
		return FALSE;
	}

	// getting the file size (classic c moment)
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	// if there is nothing except PE headers
	if (fileSize < PAGE_SIZE) {
		printf("[!] File size is invalid \nNote: there is nothin else except PE headers \n");

		fclose(pFile);
		return FALSE;
	}

	// reading the dll file into memory for analysis
	pSrcDllData = (BYTE*)malloc(fileSize * sizeof(BYTE));
	if (pSrcDllData == NULL) {
		printf("[!] Failed to allocate memory for the dll data\n");

		fclose(pFile);
		return FALSE;
	}

	if (!fread(pSrcDllData, 1, fileSize, pFile)) {
		printf("[!] Didnt success to read the dll content.\n");

		free(pSrcDllData);
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);
	return pSrcDllData;
}

/*
	This function is the loader shellcode that make the most important things in the injection
	In:
		loaderParams - parameters structure for the loader (set in the main function)

	Out:
		returning to the remote thread some returned values from the dll
*/

DWORD __stdcall loaderShellcode(loaderData* loaderParams) {
	unsigned int i					= 0;
	unsigned int amountOfEntries	= 0;
	PWORD pRelativeRelocInfo		= 0;
	PDWORD pRva						= 0;

	PIMAGE_BASE_RELOCATION pBaseReloc		= loaderParams->BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc	= NULL;

	DWORD deltaOfBase = (DWORD)((LPBYTE)loaderParams->ImageBase - loaderParams->NtHeaders->OptionalHeader.ImageBase);

	PIMAGE_THUNK_DATA FirstThunk			= NULL;
	PIMAGE_THUNK_DATA OriginalFirstThunk	= NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName		= NULL;
	HMODULE hMod							= NULL;
	void* modFunc							= 0;

	dllmain entryPointOfDll = 0;

	// reloc addresses if needed
	// checks if needs a relocation (if the allocation made successfuly in the image base, flex on your friends)
	if (deltaOfBase) {
		if (loaderParams->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			while (pBaseReloc->VirtualAddress) {
				// getting the amount of the entries for specific block
				if (pBaseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {

					amountOfEntries = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					pRelativeRelocInfo = (PWORD)(pBaseReloc + 1); // gets the entry info (offset + type)

					for (i = 0; i < amountOfEntries; i++) {
						if (pRelativeRelocInfo[i]) {
							// getting the pointer to the rva
							pRva = (PDWORD)((LPBYTE)loaderParams->ImageBase + pBaseReloc->VirtualAddress + (pRelativeRelocInfo[i] & 0xFFF));
							*pRva += deltaOfBase;
						}
					}
				}
				pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
			}
		}
	}

	// resolving dll imports
	pImportDesc = loaderParams->ImportDirectory;

	while (pImportDesc->Characteristics) {
		OriginalFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderParams->ImageBase + pImportDesc->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderParams->ImageBase + pImportDesc->FirstThunk);

		hMod = loaderParams->fnLoadLibraryA((LPCSTR)loaderParams->ImageBase + pImportDesc->Name);
		if (!hMod) {
			return FALSE;
		}

		while (OriginalFirstThunk->u1.AddressOfData) {
			if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				modFunc = (void*)loaderParams->fnGetProcAddress(hMod, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0xFFFF));
			} else {
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderParams->ImageBase + OriginalFirstThunk->u1.AddressOfData);
				modFunc = (void*)loaderParams->fnGetProcAddress(hMod, (LPCSTR)pImportByName->Name);
			}

			if (!modFunc) {
				return FALSE;
			}
			FirstThunk->u1.Function = modFunc;

			OriginalFirstThunk++;
			FirstThunk++;
		}
		pImportDesc++;	
	}

	if (loaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
		entryPointOfDll = (dllmain)((LPBYTE)loaderParams->ImageBase + loaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		entryPointOfDll((HMODULE)loaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}
}

/*
	This function made for get function size (shellcode size)
	In:
		NULL

	Out:
		Null
*/

void stubFunction() { }