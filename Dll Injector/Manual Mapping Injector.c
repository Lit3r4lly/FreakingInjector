#include "Includes.h"

int manualMappingInjectionMethod(int processId, char* dllPath) {
	BYTE					*pSrcDllData			= NULL;
	IMAGE_DOS_HEADER		*pDosHeader				= NULL;
	IMAGE_NT_HEADERS		*pOldNtHeader			= NULL;
	IMAGE_OPTIONAL_HEADER	*pOldOptHeader			= NULL;
	IMAGE_FILE_HEADER		*pOldFileHeader			= NULL;
	IMAGE_SECTION_HEADER	*pSectionHeader			= NULL;
	BYTE					*pTargetAddr			= NULL;

	FILE		*pFile			= NULL;
	long		fileSize		= 0;

	unsigned int i = 0;
	HANDLE hProcess = NULL;
	LPTHREAD_START_ROUTINE entryPoint = 0;

	loaderData loaderParams = { 0 };
	PVOID loaderMemory = 0;

	HANDLE hThread = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		// failed to create handle with the process
		return FALSE;
	}

	pFile = fopen("C:\\check\\DllToInjectIn.dll", "rb");
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

	if (!fread(pSrcDllData, 1, fileSize, pFile) ) {
		printf("[!] Didnt success to read the dll content.\n");

		fclose(pFile);
		return FALSE;
	}
	fclose(pFile);

	// starting analysis the dll

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
	
	// allocating memory in the target process for writing the dll
	// first trying to allocate in the image base of the process for unusing rva and some extra offsets
	pTargetAddr = (BYTE*)VirtualAllocEx(hProcess, (void*)pOldOptHeader->ImageBase, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pTargetAddr == NULL) {
		// trying to allocate in other address (not directly to the image base)
		
		pTargetAddr = (BYTE*)VirtualAllocEx(hProcess, NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pTargetAddr == NULL) {
			printf("[!] Failed to allocate memory in the target process \n");

			free(pSrcDllData);
			return FALSE;
		}
	}

	// writing sections to memory (target process)
	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (i = 0; i != pOldFileHeader->NumberOfSections; i++, pSectionHeader++) {
		if (!WriteProcessMemory(hProcess, pTargetAddr + pSectionHeader->VirtualAddress, pSrcDllData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, NULL)) {
			printf("[!] Failed to write the sections into the process\n");

			VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
			free(pSrcDllData);
			return FALSE;
		}
	}

	// allocate memory for the loader (params + code)
	loaderMemory = VirtualAllocEx(hProcess, NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (loaderMemory == NULL) {
		printf("[!] Failed to allocate memory in the target process for the loader \n");

		free(pSrcDllData);
		VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
		return FALSE;
	}

	// setting loader params for starting relocating and resolving iat
	loaderParams.ImageBase = pTargetAddr;
	loaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pTargetAddr + pDosHeader->e_lfanew);

	loaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pTargetAddr + pOldNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	loaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pTargetAddr + pOldNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	loaderParams.fnLoadLibraryA = LoadLibraryA;
	loaderParams.fnGetProcAddress = GetProcAddress;

	// write params and loader into target process memory
	WriteProcessMemory(hProcess, loaderMemory, &loaderParams, sizeof(loaderData), NULL);
	WriteProcessMemory(hProcess, (PVOID)((loaderData*)loaderMemory + 1), loaderShellcode, PAGE_SIZE - sizeof(loaderParams), NULL);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderData*)loaderMemory + 1), loaderMemory, 0, NULL);
	if (hThread == NULL) {
		printf("[!] Creating remote thread failed \n");

		VirtualFreeEx(hProcess, loaderMemory, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
		free(pSrcDllData);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, loaderMemory, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pTargetAddr, 0, MEM_RELEASE);
	free(pSrcDllData);
	return TRUE;
}

DWORD __stdcall loaderShellcode(loaderData* loaderParams) {
	unsigned int	i						= 0;
	unsigned int	amountOfEntries			= 0;
	PWORD			pRelativeRelocInfo		= 0;
	PDWORD			pRva					= 0;

	PIMAGE_BASE_RELOCATION		 pBaseReloc			= loaderParams->BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR	 pImportDesc		= NULL;

	// checks if needs a relocation (if the allocation made successfuly in the image base, flex on your friends)
	DWORD deltaOfBase = (DWORD)((LPBYTE)loaderParams->ImageBase - loaderParams->NtHeaders->OptionalHeader.ImageBase);

	PIMAGE_THUNK_DATA FirstThunk = NULL;
	PIMAGE_THUNK_DATA OriginalFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
	HMODULE hMod = NULL;
	DWORD modFunc = 0;

	// relocating (if needed) addresses
	if (deltaOfBase) {
		if (loaderParams->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			while (pBaseReloc->VirtualAddress) {
				// getting the amount of the entries for specific block
				if (pBaseReloc->SizeOfBlock >= sizeof(PIMAGE_BASE_RELOCATION)) {

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
			FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderParams->ImageBase + pImportDesc->FirstThunk);
			OriginalFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)loaderParams->ImageBase + pImportDesc->OriginalFirstThunk);

			hMod = loaderParams->fnLoadLibraryA((LPCSTR)loaderParams->ImageBase + pImportDesc->Name);
			if (!hMod) {
				return FALSE;
			}

			while (OriginalFirstThunk->u1.AddressOfData) {
				if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					modFunc = (DWORD)loaderParams->fnGetProcAddress(hMod, (LPCSTR)(OriginalFirstThunk->u1.Ordinal & 0xFFFF));
					if (!modFunc) {
						return FALSE;
					}

					FirstThunk->u1.Function = modFunc;
				}
				else {
					pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderParams->ImageBase + OriginalFirstThunk->u1.AddressOfData);
					modFunc = (DWORD)loaderParams->fnGetProcAddress(hMod, (LPCSTR)pImportByName->Name);
					if (!modFunc) {
						return FALSE;
					}

					FirstThunk->u1.Function = modFunc;
				}
				OriginalFirstThunk++;
				FirstThunk++;
			}
			pImportDesc++;
	}

	//__debugbreak();
	if (loaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint) {
		//dllmain entryPointOfDll = (dllmain)((LPBYTE)loaderParams->ImageBase + loaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		//__debugbreak();
		//return entryPointOfDll((HMODULE)loaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}