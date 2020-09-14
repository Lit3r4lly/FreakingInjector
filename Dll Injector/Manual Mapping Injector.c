#include "Includes.h"

int manualMappingInjectionMethod(int processId, char* dllPath) {
	BYTE					*pSrcData				= NULL;
	IMAGE_DOS_HEADER		*pDosHeader				= NULL;
	IMAGE_NT_HEADERS		*pOldNtHeader			= NULL;
	IMAGE_OPTIONAL_HEADER	*pOldOptHeader			= NULL;
	IMAGE_FILE_HEADER		*pOldFileHeader			= NULL;
	IMAGE_SECTION_HEADER	*pSectionHeader			= NULL;
	BYTE					*pTargetModBaseAddr		= NULL;

	FILE				*pFile			= NULL;
	unsigned int		fileSize		= 0;

	pFile = fopen(dllPath, "wb");
	if (pFile == NULL) {
		printf("[!] Failed to open the dll file");

		return FALSE;
	}

	// getting the file size (classic c moment)
	fseek(pFile, 0L, SEEK_END);
	fileSize = ftell(pFile);
	rewind(pFile);

	// if there is nothing except PE headers
	if (fileSize < 0x1000) {
		printf("[!] File size is invalid \nNote: there is nothin else except PE headers");

		fclose(pFile);
		return FALSE;
	}

	// reading the dll file into memory for analysis
	pSrcData = (BYTE*)malloc(fileSize);
	if (pSrcData == NULL) {
		printf("[!] Failed to allocate memory");
		
		fclose(pFile);
		return FALSE;

	}
	fread(pSrcData, sizeof(BYTE*), fileSize, pFile);
	fclose(pFile);

	// starting analysis the dll

	pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Invalid executable(dll) file \nNote: there is no MZ signature at the start of the file");
		
		free(pSrcData);
		return FALSE;
	}

	pOldNtHeader = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("[!] Dll didnt compiled to 64 bit \nNote: compile it again to 64 bit (injector support only 64 bit)");

		free(pSrcData);
		return FALSE;
	}

	pSectionHeader = (IMAGE_SECTION_HEADER)pOldNtHeader;
	

	free(pSrcData);
	return TRUE;
}

