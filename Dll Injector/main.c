#include "Includes.h"

int main(int argc, char **argv) {
	char	processName[MAX_PROCESS_NAME_LEN]	= { 0 };
	char	dllPath[MAX_DLL_PATH_LEN]		= { 0 };
	int		processId							= 0;
	int		injectionStatus						= 0;
	int		injectionMethod						= 0;

	// args validation
	if (argc < 3) {
		printf("[!] Usage: DllInjector.exe <process_name> <dll_path>\n");
		return 0;
	}

	if (strlen(argv[1]) >= MAX_PROCESS_NAME_LEN) {
		printf("[!] Process name length is too long!\n");
		return 0;
	}
	strcpy(processName, argv[1]);

	if (strlen(argv[2]) >= MAX_DLL_PATH_LEN) {
		printf("[!] Dll path length is too long!\n");
		return 0;
	}
	strcpy(dllPath, argv[2]);

	if (!GetFileAttributesA(dllPath)) {
		printf("[!] Dll file dosent exist \nNote: check if the path spelled out correctly");
		return 0;
	}

	// getting process ID
	printf("[&] Searching Process : %s\n", processName);
	processId = getPidByProcessName(processName);
	if (processId == FALSE) {
		printf("[!] Failed to find processID \nNote: check if you spelled out the process name correctly");
		return 0;
	}
	printf("[^] ProcessID Found : %d\n", processId);
	
	// injection method
	printf("[$] Enter injection method: \n\t1. Simple injection \n\t2. Manual mapping injection \n\t3. Reflective injection \n\tYour choice: ");
	scanf("%d", &injectionMethod);

	switch (injectionMethod)
	{
	case SIMPLE_INJECTION:
		printf("[^] Simple dll injection starting...\n");
		injectionStatus = simpleInjectionMethod(processId, dllPath);
		break;

	case MANUAL_MAPPING_INJECTION:
		printf("[^] Manual mapping dll injection starting...\n");
		injectionStatus = manualMappingInjectionMethod(processId, dllPath);
		break;

	case REFLECTIVE_INJECTION:
		printf("[^] Reflective dll injection starting...\n");
		// injectionStatus = reflectiveInjectionMethoud();
		break;

	default:
		printf("[!] Injection method didnt found! \nNote: check if your injection method appears in the list above");
		break;
	}

	if (injectionStatus == FALSE) {
		printf("[!] Injection failed. \nNote: Please make sure your dll and your process are both compiled / run at 64/32 bit (depends on your decision)\n");
	} else if (injectionStatus == TRUE) {
		printf("[!] Injection succeeded. \nNote: If you want to inject again, please terminate and start your process (entry address reinject feature will be soon)\n");
	}

	system("PAUSE");
	return 0;
}
