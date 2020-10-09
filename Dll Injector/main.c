#include "Includes.h"

int main(int argc, char **argv) {
	char processName[MAX_PROCESS_NAME_LEN]	= { 0 };
	char dllPath[MAX_DLL_PATH_LEN]			= { 0 };
	int	processId							= 0;
	int	injectionStatus						= 0;
	int	injectionMethod						= 0;
	int argsValid							= 0;

	// args validation
	argsValid = argumentsValidation(argc, argv);
	if (argsValid == FALSE) {
		return 0;
	}
	
	if (atoi(argv[ARGS_METHOD]) == 1) {
		processId = argv[PROCESS];
	}
	else {
		// processID lookup
		strcpy(processName, argv[PROCESS]);

		printf("[&] Searching Process : %s\n", processName);
		processId = getPidByProcessName(processName);

		if (processId == FALSE) {
			printf("[!] Failed to find processID \nNote: check if you spelled out the process name correctly");
			return FALSE;
		}
		printf("[^] ProcessID Found : %d\n", processId);
	}
	strcpy(dllPath, argv[DLL_PATH]);
	
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

int argumentsValidation(int nArguments, char **arguments) {
	char dot[MAX_EXT_LEN] = { 0 };

	if (strcmp(arguments[HELP], "-h") == 0) {
		help();
		return FALSE;
	}
	else if (nArguments < 4) {
		printf("[!] Not enough arguments");
		return FALSE;
	}
	else if (atoi(arguments[ARGS_METHOD]) == 2) {
		if (strlen(arguments[PROCESS]) >= MAX_PROCESS_NAME_LEN) {
			printf("[!] Process name length is too long");
			return FALSE;
		}
	}
	else {
		printf("Failed to find <arguments_method> \n[!] Usage: DllInjector.exe -h");
		return FALSE;
	}

	if (strlen(arguments[DLL_PATH]) >= MAX_DLL_PATH_LEN) {
		printf("[!] Dll path length is too long!\n");
		return FALSE;
	}
	else if (!GetFileAttributesA(arguments[DLL_PATH])) {
		printf("[!] Dll file dosent exist \nNote: check if the path spelled out correctly");
		return FALSE;
	}

	strcpy(dot, strrchr(arguments[DLL_PATH], '.'));
	if (!dot || dot == arguments[DLL_PATH]) {
		printf("[!] File has no extension or file is a dot file");
		return FALSE;
	}

	return TRUE;
}

void help() {
	printf("Hello! Welcome to FreakingInjector, a tool made for making dll injections\n");
	printf("[$] Usage: \n\tMethod (1) - FreakingInjector.exe <PID> <dll_path> <arguments_method> \n\tMethod (2) - FreakingInjector.exe <process_name> <dll_path> <arguments_method>\n");
	printf("[*] Examples: \n\tMethod (1) - \"FreakingInjector.exe\" \"548\" \"C:\\Users\\Maxim\\myDll.dll\" \"1\" \n\tMethod (2) - \"FreakingInjector.exe\" \"Calculator.exe\" \"C:\\Users\\Maxim\\myDll.dll\" \"2\"\n\n");
	printf("[@] If you have some issues with this tool, ping me on Discord: Lit3r4lly#8336\n");
}