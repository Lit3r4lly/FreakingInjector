#pragma once

// librarys
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>

// injector file headers
#include "Process Lookup.h"
#include "Simple Injector.h"
#include "Manual Mapping Injector.h"
#include "Reflective Injector.h"

// defines
#define HELP 1
#define PROCESS 1
#define DLL_PATH 2
#define ARGS_METHOD 3

#define MAX_EXT_LEN 4

#define SIMPLE_INJECTION 1
#define MANUAL_MAPPING_INJECTION 2
#define REFLECTIVE_INJECTION 3

#define MAX_DLL_PATH_LEN 0x200

int argumentsValidation(int nArguments, char** arguments);
void help();