#pragma once

// librarys
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>

// file headers
#include "Simple Injector.h"
#include "Process Lookup.h"

// defines
#define SIMPLE_INJECTION 1
#define MANUAL_MAPPING_INJECTION 2
#define REFLECTIVE_INJECTION 3

#define MAX_DLL_PATH_LEN 0x200