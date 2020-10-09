# FreakingInjector
This project focuses on dll injection with bunch of diffrent methods.
The injector has a friendly UI and divided into two parts: User-mode injector and Kernel-mode injector (Driver) 

## Remark
- Injector supports only 64 bit dll \ processes
- build only in release mode (or turn off incremental - /INCREMENTAL:NO) - incremental linking could make some jump thunks to handle relocations of functions \ pointers to new addresses
- build file will be added

## Features
- [x] Simple injection method 
- [x] Manual mapping injection method
- [ ] Reflective injection method
- [ ] GUI
- [ ] Kernel mode injector (Driver)
- [ ] Other methods of injection

## Usage
```
[$] Usage:  
        Method (1) - FreakingInjector.exe <PID> <dll_path> <arguments_method>  
        Method (2) - FreakingInjector.exe <process_name> <dll_path> <arguments_method>  
[*] Examples:  
        Method (1) - "FreakingInjector.exe" "548" "C:\Users\Maxim\myDll.dll" "1"  
        Method (2) - "FreakingInjector.exe" "Calculator.exe" "C:\Users\Maxim\myDll.dll" "2"  
```

## Screenshots
TBD

## Issues
If you have any issues with this tool, you can ping me on Discord: Lit3r4lly#8336  
If you have some critical bug, open an PR/Issue ticket