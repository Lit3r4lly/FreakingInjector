# Dllinjector
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

## Screenshots
TBD