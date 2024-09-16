# EByte-Shellcode-Loader

**EByte-Shellcode-Loader** is a shellcode loader that uses indirect syscalls written in **D language**. The loader bypasses user-mode hooks by resolving system calls manually from NTDLL using a hash-based method. The project includes various tools written in **Go** and **Python** to generate shellcode from executables and automate the shellcode extraction and loader compilation process.

## Project Structure

The project consists of the following files:

- **`syscalls.d`**: Implements indirect syscalls using manually resolved system calls from NTDLL. It uses a hash-based approach to identify syscalls like `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx`.
  
- **`loader.d`**: The main loader script written in **D**. It uses the syscalls implemented in `syscalls.d` to allocate memory, write shellcode, change memory protections, and execute the shellcode via a newly created thread.

- **`donut.exe`**: A tool for generating shellcode from an executable (PE file). The shellcode is position-independent and can be injected using the loader.

- **`generate_bin_file.go`**: A **Go** script that automates the generation of a binary file from an executable using the Donut tool. This binary file will then be used for shellcode extraction.

- **`generate_shellcode_and_compile.py`**: A **Python** script that automates the extraction of shellcode from a binary file and compiles the loader with the extracted shellcode.

## Usage

### Prerequisites

- **D Language Compiler (`dmd`)**: To compile the D scripts (`loader.d` and `syscalls.d`).
- **Go**: To run the Go script that generates binary files from executables.
- **Python**: To execute the script for shellcode extraction and loader compilation.
- **Donut**: The Donut tool (`donut.exe`) is used to generate shellcode from executables.

### License:
Apache License 2.0
