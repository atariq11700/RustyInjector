use crate::utils;
use winapi::{
    shared::{
        basetsd::{SIZE_T, UINT_PTR, ULONG_PTR},
        minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPCVOID, LPDWORD, LPVOID, WORD},
        ntdef::{HANDLE, LPCSTR},
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        minwinbase::LPSECURITY_ATTRIBUTES,
        processthreadsapi::{CreateRemoteThreadEx, OpenProcess, LPPROC_THREAD_ATTRIBUTE_LIST},
        tlhelp32::PROCESSENTRY32,
        winnt::{
            IMAGE_IMPORT_DESCRIPTOR_u, DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION,
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_HEADER, IMAGE_FILE_HEADER, IMAGE_IMPORT_BY_NAME,
            IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER, IMAGE_ORDINAL_FLAG32,
            IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
            IMAGE_SECTION_HEADER, IMAGE_SNAP_BY_ORDINAL, IMAGE_TLS_DIRECTORY, MEM_COMMIT, MEM_FREE,
            MEM_RESERVE, PAGE_EXECUTE_READWRITE, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER,
            PIMAGE_TLS_CALLBACK, PROCESS_ALL_ACCESS, PVOID,
        },
    },
    vc::vadefs::uintptr_t,
};

type f_LoadLibraryA = unsafe extern "system" fn(lpLibraryFilename: LPCSTR) -> HINSTANCE;
type f_GetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;
type f_DllMain = unsafe extern "system" fn(
    hModule: HMODULE,
    dw_reason_for_call: DWORD,
    lpReserved: LPVOID,
) -> BOOL;
type f_printf = unsafe extern "cdecl" fn(format: LPCSTR, ...);

struct ManualMapLoaderData {
    pLoadLibraryA: f_LoadLibraryA,
    pGetProcAddress: f_GetProcAddress,
    pDllBaseAddr: HINSTANCE,
}

fn image_first_section(pnt_header: PIMAGE_NT_HEADERS) -> PIMAGE_SECTION_HEADER {
    let base = (pnt_header as ULONG_PTR);
    let off1 = memoffset::offset_of!(IMAGE_NT_HEADERS, OptionalHeader);
    let off2 = ((unsafe { *pnt_header } as IMAGE_NT_HEADERS)
        .FileHeader
        .SizeOfOptionalHeader) as usize;
    return (base + off1 + off2) as PIMAGE_SECTION_HEADER;
}

struct SectionName {
    bytes: [u8; 8],
}
impl SectionName {
    fn from(name_array: [u8; 8]) -> SectionName {
        return SectionName { bytes: name_array };
    }
}
impl std::fmt::Display for SectionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}{}{}{}{}",
            self.bytes[0] as char,
            self.bytes[1] as char,
            self.bytes[2] as char,
            self.bytes[3] as char,
            self.bytes[4] as char,
            self.bytes[5] as char,
            self.bytes[6] as char,
            self.bytes[7] as char
        )
    }
}

fn get_headers_from_dll<'a>(
    p_data: *const u8,
) -> (
    &'a IMAGE_DOS_HEADER,
    &'a IMAGE_NT_HEADERS,
    &'a IMAGE_OPTIONAL_HEADER,
    &'a IMAGE_FILE_HEADER,
) {
    let dos_header: &IMAGE_DOS_HEADER = unsafe { &*(p_data as *const IMAGE_DOS_HEADER) };
    let nt_header = unsafe {
        &*(p_data.add(dos_header.e_lfanew.try_into().unwrap()) as *const IMAGE_NT_HEADERS)
    };
    let optional_header = &nt_header.OptionalHeader;
    let file_header = &nt_header.FileHeader;

    return (dos_header, nt_header, optional_header, file_header);
}

pub fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let dll_data = utils::files::is_valid_dll(dll_path.clone());
    if !(dll_data.len() > 0) {
        println!("Unable to read dll");
        return false;
    }

    println!(
        "Dll loaded in host process at 0x{:x}",
        dll_data.as_ptr() as usize
    );

    let target_proc: HANDLE =
        unsafe { OpenProcess(PROCESS_ALL_ACCESS, false as BOOL, proc.th32ProcessID) };

    if target_proc == INVALID_HANDLE_VALUE {
        println!("Unable to open target process");
        return false;
    }

    println!(
        "Opened process [{}] {}, Handle: 0x{:x}",
        proc.th32ProcessID,
        crate::dllinjector::components::processeslist::sz_exe_to_string(proc.szExeFile),
        target_proc as usize
    );

    let (dos_header, nt_header, optional_header, file_header) =
        get_headers_from_dll(dll_data.as_ptr());

    println!(
        "Dll dos header in host process found at 0x{:x}",
        dos_header as *const IMAGE_DOS_HEADER as usize
    );
    println!(
        "Dll nt header in host process found at 0x{:x}",
        nt_header as *const IMAGE_NT_HEADERS as usize
    );
    println!(
        "Dll optional header in host process found at 0x{:x}",
        optional_header as *const IMAGE_OPTIONAL_HEADER as usize
    );

    println!(
        "Dll file header in host process found at 0x{:x}",
        file_header as *const IMAGE_FILE_HEADER as usize
    );

    let mut base_addr_ex = unsafe {
        VirtualAllocEx(
            target_proc,
            optional_header.ImageBase as LPVOID,
            optional_header.SizeOfImage as SIZE_T,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8
    };

    if base_addr_ex as usize == 0 {
        base_addr_ex = unsafe {
            VirtualAllocEx(
                target_proc,
                0 as LPVOID,
                optional_header.SizeOfImage as SIZE_T,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8
        };
    }

    if base_addr_ex as usize == 0 {
        println!("Unable to allocate memory inside target process for dll");
        unsafe { CloseHandle(target_proc) };
    }
    println!(
        "Allocated 0x{:x} bytes in target proc at 0x{:x}",
        optional_header.SizeOfImage, base_addr_ex as usize
    );

    let mut psection_header =
        image_first_section(nt_header as *const IMAGE_NT_HEADERS as PIMAGE_NT_HEADERS);

    for _ in 0..file_header.NumberOfSections {
        unsafe {
            let section_header = &*psection_header;
            println!(
                "Found section header {} at 0x{:x}",
                SectionName::from(section_header.Name),
                psection_header as usize
            );
            if section_header.SizeOfRawData > 0 {
                let name = section_header.Name;
                if WriteProcessMemory(
                    target_proc,
                    base_addr_ex.add(section_header.VirtualAddress as usize) as LPVOID,
                    dll_data
                        .as_ptr()
                        .add(section_header.PointerToRawData as usize)
                        as LPCVOID,
                    section_header.SizeOfRawData as SIZE_T,
                    0 as *mut usize,
                ) == 0
                {
                    println!(
                        "Unable to map section {} into target process memory",
                        SectionName::from(name)
                    );
                    CloseHandle(target_proc);
                    VirtualFreeEx(
                        target_proc,
                        base_addr_ex as LPVOID,
                        optional_header.SizeOfImage as SIZE_T,
                        MEM_FREE,
                    );
                    return false;
                }
                println!(
                    "Mapped dll section {} ({}) into target process as 0x{:x}",
                    SectionName::from(name),
                    section_header.SizeOfRawData,
                    base_addr_ex.add(section_header.VirtualAddress as usize) as usize
                );
            }
            psection_header = psection_header.add(1);
        }
    }

    if unsafe {
        WriteProcessMemory(
            target_proc,
            base_addr_ex as LPVOID,
            dll_data.as_ptr() as LPCVOID,
            0x1000,
            0 as *mut SIZE_T,
        )
    } == 0
    {
        println!("Unable to write pe headers to target process");
    }
    println!("Wrote pe headers to target process");

    let kernel32 = unsafe { GetModuleHandleA("kernel32.dll\0".as_ptr() as LPCSTR) };
    let mm_data = ManualMapLoaderData {
        pLoadLibraryA: unsafe {
            std::mem::transmute(GetProcAddress(
                kernel32,
                "LoadLibraryA\0".as_ptr() as LPCSTR,
            ))
        },
        pGetProcAddress: unsafe {
            std::mem::transmute(GetProcAddress(
                kernel32,
                "GetProcAddress\0".as_ptr() as LPCSTR,
            ))
        },
        pDllBaseAddr: base_addr_ex as HINSTANCE,
    };

    if unsafe {
        WriteProcessMemory(
            target_proc,
            base_addr_ex as LPVOID,
            &mm_data as *const ManualMapLoaderData as LPCVOID,
            std::mem::size_of::<ManualMapLoaderData>(),
            0 as *mut SIZE_T,
        )
    } == 0
    {
        println!("Unable to write loader data");
    }
    println!("Wrote loader data to target process");

    let loader_addr = unsafe {
        VirtualAllocEx(
            target_proc,
            0 as LPVOID,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if loader_addr as usize == 0 {
        println!("Unable to allocate data in target process for oader funtion");
    }
    println!(
        "Allocated 0x1000 bytes at 0x{:x} inside the target process for the loader function",
        loader_addr as usize
    );

    if unsafe {
        WriteProcessMemory(
            target_proc,
            loader_addr,
            loader as LPCVOID,
            0x1000,
            0 as *mut SIZE_T,
        )
    } == 0
    {
        println!("Unable to write loader function to the target process");
    }
    println!("Wrote loader function to the target process");

    if unsafe {
        CreateRemoteThreadEx(
            target_proc,
            0 as LPSECURITY_ATTRIBUTES,
            0,
            std::mem::transmute(loader_addr),
            base_addr_ex as LPVOID,
            0,
            0 as LPPROC_THREAD_ATTRIBUTE_LIST,
            0 as LPDWORD,
        )
    } == INVALID_HANDLE_VALUE
    {
        println!("Unable to create remote thread inside the target process");
    }
    println!("Created remote thread inside the target process");

    return true;
}

unsafe extern "system" fn loader(pmm_data: *mut ManualMapLoaderData) {
    if pmm_data as usize == 0 {
        return;
    }

    let _LoadLibraryA = (*pmm_data).pLoadLibraryA;
    let _GetProcAddress = &(*pmm_data).pGetProcAddress;
    let base_addr = pmm_data as *const u8;

    let dos_header: &IMAGE_DOS_HEADER = &*(base_addr as *const IMAGE_DOS_HEADER);
    let nt_header = &*(base_addr.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
    let optional_header = &nt_header.OptionalHeader;
    let file_header = &nt_header.FileHeader;

    let _DllMain: f_DllMain =
        std::mem::transmute(base_addr.add(optional_header.AddressOfEntryPoint as usize));

    let loc_delta = base_addr as u64 - optional_header.ImageBase;
    if loc_delta != 0 {
        if optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size == 0 {
            return;
        }

        let mut preloc_data: *mut IMAGE_BASE_RELOCATION = base_addr.add(
            optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress
                as usize,
        ) as *mut IMAGE_BASE_RELOCATION;
        let reloc_data = &*preloc_data;

        while reloc_data.VirtualAddress != 0 {
            let number_of_entries = (reloc_data.SizeOfBlock as usize
                - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                / std::mem::size_of::<WORD>();
            let mut prelative_info = preloc_data.add(1) as *const WORD;

            for i in 0..number_of_entries {
                #[cfg(target_pointer_width = "64")]
                if (*prelative_info >> 0x0C) == IMAGE_REL_BASED_DIR64 {
                    let pPatch = base_addr
                        .add(reloc_data.VirtualAddress as usize)
                        .add((*prelative_info & 0xFFF) as usize)
                        as *mut uintptr_t;
                    *pPatch += loc_delta as usize;
                }

                #[cfg(target_pointer_width = "32")]
                if (*prelative_info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW {
                    let pPatch = base_addr
                        .add(reloc_data.VirtualAddress as usize)
                        .add((*prelative_info & 0xFFF) as usize)
                        as *mut uintptr_t;
                    *pPatch += loc_delta as usize;
                }
                prelative_info = prelative_info.add(1);
            }

            preloc_data = (preloc_data as *mut u8).add(reloc_data.SizeOfBlock as usize)
                as *mut IMAGE_BASE_RELOCATION;
        }
    }

    if optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].Size != 0 {
        let mut pimport_desc = base_addr.add(
            optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress
                as usize,
        ) as *const IMAGE_IMPORT_DESCRIPTOR;
        let mut import_desc = &*pimport_desc;

        while import_desc.Name != 0 {
            let szModule = base_addr.add(import_desc.Name as usize) as *const i8;

            let loaded_module = _LoadLibraryA(szModule);

            let originalFirstThunk =
                unsafe { *(&import_desc.u as *const IMAGE_IMPORT_DESCRIPTOR_u as *const usize) };
            let mut pThunk = base_addr.add(originalFirstThunk) as *mut uintptr_t;

            let mut pFunc = base_addr.add(import_desc.FirstThunk as usize) as *mut uintptr_t;

            if pThunk as usize != 0 {
                pThunk = pFunc;
            }

            while *pThunk != 0 {
                #[cfg(target_pointer_width = "64")]
                if ((*pThunk as u64) & IMAGE_ORDINAL_FLAG64) != 0 {
                    *pFunc =
                        _GetProcAddress(loaded_module, (*pThunk & 0xFFFF) as *const i8) as usize;
                } else {
                    let import_name = base_addr.add(*pThunk) as *const IMAGE_IMPORT_BY_NAME;
                    *pFunc =
                        _GetProcAddress(loaded_module, &(*import_name).Name[0] as LPCSTR) as usize;
                }

                #[cfg(target_pointer_width = "32")]
                if ((*pThunk as u64) & IMAGE_ORDINAL_FLAG32) != 0 {
                    *pFunc =
                        _GetProcAddress(loaded_module, (*pThunk & 0xFFFF) as *const i8) as usize;
                } else {
                    let import_name = base_addr.add(*pThunk) as *const IMAGE_IMPORT_BY_NAME;
                    *pFunc =
                        _GetProcAddress(loaded_module, &(*import_name).Name[0] as LPCSTR) as usize;
                }

                pThunk = pThunk.add(1);
                pFunc = pFunc.add(1);
            }
            pimport_desc = pimport_desc.add(1);
            import_desc = &*pimport_desc;
        }
    }

    if optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize].Size != 0 {
        let pTls_dir = base_addr.add(
            optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize].VirtualAddress
                as usize,
        ) as *const IMAGE_TLS_DIRECTORY;

        let mut pTls_callback = (*pTls_dir).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;

        while pTls_callback as usize != 0
        {
            match *pTls_callback {
                Some(callback) => callback(base_addr as PVOID, DLL_PROCESS_ATTACH, 0 as PVOID),
                None => break,
            }
            pTls_callback = pTls_callback.add(1);
        }
    }

    _DllMain(base_addr as HMODULE, DLL_PROCESS_ATTACH, 0 as PVOID);
}
