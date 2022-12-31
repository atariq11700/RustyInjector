use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::{SIZE_T, ULONG_PTR},
        minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPCVOID, LPDWORD, LPVOID, WORD},
        ntdef::{HANDLE, LPCSTR},
    },
    um::{
        consoleapi::AllocConsole,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetProcAddress, LoadLibraryA},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        minwinbase::LPSECURITY_ATTRIBUTES,
        processthreadsapi::{CreateRemoteThreadEx, OpenProcess, LPPROC_THREAD_ATTRIBUTE_LIST},
        tlhelp32::PROCESSENTRY32,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER,
            IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SECTION_HEADER, MEM_COMMIT,
            MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PIMAGE_NT_HEADERS,
            PIMAGE_SECTION_HEADER, PROCESS_ALL_ACCESS,
        },
    },
};

use crate::utils;

type f_LoadLibraryA = unsafe extern "system" fn(lpLibraryFilename: LPCSTR) -> HINSTANCE;
type f_GetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;
type f_DllMain = unsafe extern "system" fn(
    hModule: HMODULE,
    dw_reason_for_call: DWORD,
    lpReserved: LPVOID,
) -> BOOL;

struct ManualMapLoaderData {
    pLoadLibraryA: f_LoadLibraryA,
    pGetProcAddress: f_GetProcAddress,
    pDllBaseAddr: HINSTANCE,
}

fn needs_reloc(reloc_info: WORD) -> bool {
    #[cfg(target_pointer_width = "64")]
    return (reloc_info >> 0x0C) == IMAGE_REL_BASED_DIR64;

    #[cfg(target_pointer_width = "32")]
    return (reloc_info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW;
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

    let dos_header: &IMAGE_DOS_HEADER = unsafe { &*(dll_data.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_header = unsafe {
        &*(dll_data
            .as_ptr()
            .add(dos_header.e_lfanew.try_into().unwrap()) as *const IMAGE_NT_HEADERS)
    };
    let optional_header = &nt_header.OptionalHeader;
    let file_header = &nt_header.FileHeader;

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

    let mm_data = ManualMapLoaderData {
        pLoadLibraryA: LoadLibraryA,
        pGetProcAddress: GetProcAddress,
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

extern "system" fn loader(pmm_data: *mut ManualMapLoaderData) {
    if pmm_data as usize == 0 {
        return;
    }

    let _LoadLibraryA = unsafe { (*pmm_data).pLoadLibraryA };
    let _GetProcAddress = unsafe { &(*pmm_data).pGetProcAddress };
    let base_addr = pmm_data as *const u8;
}
