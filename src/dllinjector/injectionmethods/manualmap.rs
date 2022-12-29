use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPVOID, WORD},
        ntdef::{LPCSTR, HANDLE}, basetsd::SIZE_T,
    },
    um::{
        handleapi::{INVALID_HANDLE_VALUE, CloseHandle},
        memoryapi::VirtualAllocEx,
        processthreadsapi::OpenProcess,
        tlhelp32::PROCESSENTRY32,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS, IMAGE_SECTION_HEADER
        },
    },
};

use crate::dllinjector::utils;

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

fn image_first_section(nt_header: IMAGE_NT_HEADERS) -> IMAGE_SECTION_HEADER {
    
}

pub fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let dll_data = utils::files::is_valid_dll(dll_path.clone());
    if !(dll_data.len() > 0) {
        println!("Unable to read dll");
        return false;
    }

    let target_proc: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false as BOOL, proc.th32ProcessID) };

    if target_proc == INVALID_HANDLE_VALUE {
        println!("Unable to open target process");
        return false;
    }

    let dos_header: IMAGE_DOS_HEADER = unsafe { *(dll_data.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_header = unsafe {
        *(dll_data
            .as_ptr()
            .add(dos_header.e_lfanew.try_into().unwrap()) as *const IMAGE_NT_HEADERS)
    };
    let optional_header = nt_header.OptionalHeader;
    let file_header = nt_header.FileHeader;

    let mut base_addr_ex = unsafe {
        VirtualAllocEx(
            target_proc,
            optional_header.ImageBase as LPVOID,
            optional_header.SizeOfImage as SIZE_T,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if base_addr_ex as usize == 0 {
        base_addr_ex =  unsafe {VirtualAllocEx(
            target_proc,
            0 as LPVOID,
            optional_header.SizeOfImage as SIZE_T,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )};
    }

    if base_addr_ex as usize == 0 {
        println!("Unable to allocate memory inside target process for dll");
        unsafe { CloseHandle(target_proc)};
    }

    let section_header = image_first_section(nt_header);
    

    return false;
}
