use std::ptr::addr_of;

use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T,
        minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPCVOID, LPVOID, WORD},
        ntdef::{HANDLE, LPCSTR},
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::OpenProcess,
        tlhelp32::PROCESSENTRY32,
        winnt::{
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
            IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER, PROCESS_ALL_ACCESS,
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

//todo: broken
fn image_first_section(pnt_header: PIMAGE_NT_HEADERS) -> PIMAGE_SECTION_HEADER {
    return unsafe {
        pnt_header
            .add(memoffset::offset_of!(IMAGE_NT_HEADERS, OptionalHeader))
            .add(
                (*pnt_header as IMAGE_NT_HEADERS)
                    .FileHeader
                    .SizeOfOptionalHeader as usize,
            ) as PIMAGE_SECTION_HEADER
    };
}

pub fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let dll_data = utils::files::is_valid_dll(dll_path.clone());
    if !(dll_data.len() > 0) {
        println!("Unable to read dll");
        return false;
    }

    let target_proc: HANDLE =
        unsafe { OpenProcess(PROCESS_ALL_ACCESS, false as BOOL, proc.th32ProcessID) };

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
        base_addr_ex = unsafe {
            VirtualAllocEx(
                target_proc,
                0 as LPVOID,
                optional_header.SizeOfImage as SIZE_T,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };
    }

    if base_addr_ex as usize == 0 {
        println!("Unable to allocate memory inside target process for dll");
        unsafe { CloseHandle(target_proc) };
    }

    let mut section_header =
        image_first_section(&nt_header as *const IMAGE_NT_HEADERS as PIMAGE_NT_HEADERS);

    for i in 0..file_header.NumberOfSections {
        unsafe {
            if (*section_header).SizeOfRawData > 0 {
                let name = (*section_header).Name;
                if WriteProcessMemory(
                    target_proc,
                    base_addr_ex.add((*section_header).VirtualAddress as usize),
                    dll_data
                        .as_ptr()
                        .add((*section_header).PointerToRawData as usize)
                        as LPCVOID,
                    (*section_header).SizeOfRawData as SIZE_T,
                    0 as *mut usize,
                ) == 0
                {
                    println!("Unable to map section {name:?} into target process memory");
                    CloseHandle(target_proc);
                    VirtualFreeEx(
                        target_proc,
                        base_addr_ex,
                        optional_header.SizeOfImage as SIZE_T,
                        MEM_FREE,
                    );
                    return false;
                }
                println!(
                    "Mapped dll section {:?} {} into target process as 0x{:x}",
                    name,
                    (*section_header).SizeOfRawData,
                    base_addr_ex.add((*section_header).VirtualAddress as usize) as usize
                );
            }
            section_header =
                section_header.add(std::mem::size_of::<IMAGE_SECTION_HEADER>() as usize);
        }
    }

    return false;
}
