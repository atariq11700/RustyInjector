use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T,
        minwindef::{FALSE, LPDWORD, LPVOID},
        ntdef::LPCSTR,
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        minwinbase::{LPSECURITY_ATTRIBUTES},
        processthreadsapi::{CreateRemoteThreadEx, OpenProcess, LPPROC_THREAD_ATTRIBUTE_LIST},
        tlhelp32::PROCESSENTRY32,
        winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS},
    },
};

use crate::dllinjector::utils;

pub fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let dll_data = utils::files::is_valid_dll(dll_path.clone());
    if !(dll_data.len() > 0) {
        println!("Unable to read dll");
        return false;
    }

    let target_proc: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc.th32ProcessID) };

    if target_proc == INVALID_HANDLE_VALUE {
        println!("Unable to open target process");
        return false;
    }

    let addr: LPVOID = unsafe {
        VirtualAllocEx(
            target_proc,
            0 as LPVOID,
            (&dll_path).len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if (addr as usize) == 0 {
        println!("Unable to allocte memory inside target process");
        unsafe { CloseHandle(target_proc) };
        return false;
    }

    let mut _f: SIZE_T = 0;
    if unsafe {
        WriteProcessMemory(
            target_proc,
            addr,
            dll_path.as_ptr() as *const c_void,
            dll_path.len(),
            &mut _f as *mut SIZE_T,
        )
    } == 0
    {
        println!("Unable to write dll path to target process");
        unsafe { CloseHandle(target_proc) };
        return false;
    }

    let new_thread = unsafe {
        CreateRemoteThreadEx(
            target_proc,
            0 as LPSECURITY_ATTRIBUTES,
            0,
            std::mem::transmute(GetProcAddress(
                GetModuleHandleA("kernel32.dll\0".as_ptr() as LPCSTR),
                "LoadLibraryA\0".as_ptr() as LPCSTR,
            )),
            addr,
            0,
            0 as LPPROC_THREAD_ATTRIBUTE_LIST,
            0 as LPDWORD,
        )
    };

    if new_thread == INVALID_HANDLE_VALUE {
        println!("Unable to create a remote thread");
        unsafe { CloseHandle(target_proc) };
        return false;
    }

    unsafe {
        CloseHandle(new_thread);
        CloseHandle(target_proc);
    };

    return true;
}
