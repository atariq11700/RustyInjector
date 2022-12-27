use winapi::{
    shared::ntdef::FALSE,
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        processthreadsapi::OpenProcess,
        tlhelp32::PROCESSENTRY32,
        winnt::{HANDLE, PROCESS_ALL_ACCESS},
    },
};

use crate::dllinjector::utils;

pub fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let dll_data = utils::files::is_valid_dll(dll_path);
    if !dll_data.len() > 0 {
        println!("Unable to read dll");
        return false;
    }

    unsafe {
        let target_proc: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE as i32, proc.th32ModuleID);
        
        if (target_proc == INVALID_HANDLE_VALUE) {
            println!("Unable to open target process");
            return false;
        }
    }

    return false;
}
