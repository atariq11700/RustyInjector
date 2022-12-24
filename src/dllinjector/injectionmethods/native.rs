
use winapi::{
    um::{
        tlhelp32::PROCESSENTRY32, 
        processthreadsapi::OpenProcess, 
        winnt::{
            HANDLE, 
            PROCESS_ALL_ACCESS
        }, 
        handleapi::INVALID_HANDLE_VALUE,
    }, shared::ntdef::FALSE, 
};

pub unsafe fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let hTargetProc: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE as i32, proc.th32ModuleID);

    if (hTargetProc == INVALID_HANDLE_VALUE) {
        println!("Unable to open target process");
        return false;
    }

    return false;
}