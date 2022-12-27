use winapi::{
    shared::ntdef::FALSE,
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        processthreadsapi::OpenProcess,
        tlhelp32::PROCESSENTRY32,
        winnt::{HANDLE, PROCESS_ALL_ACCESS},
    },
};

pub unsafe fn inject(proc: PROCESSENTRY32, dll_path: String) -> bool {
    let hTargetProc: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE as i32, proc.th32ModuleID);

    if (hTargetProc == INVALID_HANDLE_VALUE) {
        println!("Unable to open target process");
        return false;
    }

    return false;
}
