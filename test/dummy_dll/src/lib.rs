use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};

#[no_mangle] // call it "DllMain" in the compiled DLL
pub extern "stdcall" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lpv_reserved: LPVOID,
) -> i32 {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            println!("Hi from dll");
            std::thread::sleep(std::time::Duration::from_secs(5));
            // std::process::exit(0);
            return true as i32;
        }
        DLL_PROCESS_DETACH => {
            println!("Goodbye from dll");
            return true as i32;
        }
        _ => true as i32,
    }
}
