use std::{io::Read, mem::size_of, ptr::null};

use std::fs;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_NT_HEADERS,
};

pub fn isValidDll(dll_path: &str) -> Vec<u8> {
    println!("Checking that {dll_path} exists");

    let file_res = fs::File::open(dll_path);

    if file_res.is_err() {
        println!("Unable to open/access {dll_path}");
        return Vec::new();
    }

    let mut file = file_res.unwrap();
    let file_metadata_res = file.metadata();

    if file_metadata_res.is_err() {
        println!("Unable to access {dll_path} metadata");
        return Vec::new();
    }

    let file_metadata = file_metadata_res.unwrap();
    if file_metadata.len() < size_of::<IMAGE_DOS_HEADER>().try_into().unwrap(){
        println!("{dll_path} has an invalid size");
        return Vec::new();
    }

    let mut file_contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_contents);

    let dos_header: IMAGE_DOS_HEADER =
        unsafe { (*(file_contents.as_ptr() as *const IMAGE_DOS_HEADER)) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        println!("{dll_path} is not a valid pe image");
        return Vec::new();
    }


    if file_metadata.len() < dos_header.e_lfanew.try_into().unwrap() {
        println!("{dll_path} has an invalid size");
        return Vec::new();
    }

    let nt_header = unsafe {
        (*(file_contents
            .as_ptr()
            .add(dos_header.e_lfanew.try_into().unwrap()) as *const IMAGE_NT_HEADERS))
    };
    let optional_header = nt_header.OptionalHeader;
    let file_header = nt_header.FileHeader;

    #[cfg(target_pointer_width = "64")]
    if file_header.Machine != IMAGE_FILE_MACHINE_AMD64 {
        println!("Host is 64bit and dll is not");
        return Vec::new();
    }

    #[cfg(target_pointer_width = "32")]
    if file_header.Machine != IMAGE_FILE_MACHINE_I386 {
        println!("Host is 32bit and dll is not");
        return Vec::new();
    }

    println!("Dll is valid");

    return file_contents;
}
