use std::{io::Read, ptr::null};

use egui::RichText;
use std::fs;
use winapi::um::{
    winnt::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS,
        IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER,
    },
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
    if file_metadata.len() < 0x1000 {
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

    let nt_header = unsafe {
        (*(file_contents
            .as_ptr()
            .add(dos_header.e_lfanew.try_into().unwrap()) as *const IMAGE_NT_HEADERS))
    };
    let optional_header = unsafe { (*(&nt_header.OptionalHeader as *const IMAGE_OPTIONAL_HEADER)) };
    let file_header = unsafe { (*(&nt_header.FileHeader as *const IMAGE_FILE_HEADER)) };

    let f = optional_header.CheckSum;
    let g = optional_header.ImageBase;
    let h = file_header.Machine;

    unsafe {
        for i in 0..10 {
            let byte = file_contents[i];
            let byte2 = *((&dos_header as *const IMAGE_DOS_HEADER as *const u8).add(i));
            print!("[{byte},{byte2}] ");
        }
    }
    println!("");
    println!("{f}");
    println!("{g}");
    println!("{h}");

    return Vec::new();
}
