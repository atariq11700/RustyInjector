use std::{io::Read, mem::size_of};

use std::fs;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_HEADERS,
};

pub fn is_valid_dll(dll_path: String) -> Vec<u8> {
    let file_name = &dll_path;
    let empty_vec: Vec<u8> = Vec::new();

    println!("Checking that {file_name} exists");

    let file_res = fs::File::open(&dll_path);

    if file_res.is_err() {
        println!("Unable to open/access {file_name}");
        return empty_vec;
    }

    let mut file = file_res.unwrap();
    let file_metadata_res = file.metadata();

    if file_metadata_res.is_err() {
        println!("Unable to access {file_name} metadata");
        return empty_vec;
    }

    let file_metadata = file_metadata_res.unwrap();
    if file_metadata.len() < size_of::<IMAGE_DOS_HEADER>().try_into().unwrap() {
        println!("{file_name} has an invalid size");
        return empty_vec;
    }

    let mut file_contents: Vec<u8> = Vec::new();
    if file.read_to_end(&mut file_contents).is_err() {
        println!("Unable to read dll");
        return empty_vec;
    }

    let dos_header: IMAGE_DOS_HEADER =
        unsafe { *(file_contents.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        println!("{file_name} is not a valid pe image");
        return empty_vec;
    }

    if file_metadata.len() < dos_header.e_lfanew.try_into().unwrap() {
        println!("{file_name} has an invalid size");
        return empty_vec;
    }

    let nt_header = unsafe {
        *(file_contents
            .as_ptr()
            .add(dos_header.e_lfanew.try_into().unwrap()) as *const IMAGE_NT_HEADERS)
    };
    let _optional_header = nt_header.OptionalHeader;
    let file_header = nt_header.FileHeader;

    #[cfg(target_pointer_width = "64")]
    if file_header.Machine != IMAGE_FILE_MACHINE_AMD64 {
        println!("Host is 64bit and dll is not");
        return empty_vec;
    }

    #[cfg(target_pointer_width = "32")]
    if file_header.Machine != IMAGE_FILE_MACHINE_I386 {
        println!("Host is 32bit and dll is not");
        return null;
    }

    println!("Dll is valid");

    return file_contents;
}

#[allow(dead_code)]
pub fn load_icon(path: &str) -> eframe::IconData {
    let (icon_rgba, icon_width, icon_height) = {
        let image = image::open(path)
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    eframe::IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
}
