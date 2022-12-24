use std::ptr::null;

use winapi::um::fileapi::GetFileAttributesA;
use egui::RichText;
use std::fs;

pub fn isValidDll(dll_path: String) -> Vec<i8> {
    println!("Checking that {dll_path} exists");

    fs::try_exists(path)
}