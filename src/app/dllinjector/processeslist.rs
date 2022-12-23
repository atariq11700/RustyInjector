use egui::{CentralPanel, Color32, Frame, RichText, ScrollArea, Ui};
use winapi::{
    shared::{
        minwindef::{DWORD, MAX_PATH},
        ntdef::{CHAR, HANDLE, NULL},
    },
    um::{
        handleapi::CloseHandle,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
    },
};

use super::AppState;

pub struct ProcessesList {}

impl ProcessesList {
    pub fn new() -> ProcessesList {
        return ProcessesList {};
    }

    pub fn show(&mut self, ctx: &egui::Context, app_state: &mut AppState) {
        CentralPanel::default()
            .frame(Frame::default().fill(Color32::LIGHT_GREEN))
            .show(ctx, |ui| {
                ScrollArea::vertical().show(ui, |ui| {
                    let procs = get_processes();
                    match procs {
                        Some(procs) => render_processes(ui, procs, app_state),
                        None => println!("Unable to get list of processes"),
                    }
                })
            });
    }
}

fn render_processes(ui: &mut Ui, procs: Vec<PROCESSENTRY32>, app_state: &mut AppState) {
    for proc in procs {
        let button_text = format!(
            "[{:>12}] - {:<30}",
            proc.th32ProcessID,
            sz_exe_to_string(proc.szExeFile)
        );
        let button_color = match app_state.selected_process {
            Some(selected_proc) => match selected_proc.th32ProcessID == proc.th32ProcessID {
                true => Color32::RED,
                false => Color32::BLUE,
            },
            None => Color32::BLUE,
        };
        let button = ui.button(RichText::new(button_text).color(button_color));

        if button.clicked() {
            let name = sz_exe_to_string(proc.szExeFile);
            println!("Button Clicked {name}");
            app_state.selected_process = Some(proc);
        }
    }
}

fn get_processes() -> Option<Vec<PROCESSENTRY32>> {
    let mut procs: Vec<PROCESSENTRY32> = Vec::new();
    let mut proc_entry = PROCESSENTRY32::default();
    proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;

    unsafe {
        let proc_snap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL as DWORD);

        match Process32First(proc_snap, &mut proc_entry) {
            0 => {
                CloseHandle(proc_snap);
                return None;
            }
            _ => {
                procs.push(proc_entry);
            }
        }

        loop {
            match Process32Next(proc_snap, &mut proc_entry) {
                0 => {
                    CloseHandle(proc_snap);
                    break;
                }
                _ => {
                    procs.push(proc_entry);
                }
            }
        }
    };

    return Some(procs);
}

pub fn sz_exe_to_string(arr: [CHAR; MAX_PATH]) -> String {
    let mut byte_vec: Vec<u8> = Vec::new();
    for byte in arr {
        if byte == 0 {
            break;
        }
        byte_vec.push(byte as u8)
    }
    return String::from_utf8(byte_vec).unwrap_or("Error Getting Process Name".to_string());
}
