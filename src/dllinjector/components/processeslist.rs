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

use crate::dllinjector::AppState;

pub struct ProcessesList {
    filter_string: String,
}

impl ProcessesList {
    pub fn new() -> ProcessesList {
        return ProcessesList {
            filter_string: String::default(),
        };
    }

    pub fn show(&mut self, ctx: &egui::Context, app_state: &mut AppState) {
        CentralPanel::default()
            .frame(Frame::default().fill(Color32::LIGHT_GREEN))
            .show(ctx, |ui| {
                ui.text_edit_multiline(&mut self.filter_string);
                ScrollArea::vertical().show(ui, |ui| {
                    let procs = get_processes();
                    match procs {
                        Some(procs) => self.render_processes(ui, procs, app_state),
                        None => println!("Unable to get list of processes"),
                    }
                })
            });
    }

    fn render_processes(&self, ui: &mut Ui, procs: Vec<PROCESSENTRY32>, app_state: &mut AppState) {
        for proc in procs {
            let proc_name = sz_exe_to_string(proc.szExeFile);
            if !proc_name
                .to_ascii_lowercase()
                .starts_with(&self.filter_string)
            {
                continue;
            }
            let button_text = format!("[{:>12}] - {:<30}", proc.th32ProcessID, proc_name);
            let button_color = match app_state.selected_process {
                Some(selected_proc) => match selected_proc.th32ProcessID == proc.th32ProcessID {
                    true => Color32::GRAY,
                    false => Color32::GOLD,
                },
                None => Color32::GOLD,
            };
            let button = ui.button(RichText::new(button_text).color(button_color));

            if button.clicked() {
                println!("Button Clicked {proc_name}");
                app_state.selected_process = Some(proc);
            }
        }
    }

    pub fn save(&self, storage: &mut dyn eframe::Storage) {
        storage.set_string("pl_proc_filter", self.filter_string.clone());
    }

    pub fn load(storage: &dyn eframe::Storage) -> ProcessesList {
        ProcessesList {
            filter_string: storage.get_string("pl_proc_filter").unwrap_or_default(),
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
