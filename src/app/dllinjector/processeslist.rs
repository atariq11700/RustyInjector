use egui::{CentralPanel,Frame, Color32, Context, ScrollArea, Ui};
use winapi::{
    um::{
        tlhelp32::{PROCESSENTRY32, CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, Process32First, Process32Next}, 
        handleapi::CloseHandle
    }, 
    shared::{
        ntdef::{HANDLE, NULL, CHAR}, 
        minwindef::{MAX_PATH, DWORD}
    }
};

pub struct ProcessesList<'a> {
    context: &'a Context,
    panel: CentralPanel
}

impl ProcessesList<'_> {
    pub fn new<'a>(context: &'a Context) -> ProcessesList<'a> {
        return ProcessesList {
            context: context,
            panel: CentralPanel::default()
        }
    }
    pub fn show(mut self) -> () {
        self.panel
        .frame(Frame::default().fill(Color32::LIGHT_GREEN))
        .show(self.context, |ui| {
            ScrollArea::vertical()
            .show(ui, |ui| {
                let procs = get_processes();
                match procs {
                    Some(procs) => render_processes(ui, procs),
                    None => println!("Unable to get list of processes")
                }
            })
        });
    }
}

fn get_processes() -> Option<Vec<PROCESSENTRY32>> {
    let mut procs: Vec<PROCESSENTRY32> = Vec::new();
    let mut proc_entry = PROCESSENTRY32::default();
    proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;

    unsafe {    
        let proc_snap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL as DWORD);

        if (Process32First(proc_snap, &mut proc_entry) == 0) {
            CloseHandle(proc_snap);
            return None;
        }

        procs.push(proc_entry);

        while (Process32Next(proc_snap, &mut proc_entry) != 0) {
            procs.push(proc_entry);
        }

        CloseHandle(proc_snap);
        
    };

    
    return Some(procs);
}

fn render_processes(ui: &mut Ui, procs: Vec<PROCESSENTRY32>) {
    for proc in procs {
        ui.label(format!("[{}] - {}", proc.th32ProcessID, szExeToString(proc.szExeFile)));
    }
}

fn szExeToString(arr: [CHAR; MAX_PATH]) -> String {
    let mut byte_vec: Vec<u8> = Vec::new();
    for byte in arr {
        if (byte == 0) {
            break
        }
        byte_vec.push(byte as u8)
    }
    return String::from_utf8(byte_vec).unwrap();
}

