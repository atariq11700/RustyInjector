mod components;
mod injectionmethods;
mod utils;


use components::processeslist::ProcessesList;
use components::sidebar::Sidebar;
use eframe::CreationContext;
use winapi::um::tlhelp32::PROCESSENTRY32;

pub struct DllInejctorApp {
    sidebar: Sidebar,
    process_list: ProcessesList,
    state: AppState,
}

struct AppState {
    selected_process: Option<PROCESSENTRY32>,
}

impl AppState {
    fn new() -> AppState {
        return AppState {
            selected_process: None,
        };
    }
}

impl DllInejctorApp {
    pub fn new(_creation_contex: &CreationContext) -> DllInejctorApp {
        return DllInejctorApp {
            sidebar: Sidebar::new(),
            process_list: ProcessesList::new(),
            state: AppState::new(),
        };
    }
}

impl eframe::App for DllInejctorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.sidebar.show(ctx, &mut self.state);
        self.process_list.show(ctx, &mut self.state);
    }
}
