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

pub struct AppState {
    selected_process: Option<PROCESSENTRY32>,
    save_state: bool,
}

impl AppState {
    fn new() -> AppState {
        return AppState {
            selected_process: None,
            save_state: false,
        };
    }
    fn save(&self, storage: &mut dyn eframe::Storage) {
        storage.set_string("appstate_save_state", self.save_state.to_string())
    }
    fn load(storage: &dyn eframe::Storage) -> AppState {
        AppState {
            selected_process: None,
            save_state: match storage.get_string("appstate_save_state") {
                Some(value) => value.trim().parse().unwrap(),
                _ => false,
            },
        }
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

    pub fn load(creation_context: &CreationContext) -> DllInejctorApp {
        let storage = creation_context.storage.unwrap();
        let prev_state = AppState::load(storage);

        match prev_state.save_state {
            true => DllInejctorApp {
                sidebar: Sidebar::load(storage),
                process_list: ProcessesList::load(storage),
                state: prev_state,
            },
            false => DllInejctorApp::new(creation_context),
        }
    }
}

impl eframe::App for DllInejctorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.sidebar.show(ctx, &mut self.state);
        self.process_list.show(ctx, &mut self.state);
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.state.save(storage);
        self.sidebar.save(storage);
        self.process_list.save(storage);
    }
}
