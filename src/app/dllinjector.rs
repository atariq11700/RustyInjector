mod sidebar;
mod processeslist;

use eframe::CreationContext;

use sidebar::Sidebar;
use processeslist::ProcessesList;


pub struct DllInejctorApp {
    sidebar: Sidebar,
    process_list: ProcessesList,
}

impl DllInejctorApp {
    pub fn new(_creation_contex: &CreationContext) -> DllInejctorApp {
        return DllInejctorApp {
            sidebar: Sidebar::new(),
            process_list: ProcessesList::new()
        }
    }
}

impl eframe::App for DllInejctorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.sidebar.show(ctx);
        self.process_list.show(ctx);
    }
}