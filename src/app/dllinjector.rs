mod sidebar;
mod processeslist;

use eframe::CreationContext;

use sidebar::Sidebar;
use processeslist::ProcessesList;


pub struct DllInejctorApp;

impl DllInejctorApp {
    pub fn new(_creation_contex: &CreationContext) -> DllInejctorApp {
        return DllInejctorApp;
    }
}

impl eframe::App for DllInejctorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Sidebar::new(ctx).show();
        ProcessesList::new(ctx).show();
    }
}