use egui::{SidePanel, Frame, Color32, Context};




pub struct Sidebar {
    state: State,
}

struct State {

}

impl Sidebar {
    pub fn new() -> Sidebar {
        return Sidebar { 
            state: State {}
        }
    }
    pub fn show(&self, ctx: &egui::Context) -> () {
        SidePanel::left("Left SidePanel")
            .frame(Frame::default().fill(Color32::LIGHT_BLUE))
            .show(ctx, |ui| {
                ui.label("sidebar")
            });
    }
}