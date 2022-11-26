use egui::{SidePanel, Frame, Color32, Context};


pub struct Sidebar<'a> {
    context: &'a Context,
    panel: SidePanel
}

impl Sidebar<'_> {
    pub fn new<'a>(context: &'a Context) -> Sidebar<'a> {
        return Sidebar {
            context: context,
            panel: SidePanel::left("left sidepanel")
        }
    }
    pub fn show(self) -> () {
        self.panel
        .frame(Frame::default().fill(Color32::LIGHT_BLUE))
        .show(self.context, |ui| {
            ui.label("sidebar");
        });
    }
}