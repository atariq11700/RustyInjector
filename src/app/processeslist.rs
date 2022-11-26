use egui::{CentralPanel,Frame, Color32, Context};


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
            ui.label("processes list");
        });
    }
}