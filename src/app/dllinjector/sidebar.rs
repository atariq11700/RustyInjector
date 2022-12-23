use egui::{Color32, ComboBox, Context, Frame, SidePanel, Widget, WidgetText};
use winapi::um::tlhelp32::PROCESSENTRY32;

use super::{processeslist::sz_exe_to_string, AppState, DllInejctorApp};

pub struct Sidebar {
    injection_type: InjectionTypes,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum InjectionTypes {
    Native,
    ManualMap,
    Kernel,
}

impl InjectionTypes {
    fn to_string(&self) -> &str {
        match self {
            InjectionTypes::Native => "Native",
            InjectionTypes::ManualMap => "Manual Map",
            InjectionTypes::Kernel => "Kernel",
        }
    }
}

impl Sidebar {
    pub fn new() -> Sidebar {
        return Sidebar {
            injection_type: InjectionTypes::Native,
        };
    }
    pub fn show(&mut self, ctx: &egui::Context, app_state: &mut AppState) -> () {
        SidePanel::left("Left SidePanel")
            .frame(Frame::default().fill(Color32::LIGHT_BLUE))
            .show(ctx, |ui| {
                ui.label("Injection Options");
                ui.label(format!(
                    "Selected Process: {}",
                    match app_state.selected_process {
                        Some(proc) => sz_exe_to_string(proc.szExeFile),
                        _ => "None".to_string(),
                    }
                ));
                ComboBox::from_label("Select Inection Type")
                    .selected_text(&*self.injection_type.to_string())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.injection_type,
                            InjectionTypes::Native,
                            InjectionTypes::Native.to_string(),
                        );
                        ui.selectable_value(
                            &mut self.injection_type,
                            InjectionTypes::ManualMap,
                            InjectionTypes::ManualMap.to_string(),
                        )
                    })
            });
    }
}
