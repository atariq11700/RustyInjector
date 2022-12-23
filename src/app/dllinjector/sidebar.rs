use egui::{SidePanel, Frame, Color32, Context, ComboBox, Widget, WidgetText};
use winapi::um::tlhelp32::PROCESSENTRY32;

use super::{processeslist::sz_exe_to_string, DllInejctorApp};




pub struct Sidebar {
    state: State,
}

struct State {
    injection_type: InjectionTypes,
    selected_process: Option<PROCESSENTRY32>
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
            InjectionTypes::Kernel => "Kernel"

        }
    }
}

impl Sidebar {
    pub fn new() -> Sidebar {
        return Sidebar { 
            state: State { 
                injection_type: InjectionTypes::Native,
                selected_process: None
            }
        }
    }
    pub fn show(&mut self, ctx: &egui::Context) -> () {
        SidePanel::left("Left SidePanel")
            .frame(Frame::default()
                .fill(Color32::LIGHT_BLUE))
            .show(ctx, |ui| {
                ui.label("Injection Options");
                ui.label(match self.state.selected_process {
                    Some(proc) => sz_exe_to_string(proc.szExeFile),
                    None => "No Process Selected".to_string()
                });
                ComboBox::from_label("Select Inection Type")
                    .selected_text(&*self.state.injection_type.to_string())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.state.injection_type, 
                            InjectionTypes::Native, 
                            InjectionTypes::Native.to_string()
                        );
                        ui.selectable_value(
                            &mut self.state.injection_type, 
                            InjectionTypes::ManualMap, 
                            InjectionTypes::ManualMap.to_string()
                        )
                    })
            });
        
    }
}