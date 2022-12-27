use crate::{dllinjector::components::processeslist::sz_exe_to_string, dllinjector::AppState};
use egui::{Color32, ComboBox, Frame, RichText, SidePanel};

pub struct Sidebar {
    injection_type: InjectionTypes,
    injection_msg: Option<RichText>,
    dll_path: Option<String>,
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
            injection_msg: None,
            dll_path: None,
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
                    });
                if ui.button("Inject").clicked() {
                    self.injection_msg = match app_state.selected_process {
                        Some(proc) => match self.injection_type {
                            InjectionTypes::Native => {
                                Some(RichText::new("Injecting with native").color(Color32::GREEN))
                            }
                            InjectionTypes::ManualMap => {
                                Some(RichText::new("Injecting with mm").color(Color32::GREEN))
                            }
                            _ => Some(RichText::new("Unknown Injection Type").color(Color32::RED)),
                        },
                        _ => Some(RichText::new("No Selected Process").color(Color32::RED)),
                    };
                    crate::dllinjector::utils::files::isValidDll("test/dlltobeinjected.dll");
                };

                if !self.injection_msg.is_none() {
                    ui.label(self.injection_msg.as_ref().unwrap().clone());
                }
            });
    }
}
