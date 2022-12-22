use egui::{SidePanel, Frame, Color32, Context, ComboBox, Widget, WidgetText};




pub struct Sidebar {
    state: State,
}

struct State {
    injection_type: InjectionTypes
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum InjectionTypes {
    Native,
    ManualMap,
}

impl InjectionTypes {
    fn to_string(&self) -> &str {
        match self {
            InjectionTypes::Native => "Native",
            InjectionTypes::ManualMap => "Manual Map",
        }
    }
}

impl Sidebar {
    pub fn new() -> Sidebar {
        return Sidebar { 
            state: State { 
                injection_type: InjectionTypes::Native
            }
        }
    }
    pub fn show(&mut self, ctx: &egui::Context) -> () {
        SidePanel::left("Left SidePanel")
            .frame(Frame::default()
                .fill(Color32::LIGHT_BLUE))
            .show(ctx, |ui| {
                ui.label("sidebar");
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