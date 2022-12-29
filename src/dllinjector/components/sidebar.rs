use crate::dllinjector::{components::processeslist::sz_exe_to_string, injectionmethods, AppState};
use egui::{
    Align2, Color32, ComboBox, Frame, Id, LayerId, Order, RichText, SidePanel, TextStyle, Ui,
};
use std::fmt::Write;

pub struct Sidebar {
    injection_type: InjectionTypes,
    injection_msg: Option<RichText>,
    dll_path: Option<String>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum InjectionTypes {
    Native,
    ManualMap,
    _Kernel,
}

impl InjectionTypes {
    fn to_string(&self) -> &str {
        match self {
            InjectionTypes::Native => "Native",
            InjectionTypes::ManualMap => "Manual Map",
            InjectionTypes::_Kernel => "Kernel",
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

                self.injection_selection(ui);
                self.file_selector(ui);
                self.file_dropper(ctx);
                self.injection_button(app_state, ui);

                if !self.injection_msg.is_none() {
                    ui.label(self.injection_msg.as_ref().unwrap().clone());
                }
            });
    }

    fn injection_selection(&mut self, ui: &mut Ui) {
        ComboBox::from_label("Select Injection Type")
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
    }

    fn file_selector(&mut self, ui: &mut Ui) {
        if let Some(picked_path) = &self.dll_path {
            ui.horizontal(|ui| {
                ui.label("Picked file:");
                ui.monospace(picked_path);
            });
        }
        if ui.button("Open file…").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .add_filter("dll file", &["dll"])
                .pick_file()
            {
                self.dll_path = Some(path.display().to_string());
            }
        }
    }

    fn file_dropper(&mut self, ctx: &egui::Context) {
        if !ctx.input().raw.hovered_files.is_empty() {
            let mut text = "Dropping files:\n".to_owned();
            if ctx.input().raw.hovered_files.len() > 1 {
                write!(text, "Please only drop a singular dll file\n").ok();
            } else {
                let file = &ctx.input().raw.hovered_files[0];
                if file.path.as_ref().unwrap().extension().unwrap().clone() != "dll" {
                    write!(text, "Please only drop a dll file\n").ok();
                } else {
                    if let Some(path) = &file.path {
                        write!(text, "\n{}", path.display()).ok();
                    } else if !file.mime.is_empty() {
                        write!(text, "\n{}", file.mime).ok();
                    } else {
                        text += "\n???";
                    }
                }
            }

            let painter =
                ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("file_drop_target")));

            let screen_rect = ctx.input().screen_rect();
            painter.rect_filled(screen_rect, 0.0, Color32::from_black_alpha(192));
            painter.text(
                screen_rect.center(),
                Align2::CENTER_CENTER,
                text,
                TextStyle::Heading.resolve(&ctx.style()),
                Color32::WHITE,
            );
        }

        if !ctx.input().raw.dropped_files.is_empty() {
            let dropped_files = ctx.input().raw.dropped_files.clone();
            if dropped_files.len() == 1 {
                if dropped_files[0].path.as_ref().unwrap().extension().unwrap() == "dll" {
                    self.dll_path = Some(
                        dropped_files[0]
                            .path
                            .as_ref()
                            .unwrap()
                            .display()
                            .to_string(),
                    );
                }
            }
        }
    }

    fn injection_button(&mut self, app_state: &AppState, ui: &mut Ui) {
        if ui.button("Inject").clicked() {
            self.injection_msg = match app_state.selected_process {
                Some(proc) => match self.injection_type {
                    InjectionTypes::Native => {
                        injectionmethods::native::inject(
                            proc,
                            self.dll_path.as_ref().unwrap().clone(),
                        );
                        Some(RichText::new("Injecting with native").color(Color32::GREEN))
                    }
                    InjectionTypes::ManualMap => {
                        injectionmethods::manualmap::inject(
                            proc,
                            self.dll_path.as_ref().unwrap().clone(),
                        );
                        Some(RichText::new("Injecting with mm").color(Color32::GREEN))
                    }
                    _ => Some(RichText::new("Unknown Injection Type").color(Color32::RED)),
                },
                _ => Some(RichText::new("No Selected Process").color(Color32::RED)),
            };
        };
    }
}
