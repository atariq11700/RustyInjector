mod dllinjector;
mod utils;

fn main() {
    #[cfg(not(debug_assertions))]
    let options = eframe::NativeOptions {
        icon_data: Some(utils::files::load_icon("res/icon.png")),
        ..Default::default()
    };

    #[cfg(debug_assertions)]
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "Rusty Injector",
        options,
        Box::new(|cc| {
            return Box::new(match cc.storage {
                Some(_) => dllinjector::DllInejctorApp::load(cc),
                None => dllinjector::DllInejctorApp::new(cc),
            });
        }),
    );
}
