mod dllinjector;
mod utils;

fn main() {
    let options = eframe::NativeOptions {
        icon_data: Some(utils::files::load_icon("res/icon.png")),
        ..Default::default()
    };

    eframe::run_native(
        "Dll Injector",
        options,
        Box::new(|cc| {
            return Box::new(match cc.storage {
                Some(_) => dllinjector::DllInejctorApp::load(cc),
                None => dllinjector::DllInejctorApp::new(cc),
            });
        }),
    );
}
