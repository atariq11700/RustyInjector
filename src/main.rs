mod dllinjector;

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Dll Injector",
        options,
        Box::new(|cc| {
            return Box::new(match cc.storage {
                Some(_) => dllinjector::DllInejctorApp::load(cc),
                None => dllinjector::DllInejctorApp::new(cc)
            });
        }),
    );
}
