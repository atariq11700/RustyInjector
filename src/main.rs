mod dllinjector;

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Dll Injector",
        options,
        Box::new(|cc| {
            return Box::new(dllinjector::DllInejctorApp::new(cc));
        }),
    );
}
