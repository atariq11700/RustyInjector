mod app;

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native("Dll Injector", options, Box::new(|cc| { 
        return Box::new(app::DllInejctorApp::new(cc));
    }));
}
