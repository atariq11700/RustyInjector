extern crate winres;

fn main() {
    #[cfg(not(debug_assertions))]
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("res/icon.ico");
        res.compile().unwrap();
    }
}
