fn main() {
    for i in 0.. {
        println!("Count: {i}");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
