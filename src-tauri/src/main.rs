// On Windows, suppress the console window that would otherwise attach to the
// release binary (debug builds keep it for logging).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    simplepass_lib::run();
}
