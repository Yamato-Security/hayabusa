use std::{env, path::PathBuf};

use clap_complete::{generate_to, Generator, Shell};
use dialoguer::Select;

pub fn auto_complete(app: &mut clap::Command, output_path: Option<&PathBuf>) {
    let shell = select_shell();
    print_completer(shell, app, output_path);
}

fn select_shell() -> Shell {
    let items: Vec<Shell> = vec![Shell::Bash, Shell::Elvish, Shell::Fish, Shell::PowerShell];

    let selection = Select::new()
        .with_prompt("Which shell are you using?")
        .items(&items)
        .interact()
        .unwrap();

    items[selection]
}
fn print_completer<G: Generator>(
    generator: G,
    app: &mut clap::Command,
    output_path: Option<&PathBuf>,
) {
    let mut name = "auto-complete".to_string();
    if output_path.is_some() {
        name = output_path.unwrap().to_str().unwrap().to_string();
    }
    let out_dir: PathBuf = env::current_dir().expect("can't get current directory");

    let _ = generate_to(generator, app, name, out_dir);
}
