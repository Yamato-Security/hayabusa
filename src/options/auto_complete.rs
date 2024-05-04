use clap_complete::{generate, Generator, Shell};
use dialoguer::Select;

pub fn select_shell() -> Shell {
    let items:Vec<Shell> = vec![Shell::Bash, Shell::Elvish, Shell::Fish, Shell::PowerShell, Shell::Zsh];

    let selection = Select::new()
        .with_prompt("Which shell are you using?")
        .items(&items)
        .interact()
        .unwrap();

    items[selection]
}
pub fn print_completer<G: Generator>(generator: G, app: &mut clap::Command) {
    let name = app.get_name().to_owned();

    generate(generator, app, name, &mut std::io::stdout());
}