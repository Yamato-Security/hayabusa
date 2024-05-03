use clap_complete::{generate, Generator};

pub fn print_completer<G: Generator>(generator: G, app: &mut clap::Command) {
    let name = app.get_name().to_owned();

    generate(generator, app, name, &mut std::io::stdout());
}