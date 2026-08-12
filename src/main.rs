#![forbid(unsafe_code)]

mod cli;

fn main() -> anyhow::Result<()> {
    cli::run()
}
