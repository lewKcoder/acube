use a3::prelude::*;

#[derive(A3Error, Debug)]
pub enum BadError {
    #[a3(status = 500)]
    MissingMessage,
}

fn main() {}
