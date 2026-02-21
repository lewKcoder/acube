use a3::prelude::*;

#[derive(A3Error, Debug)]
pub enum BadError {
    #[a3(message = "Something went wrong")]
    MissingStatus,
}

fn main() {}
