use acube::prelude::*;

#[derive(AcubeError, Debug)]
pub enum BadError {
    #[acube(message = "Something went wrong")]
    MissingStatus,
}

fn main() {}
