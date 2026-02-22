use acube::prelude::*;

#[derive(AcubeError, Debug)]
pub enum BadError {
    #[acube(status = 500)]
    MissingMessage,
}

fn main() {}
