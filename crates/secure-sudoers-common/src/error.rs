#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}: {1}")]
    IoContext(String, #[source] std::io::Error),

    #[error("{0}")]
    Validation(String),

    #[error("{0}")]
    Security(String),

    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Parse(String),

    #[error("{0}")]
    System(String),

    #[error("{0}")]
    Spoofing(String),

    #[error("{0}")]
    Network(String),

    #[error("{0}")]
    Execution(String),
}
