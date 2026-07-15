use crate::NativeError;

impl std::fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "native {}:{} status {}: {}", self.component,
            self.symbol, self.status, self.message)
    }
}

impl std::error::Error for NativeError {}
