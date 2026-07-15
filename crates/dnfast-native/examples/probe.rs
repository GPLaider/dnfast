use dnfast_native::{NativeContext, NativeError};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).ok_or("missing probe mode")?;
    let mut context = match mode.as_str() {
        "happy" => NativeContext::open(dnfast_core::Architecture::Aarch64, || false)?,
        "interrupt" => NativeContext::open(dnfast_core::Architecture::Aarch64, || true)?,
        "panic" => NativeContext::open(dnfast_core::Architecture::Aarch64, || panic!("probe callback panic"))?,
        _ => return Err("unknown probe mode".into()),
    };
    match (mode.as_str(), context.check_interruption()) {
        ("happy", Ok(false)) | ("interrupt", Ok(true)) => Ok(()),
        ("panic", Err(NativeError::CallbackFailed)) => Ok(()),
        (_, result) => Err(format!("unexpected probe result: {result:?}").into()),
    }
}
