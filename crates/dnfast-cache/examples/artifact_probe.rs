use std::{env, fs};

use dnfast_cache::{
    ArtifactCache, ArtifactSpec, Digest, HttpArtifactTransport, TransactionRequest,
};
use sha2::{Digest as _, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    let [_, certificate, base, location, source, cache] = arguments.as_slice() else {
        return Err("usage: artifact_probe CERT BASE LOCATION SOURCE CACHE".into());
    };
    let bytes = fs::read(source)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let spec = ArtifactSpec::new(
        base,
        base,
        location,
        Digest::Sha256(digest),
        bytes.len() as u64,
    )?;
    let transport = HttpArtifactTransport::with_root_certificate_pem(&fs::read(certificate)?)?;
    let transaction = TransactionRequest::for_specs(std::slice::from_ref(&spec))?;
    let mut transaction = ArtifactCache::new(cache).begin_transaction(&transaction)?;
    let path = transaction.fetch(&spec, &transport)?;
    println!("accepted-bytes={}", path.file().metadata()?.len());
    Ok(())
}
