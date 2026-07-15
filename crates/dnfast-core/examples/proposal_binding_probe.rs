use dnfast_core::{
    Action, Architecture, CanonicalDocument, CanonicalPlan, Evra, PackageAction, PackageReason,
    PlanIntegrity, RepositoryBinding, Sha256Digest, TransactionIntent,
};

fn digest(value: char) -> String {
    value.to_string().repeat(64)
}

fn binding(id: &str, digests: [char; 3]) -> Result<RepositoryBinding, dnfast_core::DomainError> {
    RepositoryBinding::new(
        id,
        Sha256Digest::parse(digest(digests[0]), "generation_sha256")?,
        Sha256Digest::parse(digest(digests[1]), "origin_sha256")?,
        Sha256Digest::parse(digest(digests[2]), "trust_sha256")?,
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let integrity = PlanIntegrity::new(
        [
            &digest('a'),
            &digest('b'),
            &digest('c'),
            &digest('d'),
            &digest('e'),
        ],
        vec![
            binding("fedora", ['1', '2', '3'])?,
            binding("updates", ['4', '5', '6'])?,
        ],
    )?;
    let intent = TransactionIntent::from_package_names(Action::Install, &["dnfast"])?;
    let action = PackageAction::install_with_vendor(
        "dnfast",
        Evra::new(0, "1", "1", Architecture::Noarch),
        "fedora",
        "Dnfast",
        PackageReason::User,
    );
    let proposal = CanonicalPlan::new(intent, integrity, 60, vec![action])?;
    let bytes = proposal.to_canonical_json()?;
    let parsed = CanonicalPlan::from_canonical_json_at(&bytes, 1)?;
    let stable = proposal.canonical_sha256()? == parsed.canonical_sha256()?;
    let mut reordered: serde_json::Value = serde_json::from_slice(&bytes)?;
    reordered["selected_repositories"]
        .as_array_mut()
        .ok_or_else(|| std::io::Error::other("selected repository array is absent"))?
        .reverse();
    let malformed = serde_json::to_vec(&reordered)?;
    let rejected = CanonicalPlan::from_canonical_json_at(&malformed, 1).is_err();
    if stable && rejected {
        println!(
            "stable_digest={} reordered_selected_repositories_rejected=true",
            proposal.canonical_sha256()?.as_str()
        );
        Ok(())
    } else {
        Err("canonical proposal probe failed".into())
    }
}
