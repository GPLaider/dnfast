use crate::Package;

pub fn search<'a>(packages: &'a [Package], query: &str) -> Vec<&'a Package> {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return Vec::new();
    }
    let mut results = packages
        .iter()
        .filter_map(|package| {
            let name = package.name.to_ascii_lowercase();
            let summary = package.summary.to_ascii_lowercase();
            let rank = if name == query {
                0
            } else if name.starts_with(&query) {
                1
            } else if name.contains(&query) {
                2
            } else if summary.contains(&query) {
                3
            } else {
                return None;
            };
            Some((rank, package))
        })
        .collect::<Vec<_>>();
    results.sort_by(|(left_rank, left), (right_rank, right)| {
        left_rank
            .cmp(right_rank)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.epoch.cmp(&right.epoch))
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.release.cmp(&right.release))
            .then_with(|| left.arch.cmp(&right.arch))
            .then_with(|| left.summary.cmp(&right.summary))
    });
    results.into_iter().map(|(_, package)| package).collect()
}
