use std::hint::black_box;
use std::time::Instant;

use serde::Serialize;

/// Fixed deterministic workload size (equal compute on every platform).
pub const DEFAULT_WORK_UNITS: u64 = 100_000_000;
const WARMUP_UNITS: u64 = 5_000_000;

pub fn run(args: super::ComputeEffectiveArgs) -> anyhow::Result<()> {
    if !args.json {
        log::info!(
            "compute_effective: running {} round(s), {} work units each",
            args.rounds,
            args.work_units
        );
    }

    for _ in 0..2 {
        black_box(run_workload(WARMUP_UNITS));
    }

    let mut elapsed_secs = Vec::with_capacity(args.rounds);
    for _ in 0..args.rounds {
        let start = Instant::now();
        let checksum = black_box(run_workload(args.work_units));
        let elapsed = start.elapsed().as_secs_f64();
        black_box(checksum);
        elapsed_secs.push(elapsed);
    }

    let report = build_report(args.work_units, &elapsed_secs);
    emit(&report, args.json)?;
    Ok(())
}

/// Portable mixed integer/float loop; LLVM cannot eliminate thanks to `black_box`.
fn run_workload(units: u64) -> u64 {
    let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut f: f64 = 0.318_309_886_183_790_7;

    for i in 0..units {
        acc = acc
            .wrapping_mul(0x5851_F42D_4C95_7F1D)
            .wrapping_add(i);
        acc ^= acc.rotate_left(17);
        acc = acc.wrapping_add(acc >> 31);

        let x = (i & 0xFF) as f64 * 1e-7;
        f = f.mul_add(1.000_000_1, x).sin().cos();
        acc ^= f.to_bits();
    }

    acc
}

#[derive(Serialize)]
struct ComputeReport {
    arch: &'static str,
    os: &'static str,
    work_units: u64,
    rounds: usize,
    elapsed_secs: Vec<f64>,
    median_elapsed_secs: f64,
    /// work_units / median_elapsed_secs
    effective_ops_per_sec: f64,
    /// effective_ops_per_sec / 1e6, human-friendly score
    effective_score: f64,
}

fn build_report(work_units: u64, elapsed_secs: &[f64]) -> ComputeReport {
    let mut sorted = elapsed_secs.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];
    let effective_ops_per_sec = work_units as f64 / median;
    let effective_score = effective_ops_per_sec / 1_000_000.0;

    ComputeReport {
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        work_units,
        rounds: elapsed_secs.len(),
        elapsed_secs: elapsed_secs.to_vec(),
        median_elapsed_secs: median,
        effective_ops_per_sec,
        effective_score,
    }
}

fn emit(report: &ComputeReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}\n", serde_json::to_string(report)?);
        return Ok(());
    }

    println!("--- CPU compute effectiveness ---");
    println!("arch:                  {}", report.arch);
    println!("os:                    {}", report.os);
    println!("work_units:            {}", report.work_units);
    println!("rounds:                {}", report.rounds);
    println!("elapsed (s):           {:?}", report.elapsed_secs);
    println!("median_elapsed (s):    {:.6}", report.median_elapsed_secs);
    println!(
        "effective_ops_per_sec: {:.2}",
        report.effective_ops_per_sec
    );
    println!("effective_score:       {:.4} Mops/s", report.effective_score);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_is_deterministic() {
        assert_eq!(run_workload(10_000), run_workload(10_000));
    }

    #[test]
    fn workload_changes_with_units() {
        assert_ne!(run_workload(10_000), run_workload(20_000));
    }
}
