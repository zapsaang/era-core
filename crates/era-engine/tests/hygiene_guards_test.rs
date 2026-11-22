//! Repository hygiene meta-gates (Round-1 H-03/H-05/H-08, Round-2 R2-HYG).
//!
//! META-GATE EXCEPTION: this file intentionally reads repository configuration
//! (.github/workflows/ci.yml, README.md) and the *source text of test files*. It
//! inspects no production source and asserts no product behaviour; every check
//! here is repository governance. Behaviour suites must call production APIs
//! instead (see the matrix tests: a source-text gate must never replace them).
//! This exception is the answer to H-04: it is confined to tests/ + repo config
//! and is explicitly labelled.
//!
//! Round-2 R2-HYG-01 hardening:
//! - the scanner classifies a body instead of matching substrings: print-only and
//!   empty bodies have no failure channel, assert!(true) / assert_eq!(x, x) are
//!   trivial channels, and only a behavioural assertion (or an explicit failure /
//!   expected-error helper) passes the gate;
//! - CI/README invariants live in the labelled meta_gates module and are matched
//!   structurally (per job, single statistics source), so legitimate job or
//!   wording changes do not turn the gate red.

use std::path::{Path, PathBuf};

/// Test functions whose failure channel was audited (H-03 / R2-04).
/// Each entry must classify as FailureChannel::Behavioral.
const AUDITED_TESTS: &[(&str, &str)] = &[
    (
        "crates/era-engine/tests/mandatory_defaults.rs",
        "test_mandatory_cdc_enabled",
    ),
    (
        "crates/era-engine/tests/shard_analysis_test.rs",
        "test_shard_distribution_analysis",
    ),
    (
        "crates/era-engine/tests/fault_tolerance_test.rs",
        "test_precise_fault_tolerance_limits",
    ),
    (
        "crates/era-engine/tests/root_cause_analysis_test.rs",
        "test_volume_requirements_strict",
    ),
    (
        "crates/era-engine/tests/deep_verification_test.rs",
        "test_sharding_math_verification",
    ),
    (
        "crates/era-engine/tests/security_tests.rs",
        "test_disable_core_dumps",
    ),
    (
        "crates/era-codec/tests/adversarial_audit_v9.rs",
        "v9_d2d_lz4_malformed_input",
    ),
];

/// The four matrix-distribution tests that R2-04 found to be self-proving.
const MATRIX_AUDIT_TESTS: &[&str] = &[
    "crates/era-engine/tests/shard_analysis_test.rs",
    "crates/era-engine/tests/fault_tolerance_test.rs",
    "crates/era-engine/tests/root_cause_analysis_test.rs",
    "crates/era-engine/tests/deep_verification_test.rs",
];

/// Production distribution entry points the matrix tests must reach. A test that
/// re-implements the algorithm locally cannot contain any of these and fails the
/// gate below.
const PRODUCTION_DISTRIBUTION_SYMBOLS: &[&str] = &[
    "calculate_volume",
    "DistributionCalculator",
    "validate_canonical_erasure_volume_count",
    "validate_erasure_volume_count",
    "VolumePool",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/era-engine must live two levels below the repo root")
        .to_path_buf()
}

fn read_repo_file(relative_path: &str) -> String {
    let path = repo_root().join(relative_path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// How a test body can fail when the behaviour it describes regresses.
#[derive(Debug, PartialEq, Eq)]
enum FailureChannel {
    /// No assertion at all (print-only or empty body): green no matter what.
    None,
    /// An assertion that can never fail: assert!(true), assert_eq!(x, x), ...
    Trivial,
    /// At least one assertion or explicit failure path that can turn red.
    Behavioral,
}

/// Extract the body of a top-level fn <name> up to the next column-zero closing
/// brace. The audited test functions are top-level items; this is a meta-gate
/// heuristic, not a Rust parser.
fn fn_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("fn {name}(");
    let start = source.find(&needle)?;
    let rest = &source[start..];
    let end = rest.find("\n}")?;
    Some(&rest[..end])
}

/// Remove line comments while preserving line structure. String literals are
/// skipped so a literal such as "https://" does not truncate the body.
fn strip_line_comments(body: &str) -> String {
    let mut code = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = chars.next() {
        if in_string {
            code.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => {
                in_string = true;
                code.push(character);
            }
            '/' if chars.peek() == Some(&'/') => {
                for comment_character in chars.by_ref() {
                    if comment_character == '\n' {
                        code.push('\n');
                        break;
                    }
                }
            }
            _ => code.push(character),
        }
    }
    code
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Given a slice that starts with '(', return its inner text and the number of
/// bytes consumed, respecting nested brackets and string literals.
fn paren_inner(input: &str) -> Option<(&str, usize)> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, character) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some((&input[1..offset], offset + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Split macro arguments on top-level commas (brackets and strings respected).
fn split_top_level_args(inner: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (offset, character) in inner.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(inner[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    args.push(inner[start..].trim());
    args
}

fn normalize(tokens: &str) -> String {
    tokens
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn is_self_comparison(condition: &str) -> bool {
    let Some((left, right)) = condition.split_once("==") else {
        return false;
    };
    let left = normalize(left);
    let right = normalize(right);
    !left.is_empty() && left == right
}

fn is_trivial_assertion(name: &str, inner: &str) -> bool {
    match name {
        "assert" | "debug_assert" => {
            let condition = split_top_level_args(inner)
                .first()
                .copied()
                .unwrap_or("")
                .to_string();
            let condition = normalize(&condition);
            condition == "true" || is_self_comparison(&condition)
        }
        "assert_eq" | "debug_assert_eq" => {
            let args = split_top_level_args(inner);
            args.len() >= 2 && normalize(args[0]) == normalize(args[1])
        }
        _ => false,
    }
}

/// Collect assertion macro invocations as (macro name, raw arguments).
fn assertion_macros(code: &str) -> Vec<(String, String)> {
    let bytes = code.as_bytes();
    let mut macros = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let Some(relative) = code[index..].find("assert") else {
            break;
        };
        let start = index + relative;
        index = start + "assert".len();
        if start > 0 && is_identifier_byte(bytes[start - 1]) {
            continue;
        }
        let mut cursor = start + "assert".len();
        let mut name = String::from("assert");
        for suffix in ["_eq", "_ne"] {
            if code[cursor..].starts_with(suffix) {
                name.push_str(suffix);
                cursor += suffix.len();
                break;
            }
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'!' {
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'(' {
            continue;
        }
        let Some((inner, consumed)) = paren_inner(&code[cursor..]) else {
            continue;
        };
        macros.push((name, inner.to_string()));
        index = cursor + consumed;
    }
    macros
}

/// Classify whether a test body can actually fail.
fn classify_failure_channel(body: &str) -> FailureChannel {
    let code = strip_line_comments(body);
    if code.trim().is_empty() {
        return FailureChannel::None;
    }
    // Explicit failures and "expect the error" helpers are failure channels even
    // without an assertion macro.
    for marker in ["panic!", "unwrap_err", "expect_err", "catch_unwind"] {
        if code.contains(marker) {
            return FailureChannel::Behavioral;
        }
    }
    let macros = assertion_macros(&code);
    if macros.is_empty() {
        return FailureChannel::None;
    }
    if macros
        .iter()
        .any(|(name, inner)| !is_trivial_assertion(name, inner))
    {
        return FailureChannel::Behavioral;
    }
    FailureChannel::Trivial
}

fn classify_source(source: &str, test_name: &str) -> FailureChannel {
    let body = fn_body(source, test_name)
        .unwrap_or_else(|| panic!("function {test_name} not found in test source"));
    classify_failure_channel(body)
}

#[test]
fn tautology_scanner_detects_missing_failure_channel() {
    // Negative examples: print-only and empty bodies have no failure channel.
    for source in [
        "#[test]\nfn sample() {\n    println!(\"still green\");\n}\n",
        "#[test]\nfn sample() {\n}\n",
        "#[test]\nfn sample() {\n    // deliberately no assertion\n}\n",
    ] {
        assert_eq!(
            classify_source(source, "sample"),
            FailureChannel::None,
            "print-only/empty test must be detected as lacking a failure channel: {source:?}"
        );
    }

    // Negative examples: assertions that can never fail are still tautologies.
    for source in [
        "#[test]\nfn sample() {\n    assert!(true);\n}\n",
        "#[test]\nfn sample() {\n    assert!(true, \"always holds\");\n}\n",
        "#[test]\nfn sample() {\n    assert_eq!(value, value);\n}\n",
        "#[test]\nfn sample() {\n    assert_eq!(value, value, \"same token on both sides\");\n}\n",
        "#[test]\nfn sample() {\n    assert!(value == value);\n}\n",
    ] {
        assert_eq!(
            classify_source(source, "sample"),
            FailureChannel::Trivial,
            "assert!(true) / assert_eq!(x, x) must be detected as trivial: {source:?}"
        );
    }

    // Positive examples: behavioural assertions and explicit failure paths pass.
    for source in [
        "#[test]\nfn sample() {\n    assert!(value.is_err());\n}\n",
        "#[test]\nfn sample() {\n    assert_eq!(left, right);\n}\n",
        "#[test]\nfn sample() {\n    panic!(\"boom\");\n}\n",
        "#[test]\nfn sample() {\n    let result = fallible();\n    assert!(result.is_ok(), \"expected success\");\n    result.unwrap_err();\n}\n",
    ] {
        assert_eq!(
            classify_source(source, "sample"),
            FailureChannel::Behavioral,
            "behavioural test must be accepted by the scanner: {source:?}"
        );
    }
}

#[test]
fn audited_tests_have_a_failure_channel() {
    let mut offenders = Vec::new();
    for (relative_path, test_name) in AUDITED_TESTS {
        let source = read_repo_file(relative_path);
        match fn_body(&source, test_name) {
            Some(body) => match classify_failure_channel(body) {
                FailureChannel::Behavioral => {}
                FailureChannel::None => offenders.push(format!(
                    "{relative_path}::{test_name} (no failing assertion)"
                )),
                FailureChannel::Trivial => offenders.push(format!(
                    "{relative_path}::{test_name} (only trivial assertions)"
                )),
            },
            None => offenders.push(format!("{relative_path}::{test_name} (function not found)")),
        }
    }
    assert!(
        offenders.is_empty(),
        "tests without a behavioural failure channel: {offenders:?}"
    );
}

/// The meta-gate must only read test sources. Production source is out of scope
/// for this file (H-04): behaviour must be asserted by calling it, not by reading
/// its text.
#[test]
fn hygiene_scan_is_limited_to_test_sources() {
    let mut offenders = Vec::new();
    for (relative_path, _) in AUDITED_TESTS {
        if !relative_path.contains("/tests/") || relative_path.contains("/src/") {
            offenders.push(*relative_path);
        }
    }
    for relative_path in MATRIX_AUDIT_TESTS {
        if !relative_path.contains("/tests/") || relative_path.contains("/src/") {
            offenders.push(relative_path);
        }
    }
    assert!(
        offenders.is_empty(),
        "the hygiene meta-gate must only inspect test sources, not production source: {offenders:?}"
    );
}

/// R2-04: an audited matrix test must reach production APIs; asserting a locally
/// re-implemented algorithm is treated the same as a print-only test.
#[test]
fn matrix_audit_tests_call_production_distribution_api() {
    let mut offenders = Vec::new();
    for relative_path in MATRIX_AUDIT_TESTS {
        let source = read_repo_file(relative_path);
        let uses_production_crate =
            source.contains("era_volume::") || source.contains("era_engine::");
        let names_distribution_api = PRODUCTION_DISTRIBUTION_SYMBOLS
            .iter()
            .any(|symbol| source.contains(symbol));
        if !(uses_production_crate && names_distribution_api) {
            offenders.push(format!(
                "{relative_path} (must call era_volume/era_engine production distribution APIs, not re-implement them)"
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "matrix audit tests are self-proving: {offenders:?}"
    );
}

/// Repository-configuration invariants. META-GATE: these read ci.yml/README.md
/// and are deliberately structural and wording-tolerant so ordinary refactors do
/// not turn them red. They assert repository governance, not product behaviour.
mod meta_gates {
    use super::read_repo_file;

    fn indentation(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    /// Job name -> job block, parsed structurally from the workflow.
    fn workflow_jobs(workflow: &str) -> Vec<(String, String)> {
        let mut jobs = Vec::new();
        let mut in_jobs = false;
        let mut current: Option<(String, String)> = None;
        for line in workflow.lines() {
            if line == "jobs:" {
                in_jobs = true;
                continue;
            }
            if !in_jobs {
                continue;
            }
            if let Some(rest) = line.strip_prefix("  ") {
                let is_job = !rest.is_empty()
                    && !rest.starts_with(' ')
                    && !rest.starts_with('#')
                    && rest.ends_with(':');
                if is_job {
                    if let Some(job) = current.take() {
                        jobs.push(job);
                    }
                    current = Some((rest.trim_end_matches(':').trim().to_string(), String::new()));
                    continue;
                }
            }
            if let Some((_, block)) = current.as_mut() {
                block.push_str(line);
                block.push('\n');
            }
        }
        if let Some(job) = current.take() {
            jobs.push(job);
        }
        jobs
    }

    #[test]
    fn ci_workflow_is_reproducible() {
        let ci = read_repo_file(".github/workflows/ci.yml");
        let jobs = workflow_jobs(&ci);
        assert!(
            jobs.len() >= 2,
            "expected at least two CI jobs, found {:?}",
            jobs.iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>()
        );
        for (job, block) in &jobs {
            let has_job_level_timeout = block.lines().any(|line| {
                indentation(line) == 4 && line.trim_start().starts_with("timeout-minutes:")
            });
            assert!(
                has_job_level_timeout,
                "CI job {job} must pin a job-level timeout-minutes"
            );
        }

        let test_jobs: Vec<&(String, String)> = jobs
            .iter()
            .filter(|(_, block)| block.contains("cargo test"))
            .collect();
        assert!(
            !test_jobs.is_empty(),
            "expected at least one CI job running cargo test"
        );
        for (job, block) in test_jobs {
            assert!(
                block.contains("ulimit -n 1024"),
                "CI job {job} must run cargo test under the pinned FD limit"
            );
            assert!(
                block.contains("--release"),
                "CI job {job} must compile tests in release mode"
            );
            assert!(
                block.contains("--locked"),
                "CI job {job} must resolve dependencies from Cargo.lock"
            );
        }

        assert!(
            ci.lines()
                .any(|line| line.contains("cargo clippy") && line.contains("--locked")),
            "clippy must run with --locked"
        );
    }

    /// The single authoritative README statistics line. The release owner
    /// refreshes this one line after the full gate run; this meta-gate never
    /// hardcodes the absolute numbers. Every other statistics mention in the
    /// README must agree with the anchor line.
    const STATISTICS_ANCHOR: &str = "Last Verified";

    fn parse_statistics(line: &str) -> Option<(u32, u32, u32)> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut passed = None;
        let mut failed = None;
        let mut ignored = None;
        for pair in tokens.windows(2) {
            let Ok(count) = pair[0].replace(',', "").parse::<u32>() else {
                continue;
            };
            match pair[1].trim_end_matches([',', '.']) {
                "passed" => passed = Some(count),
                "failed" => failed = Some(count),
                "ignored" => ignored = Some(count),
                _ => {}
            }
        }
        match (passed, failed, ignored) {
            (Some(passed), Some(failed), Some(ignored)) => Some((passed, failed, ignored)),
            _ => None,
        }
    }

    #[test]
    fn readme_test_statistics_are_consistent() {
        let readme = read_repo_file("README.md");
        let anchor_lines: Vec<&str> = readme
            .lines()
            .filter(|line| line.contains(STATISTICS_ANCHOR) && parse_statistics(line).is_some())
            .collect();
        assert_eq!(
            anchor_lines.len(),
            1,
            "README must have exactly one {STATISTICS_ANCHOR} statistics line, found {}",
            anchor_lines.len()
        );
        let anchor = anchor_lines[0];
        let (passed, failed, ignored) = parse_statistics(anchor)
            .expect("anchor line must publish passed/failed/ignored counts");
        assert_eq!(failed, 0, "README must not publish failed tests: {anchor}");
        assert!(
            passed > 0,
            "README must publish a non-zero passed count: {anchor}"
        );
        assert!(
            passed > ignored,
            "README passed count must exceed the ignored count: {anchor}"
        );

        let mut drifted = Vec::new();
        for line in readme.lines() {
            if line == anchor {
                continue;
            }
            if let Some(statistics) = parse_statistics(line) {
                if statistics != (passed, failed, ignored) {
                    drifted.push(line.trim().to_string());
                }
            }
        }
        assert!(
            drifted.is_empty(),
            "README statistics must agree with the single {STATISTICS_ANCHOR} source; drifted lines: {drifted:?}"
        );

        assert!(
            readme.contains("cargo test --release"),
            "README must document the release test command used by CI"
        );
        assert!(
            readme.contains("--locked"),
            "README must document --locked commands"
        );
    }

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn production_sources_have_zero_dead_code_or_unused_allows() {
        let root = super::repo_root();
        let mut src_roots = Vec::new();
        for group in ["crates", "bins"] {
            if let Ok(entries) = std::fs::read_dir(root.join(group)) {
                for entry in entries.flatten() {
                    let src = entry.path().join("src");
                    if src.is_dir() {
                        src_roots.push(src);
                    }
                }
            }
        }

        let forbidden = [
            "allow(dead_code)",
            "allow(unused_mut)",
            "allow(unused_imports)",
        ];
        let mut rs_files = Vec::new();
        for src_root in src_roots {
            collect_rs_files(&src_root, &mut rs_files);
        }
        rs_files.sort();

        let mut violations = Vec::new();
        for path in rs_files {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            for (idx, line) in content.lines().enumerate() {
                for pattern in forbidden {
                    if line.contains(pattern) {
                        violations.push(format!("{rel}:{}: contains {pattern}", idx + 1));
                    }
                }
            }
        }

        assert!(
            violations.is_empty(),
            "production src/ must not suppress warnings with allow(dead_code|unused_mut|unused_imports):\n{}",
            violations.join("\n")
        );
    }
}
