// TODO:
// schemars supports chorno,
// Do we really need a NonZeroDuration wrapper for humantime, which is another wrapper from chorno
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

/// Wrapper for compatibility with both clap
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq)]
pub struct NonZeroDuration(#[serde_as(as = "DisplayFromStr")] humantime::Duration);

impl std::fmt::Display for NonZeroDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for NonZeroDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NonZeroDuration> for std::time::Duration {
    fn from(d: NonZeroDuration) -> Self {
        d.0.into()
    }
}

impl std::str::FromStr for NonZeroDuration {
    type Err = humantime::DurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let duration = NonZeroDuration(s.parse::<humantime::Duration>()?);
        if duration.0.is_zero() {
            return Err(humantime::DurationError::Empty);
        }
        Ok(duration)
    }
}

impl NonZeroDuration {
    /// Build from std duration
    pub fn from_std_duration(duration: std::time::Duration) -> Self {
        NonZeroDuration(duration.into())
    }
}

/// Custom schema function for JsonSchema
pub fn custom_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut schema = String::json_schema(generator);
    schema.insert(
        "pattern".into(),
        "^(([1-9][0-9]*(\\.[0-9]+)?|0\\.[0-9]*[1-9][0-9]*)(ns|us|ms|s|m|h|d|w|M)\\s*)+$".into(),
    );
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use schemars::SchemaGenerator;

    fn get_pattern() -> String {
        let schema = custom_schema(&mut SchemaGenerator::default());
        schema
            .get("pattern")
            .and_then(|v| v.as_str())
            .expect("pattern key must exist and be a string")
            .to_string()
    }
    #[test]
    fn valid_none_zero_duration_inputs() {
        let re = Regex::new(&get_pattern()).unwrap();
        for s in &["1ns", "1us", "1ms", "1s", "1m", "1h", "1d", "1w", "1M"] {
            assert!(re.is_match(s), "expected valid: {s}");
        }
        for s in &["1.5s", "0.5ms", "2.25h", "10.0m"] {
            assert!(re.is_match(s), "expected valid input with decimal: {s}");
        }
        for s in &["1h30m", "2d6h", "1w3d", "1h30m10s"] {
            assert!(
                re.is_match(s),
                "expected valid with multiple componenet no space: {s}"
            );
        }
        for s in &["1h 30m", "2d 6h", "1w 3d 12h", "1h 30m 10s"] {
            assert!(
                re.is_match(s),
                "expected valid with multiple componenet and space: {s}"
            );
        }
        for s in &["9999s", "100000ms", "365d"] {
            assert!(re.is_match(s), "expected valid with large numbers: {s}");
        }
    }

    #[test]
    fn invalid_none_zero_duration_inputs() {
        let re = Regex::new(&get_pattern()).unwrap();
        for s in &["0ns", "0us", "0ms", "0s", "0m", "0h", "0d", "0w", "0M"] {
            assert!(
                !re.is_match(s),
                "invalid zero dutraion for none zero duration: {s}"
            );
        }
        assert!(!re.is_match(""), "empty string must not match");

        for s in &["s", "ms", "h"] {
            assert!(!re.is_match(s), "unit without number must not match: {s}");
        }

        for s in &["1y", "1sec", "1min", "1hr", "1x"] {
            assert!(!re.is_match(s), "unknown unit must not match: {s}");
        }

        assert!(!re.is_match(".5s"), "leading dot must not match");
        assert!(!re.is_match("1.2.3s"), "multiple dots must not match");
        assert!(!re.is_match("-1s"), "negative duration must not match");
        assert!(
            !re.is_match("42"),
            "bare number without unit must not match"
        );
        assert!(
            !re.is_match("1 s"),
            "space between number and unit must not match"
        );
    }
}
