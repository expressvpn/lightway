/// A lightway protocol version
#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
pub struct Version(u8, u8);

impl Version {
    /// The minimum supported protocol version
    pub const MINIMUM: Version = Version(1, 1);

    /// The maximum supported protocol version
    pub const MAXIMUM: Version = Version(1, 3);

    /// Validate and create a new [`Version`].
    pub fn try_new(major: u8, minor: u8) -> Option<Self> {
        let v = Self(major, minor);

        if v < Self::MINIMUM || v > Self::MAXIMUM {
            None
        } else {
            Some(v)
        }
    }

    /// Get the major version component
    pub fn major(&self) -> u8 {
        self.0
    }

    /// Get the minor version component
    pub fn minor(&self) -> u8 {
        self.1
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.0, self.1)
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    use test_case::test_case;

    #[test_case(0, 0 => false)]
    #[test_case(0, 1 => false)]
    #[test_case(1, 0 => false)]
    #[test_case(1, 1 => true)]
    #[test_case(1, 2 => true)]
    #[test_case(1, 3 => true)]
    #[test_case(1, 4 => false)]
    #[test_case(2, 0 => false)]
    #[test_case(2, 1 => false)]
    #[test_case(2, 2 => false)]
    #[test_case(2, 3 => false)]
    #[test_case(2, 4 => false)]
    fn validate(major: u8, minor: u8) -> bool {
        Version::try_new(major, minor).is_some()
    }

    #[test_case(Version::try_new(1, 1).unwrap() => "1.1")]
    #[test_case(Version::try_new(1, 2).unwrap() => "1.2")]
    fn display(v: Version) -> String {
        v.to_string()
    }
}

/// An inclusive range of [`Version`].
#[derive(Debug, PartialEq)]
pub(crate) struct VersionRangeInclusive(Version, Version);

impl VersionRangeInclusive {
    /// The maximal range.
    pub fn all() -> Self {
        Self(Version::MINIMUM, Version::MAXIMUM)
    }

    pub fn valid(&self) -> bool {
        self.0 <= self.1
    }

    pub fn contains(&self, v: Version) -> bool {
        v >= self.0 && v <= self.1
    }

    pub fn maximum(&self) -> Version {
        self.1
    }

    pub fn set_minimum(self, v: Version) -> Result<Self, String> {
        if v < Version::MINIMUM {
            return Err(format!(
                "Minimum version {v} is lower than the lowest supported version {}",
                Version::MINIMUM
            ));
        }
        if v > self.1 {
            return Err(format!(
                "Minimum version {v} is greater than current maximum version {}",
                self.1
            ));
        }

        Ok(Self(v, self.1))
    }

    pub fn set_maximum(self, v: Version) -> Result<Self, String> {
        if v > Version::MAXIMUM {
            return Err(format!(
                "Maximum version {v} is greater than highest supported version {}",
                Version::MAXIMUM
            ));
        }
        if v < self.0 {
            return Err(format!(
                "Maximum version {v} is lower than current minimum version {}",
                self.0
            ));
        }

        Ok(Self(self.0, v))
    }
}

#[cfg(test)]
mod version_range_inclusive_tests {
    use super::*;
    use test_case::test_case;

    const V_1_0: Version = Version(1, 0);
    const V_1_1: Version = Version(1, 1);
    const V_1_2: Version = Version(1, 2);
    const V_1_3: Version = Version(1, 3);
    const V_1_4: Version = Version(1, 4);

    #[test_case(V_1_0, V_1_1 => true)]
    #[test_case(V_1_1, V_1_1 => true)]
    #[test_case(V_1_2, V_1_1 => false)]
    fn valid(min: Version, max: Version) -> bool {
        VersionRangeInclusive(min, max).valid()
    }

    #[test_case(V_1_1, V_1_1, V_1_0 => false)]
    #[test_case(V_1_1, V_1_1, V_1_1 => true)]
    #[test_case(V_1_1, V_1_1, V_1_2 => false)]
    #[test_case(V_1_1, V_1_2, V_1_0 => false)]
    #[test_case(V_1_1, V_1_2, V_1_1 => true)]
    #[test_case(V_1_1, V_1_2, V_1_2 => true)]
    fn contains(min: Version, max: Version, v: Version) -> bool {
        VersionRangeInclusive(min, max).contains(v)
    }

    #[test_case(V_1_1, V_1_1 => V_1_1)]
    #[test_case(V_1_1, V_1_2 => V_1_2)]
    fn maximum(min: Version, max: Version) -> Version {
        VersionRangeInclusive(min, max).maximum()
    }

    #[test_case(V_1_0 => panics "Minimum version 1.0 is lower than the lowest supported version 1.1")]
    #[test_case(V_1_1 => VersionRangeInclusive(V_1_1, V_1_1))]
    #[test_case(V_1_2 => panics "Minimum version 1.2 is greater than current maximum version 1.1")]
    fn set_minimum(v: Version) -> VersionRangeInclusive {
        let r = VersionRangeInclusive(V_1_1, V_1_1);

        assert!(r.valid());

        r.set_minimum(v).unwrap()
    }

    #[test_case(V_1_0 => panics "Maximum version 1.0 is lower than current minimum version 1.1")]
    #[test_case(V_1_1 => VersionRangeInclusive(V_1_1, V_1_1))]
    #[test_case(V_1_2 => VersionRangeInclusive(V_1_1, V_1_2))]
    #[test_case(V_1_3 => VersionRangeInclusive(V_1_1, V_1_3))]
    #[test_case(V_1_4 => panics "Maximum version 1.4 is greater than highest supported version 1.3")]
    fn set_maximum(v: Version) -> VersionRangeInclusive {
        let r = VersionRangeInclusive(V_1_1, V_1_1);

        assert!(r.valid());

        r.set_maximum(v).unwrap()
    }
}
