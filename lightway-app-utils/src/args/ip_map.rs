use std::{collections::HashMap, net::IpAddr, path::PathBuf};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An argument type which can either be a path to a file containing a
/// YAML map of IP address to IPv4 subnet or an inline map of the same
/// kind.
///
/// When used via clap in the CLI the variant is always [`Self::Path`]
/// but in the configuration file either form can be used.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum IpMap {
    /// A path pointing to a file containing YAML (NB: a superset of
    /// JSON) map of IP address to IPv4 subnet.
    Path(PathBuf),
    /// An inline map of IP address to IPv4 subnet.
    Inline(HashMap<IpAddr, Ipv4Net>),
}

// This impl allows use with e.g. clap CLI parser.
impl std::str::FromStr for IpMap {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // use by clap to parse the argument, only paths are supported
        // on the command line.
        Ok(Self::Path(s.into()))
    }
}

impl std::default::Default for IpMap {
    fn default() -> Self {
        Self::Inline(Default::default())
    }
}

#[derive(Debug, Error)]
pub enum TryFromError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Format error: {0}")]
    Format(#[from] serde_yaml::Error),
}

impl TryFrom<IpMap> for HashMap<IpAddr, Ipv4Net> {
    type Error = TryFromError;

    fn try_from(value: IpMap) -> Result<Self, Self::Error> {
        match value {
            IpMap::Path(p) => {
                let f = std::fs::File::open(&p)?;
                Ok(serde_yaml::from_reader(f)?)
            }
            IpMap::Inline(m) => Ok(m),
        }
    }
}
