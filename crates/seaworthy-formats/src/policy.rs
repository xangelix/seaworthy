//! The update-policy values: whether a product updates itself (`auto`),
//! only says which version it needs (`notify`), or neither (`off`). Data
//! only: reading the machine's policy (Group Policy, the installer's
//! default, the Linux policy file, package holds) is `seaworthy-updater`'s.

use std::fmt;

/// What a product does when its server requires another version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdatePolicy {
    /// Request the helper, which installs the server's release. The
    /// default.
    #[default]
    Auto,
    /// Log and raise an event naming the required version; keep retrying.
    Notify,
    /// As `notify`; the product ships without the helper.
    Off,
}

impl UpdatePolicy {
    /// The policy's spelling in files, the registry and `seaworthy.toml`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Notify => "notify",
            Self::Off => "off",
        }
    }

    /// Parses a spelling: exactly `auto`, `notify` or `off`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "auto" => Some(Self::Auto),
            "notify" => Some(Self::Notify),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

impl fmt::Display for UpdatePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_are_exact_and_round_trip() {
        for policy in [UpdatePolicy::Auto, UpdatePolicy::Notify, UpdatePolicy::Off] {
            assert_eq!(UpdatePolicy::parse(policy.as_str()), Some(policy));
            assert_eq!(policy.to_string(), policy.as_str());
        }
        for bad in ["Auto", "", " auto", "on", "disabled"] {
            assert_eq!(UpdatePolicy::parse(bad), None, "{bad:?}");
        }
        assert_eq!(UpdatePolicy::default(), UpdatePolicy::Auto);
    }
}
