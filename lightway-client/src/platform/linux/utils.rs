use std::path::Path;

/// Where Linux keeps the IPv6 settings of each interface, one directory per
/// interface plus `all` and `default`
const IPV6_CONF_DIR: &str = "/proc/sys/net/ipv6/conf";

/// Whether IPv6 is enabled on the interface `if_name`. With its
/// `disable_ipv6` sysctl set the interface has no IPv6 address, and recent
/// kernels refuse IPv6 routes through it with EACCES.
pub fn interface_has_ipv6(if_name: &str) -> bool {
    ipv6_enabled_in(&Path::new(IPV6_CONF_DIR).join(if_name))
}

/// Whether IPv6 is enabled on any interface, or on interfaces created later
/// (`default`). `all` is skipped: it only holds the last value written to
/// it, which each interface may have changed since.
pub fn any_interface_has_ipv6() -> bool {
    any_ipv6_enabled_under(Path::new(IPV6_CONF_DIR))
}

/// Read the `disable_ipv6` sysctl in the interface directory `conf`. A value
/// that cannot be read counts as enabled.
fn ipv6_enabled_in(conf: &Path) -> bool {
    let path = conf.join("disable_ipv6");
    match std::fs::read_to_string(&path) {
        // Any non-zero value disables IPv6
        Ok(value) => !value
            .trim()
            .parse::<i32>()
            .is_ok_and(|disabled| disabled != 0),
        Err(err) => {
            tracing::debug!(
                "Failed to read {}, assuming IPv6 is enabled: {err}",
                path.display()
            );
            true
        }
    }
}

fn any_ipv6_enabled_under(conf_dir: &Path) -> bool {
    let entries = match std::fs::read_dir(conf_dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::debug!(
                "Failed to list {}, assuming IPv6 is enabled: {err}",
                conf_dir.display()
            );
            return true;
        }
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != "all")
        .any(|entry| ipv6_enabled_in(&entry.path()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Lay out a fake `/proc/sys/net/ipv6/conf` with one directory per entry
    fn conf_dir(entries: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, disable_ipv6) in entries {
            let conf = dir.path().join(name);
            std::fs::create_dir(&conf).unwrap();
            std::fs::write(conf.join("disable_ipv6"), disable_ipv6).unwrap();
        }
        dir
    }

    #[test_case("0\n", true ; "enabled")]
    #[test_case("1\n", false ; "disabled")]
    #[test_case("2\n", false ; "any non-zero value disables")]
    #[test_case("garbage", true ; "unparsable counts as enabled")]
    fn test_ipv6_enabled_in(disable_ipv6: &str, expected: bool) {
        let dir = conf_dir(&[("lo", disable_ipv6)]);
        assert_eq!(ipv6_enabled_in(&dir.path().join("lo")), expected);
    }

    #[test]
    fn test_ipv6_enabled_in_missing_counts_as_enabled() {
        let dir = conf_dir(&[]);
        assert!(ipv6_enabled_in(&dir.path().join("lo")));
    }

    #[test]
    fn test_any_ipv6_enabled_under_all_disabled() {
        // What `sysctl net.ipv6.conf.all.disable_ipv6=1` leaves behind
        let dir = conf_dir(&[
            ("all", "1\n"),
            ("default", "1\n"),
            ("lo", "1\n"),
            ("eth0", "1\n"),
        ]);
        assert!(!any_ipv6_enabled_under(dir.path()));
    }

    #[test]
    fn test_any_ipv6_enabled_under_one_interface_enabled() {
        // `all` keeps the last value written even after eth0 is re-enabled
        let dir = conf_dir(&[
            ("all", "1\n"),
            ("default", "1\n"),
            ("lo", "1\n"),
            ("eth0", "0\n"),
        ]);
        assert!(any_ipv6_enabled_under(dir.path()));
    }

    #[test]
    fn test_any_ipv6_enabled_under_default_enabled() {
        // Interfaces created later still get IPv6
        let dir = conf_dir(&[("all", "1\n"), ("default", "0\n"), ("lo", "1\n")]);
        assert!(any_ipv6_enabled_under(dir.path()));
    }

    #[test]
    fn test_any_ipv6_enabled_under_ignores_all() {
        let dir = conf_dir(&[("all", "0\n"), ("default", "1\n"), ("lo", "1\n")]);
        assert!(!any_ipv6_enabled_under(dir.path()));
    }

    #[test]
    fn test_any_ipv6_enabled_under_missing_dir_counts_as_enabled() {
        let dir = conf_dir(&[]);
        assert!(any_ipv6_enabled_under(&dir.path().join("missing")));
    }
}
