//! The update server an administrator set for the machine.
//!
//! A desktop product's helper takes no input from the app, so it can't
//! learn the server from the user's session: it asks the server the
//! machine's administrator named, else the product's default (compiled
//! into the helper). A user who points the app at another server still
//! connects, but the app treats its own updates as `notify`, never `auto`
//! ([`is_machine_server`]): a per-user endpoint can't drive a machine-wide
//! install, and two users with different servers would fight over it.
//!
//! Where it comes from, highest first, under the same trust rules as the
//! update policy (the module docs of [`crate::read_policy`]):
//!
//! - **Windows:** `HKLM\SOFTWARE\Policies\<Vendor>\<Directory>\Server`
//!   (Group Policy, the ADMX template's `Server`), then
//!   `HKLM\SOFTWARE\<Vendor>\<Directory>\Server` (the MSI's `SERVER=`).
//! - **Linux and macOS:** `server = "https://…"` in the policy file,
//!   `/etc/<vendor>/<id>/policy.toml`.
//!
//! A setting that someone other than an administrator could have written,
//! or that isn't an `https://` URL with a host (an optional port and path;
//! no user name, query or fragment; at most [`MAX_SERVER_BYTES`]), is an
//! error, never a fallback to the default: the caller fails safe.

use crate::policy::PolicySource;
use crate::{MAX_SERVER_BYTES, Product};

/// The update server an administrator set for this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminServer {
    /// The `https://` URL, as the administrator wrote it.
    pub url: String,
    /// Where it was set.
    pub source: PolicySource,
}

/// The server an administrator set for `product`: `Ok(None)` when none is
/// set (the product's default applies). Blocking (it reads files or the
/// registry); never the network.
///
/// # Errors
/// Why the setting exists but can't be trusted (a key or file someone
/// else could have written, a file this process can't read) or isn't an
/// `https://` URL.
pub fn read_admin_server(product: &Product) -> Result<Option<AdminServer>, String> {
    #[cfg(windows)]
    {
        super::windows::read_server(product)
    }
    #[cfg(not(windows))]
    {
        super::unix::read_server(product, &super::unix::Machine::system())
    }
}

/// Whether `user_server` (what the app connects to) is the machine's
/// update server: `admin`'s when set, else `default`. Both are compared
/// after normalizing (scheme and host lowercase, the default port 443
/// dropped, one trailing slash ignored); a URL that doesn't parse is never
/// the machine's.
#[must_use]
pub fn is_machine_server(user_server: &str, admin: Option<&AdminServer>, default: &str) -> bool {
    let machine = admin.map_or(default, |admin| admin.url.as_str());
    match (normalize(user_server), normalize(machine)) {
        (Some(user), Some(machine)) => user == machine,
        _ => false,
    }
}

/// A URL's parts: `<scheme>://<host>[:<port>][<path>]`.
#[derive(Debug, PartialEq, Eq)]
struct Parts<'a> {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: &'a str,
}

/// Splits `url` into its parts; `None` for anything outside
/// `<scheme>://<host>[:<port>][/<path>]` with printable ASCII, no user
/// name, query or fragment.
fn parts(url: &str) -> Option<Parts<'_>> {
    if url.len() > MAX_SERVER_BYTES || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    if rest.contains(['?', '#']) {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        // An IPv6 literal, then nothing or `:<port>`.
        let close = authority.find(']')?;
        let address = &authority[1..close];
        if address.is_empty() || !address.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return None;
        }
        let after = &authority[close + 1..];
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (&authority[..=close], port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if !host.starts_with('[') {
        let labels_ok = !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        if !labels_ok || host.len() > 253 {
            return None;
        }
    }
    let port = match port {
        None => None,
        Some(digits) => {
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            match digits.parse::<u16>() {
                Ok(0) | Err(_) => return None,
                Ok(port) => Some(port),
            }
        }
    };
    Some(Parts {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

/// `url` in the form [`is_machine_server`] compares.
fn normalize(url: &str) -> Option<String> {
    let parts = parts(url)?;
    let port = match (parts.scheme.as_str(), parts.port) {
        ("https" | "wss", Some(443)) | (_, None) => String::new(),
        (_, Some(port)) => format!(":{port}"),
    };
    let path = parts.path.strip_suffix('/').unwrap_or(parts.path);
    Some(format!("{}://{}{port}{path}", parts.scheme, parts.host))
}

/// Checks an administrator's server setting (`what` names it in errors):
/// an `https://` URL with a host, an optional port and path, no user name,
/// query or fragment, at most [`MAX_SERVER_BYTES`]. Returns it unchanged.
pub(crate) fn validate(what: &str, url: &str) -> Result<String, String> {
    let shown = || crate::log::line_safe(url);
    if url.len() > MAX_SERVER_BYTES {
        return Err(format!("{what} is longer than {MAX_SERVER_BYTES} bytes"));
    }
    match parts(url) {
        Some(parts) if parts.scheme == "https" => Ok(url.to_owned()),
        Some(_) => Err(format!("{what} is {:?}, not an https:// URL", shown())),
        None => Err(format!(
            "{what} is {:?}, not an https:// URL with a host (and an optional port and path; no user name, query or fragment)",
            shown()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin(url: &str) -> AdminServer {
        AdminServer {
            url: url.to_owned(),
            source: PolicySource::GroupPolicy,
        }
    }

    #[test]
    fn only_https_urls_with_a_host_are_accepted() {
        for good in [
            "https://updates.acme.example",
            "https://updates.acme.example/",
            "https://updates.acme.example:8443/tenant/a",
            "HTTPS://Updates.Acme.Example",
            "https://10.0.0.7",
            "https://[2001:db8::1]:8443/x",
            "https://localhost",
        ] {
            assert_eq!(validate("Server", good), Ok(good.to_owned()), "{good}");
        }
        for bad in [
            "",
            "updates.acme.example",
            "http://updates.acme.example",
            "wss://updates.acme.example",
            "https://",
            "https:///path",
            "https://user@updates.acme.example",
            "https://user:pw@updates.acme.example",
            "https://updates.acme.example/?tenant=a",
            "https://updates.acme.example/#x",
            "https://updates.acme.example:0",
            "https://updates.acme.example:65536",
            "https://updates.acme.example:",
            "https://updates.acme.example:44a",
            "https://updates..acme.example",
            "https://-updates.acme.example",
            "https://updates_acme.example",
            "https://updates.acme.example/a b",
            "https://updates.acme.example\n",
            " https://updates.acme.example",
            "https://bücher.example",
            "https://[2001:db8::1",
            "https://[2001:db8::1]x",
            "https://[]",
        ] {
            assert!(validate("Server", bad).is_err(), "{bad:?}");
        }
        let long = format!("https://a.example/{}", "p".repeat(MAX_SERVER_BYTES));
        assert!(
            validate("Server", &long)
                .unwrap_err()
                .contains("longer than")
        );
        // Errors show the value line-safe.
        let why = validate("Server", "http://a.example\r\nforged: line").unwrap_err();
        assert!(!why.contains('\n') && !why.contains('\r'), "{why}");
    }

    #[test]
    fn the_machine_server_is_the_administrators_else_the_default() {
        let default = "https://updates.acme.example";
        assert!(is_machine_server(default, None, default));
        assert!(is_machine_server(
            "HTTPS://UPDATES.acme.example:443/",
            None,
            default
        ));
        assert!(is_machine_server(
            "https://updates.acme.example/",
            None,
            default
        ));
        assert!(!is_machine_server(
            "https://staging.acme.example",
            None,
            default
        ));
        assert!(!is_machine_server(
            "https://updates.acme.example:8443",
            None,
            default
        ));
        assert!(!is_machine_server(
            "https://updates.acme.example/x",
            None,
            default
        ));
        // Paths keep their case; only one trailing slash is ignored.
        let tenant = admin("https://updates.acme.example/Tenant");
        assert!(is_machine_server(
            "https://updates.acme.example/Tenant/",
            Some(&tenant),
            default
        ));
        assert!(!is_machine_server(
            "https://updates.acme.example/tenant",
            Some(&tenant),
            default
        ));
        assert!(!is_machine_server(
            "https://updates.acme.example/Tenant//",
            Some(&tenant),
            default
        ));
        // The administrator's server replaces the default.
        let set = admin("https://onprem.example:8443");
        assert!(is_machine_server(
            "https://onprem.example:8443/",
            Some(&set),
            default
        ));
        assert!(!is_machine_server(default, Some(&set), default));
        // Anything that doesn't parse is never the machine's.
        assert!(!is_machine_server("not a url", None, default));
        assert!(!is_machine_server(default, None, "not a url"));
        assert!(!is_machine_server(
            "https://u@updates.acme.example",
            None,
            default
        ));
        // The app's own scheme compares as written (wss:443 normalizes too).
        assert!(is_machine_server(
            "wss://h.example:443",
            None,
            "wss://h.example"
        ));
        assert!(!is_machine_server(
            "wss://h.example",
            None,
            "https://h.example"
        ));
    }
}
