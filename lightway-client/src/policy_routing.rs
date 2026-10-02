//! Linux policy routing for the tunnel, based on a firewall mark.
//!
//! # Why
//!
//! Without policy routing, the tunnel's catch-all routes (`0.0.0.0/1` +
//! `128.0.0.0/1`) live in the *main* table alongside the WAN default route.
//! A `/32` host route for the VPN server then keeps the tunnel's own encrypted
//! packets off the tunnel.  That host route is maintained by
//! [`crate::route_manager`] in reaction to netlink notifications, so there is a
//! race window after a network change (e.g. Wi-Fi roam) where the kernel has
//! already invalidated the old host route but the new one has not been installed
//! yet.  During that window the VPN server's IP matches the tunnel's own
//! catch-all route, causing an encapsulation loop.
//!
//! # How this fixes it
//!
//! The tunnel routes move out of *main* into a private table, and five rules
//! determine which table is consulted:
//!
//! ```text
//! Rule MARKED:           fwmark <MARK>              lookup main    # (1) tunnel socket → WAN
//! Rule SERVER:           to <SERVER_IP>/32          lookup main    # (2) rp_filter fix (see below)
//! Rule MARKED_FALLBACK:  fwmark <MARK>              unreachable    # (3) loop-breaker (see below)
//! Rule SUPPRESS_DEFAULT: (no condition)             suppress 0/0   # (4) allow LAN routes (see below)
//! Rule TUNNEL:           (no condition)             lookup <TABLE> # (5) all other traffic → tunnel
//! ```
//!
//! The tunnel's outside socket carries `<MARK>`, so its outgoing packets hit
//! Rule MARKED and resolve via *main* — whose default route the kernel keeps
//! current on its own, with no Lightway-managed entry involved.
//!
//! # Rule SERVER — rp_filter fix
//!
//! Linux's reverse-path filter (strict mode, `rp_filter=1`) checks incoming
//! packets by looking up the *source* IP through the routing rules — but using
//! the *incoming packet's* mark, which is 0 for plain packets from the WAN.
//!
//! After Rule TUNNEL is installed, an unmarked lookup for the server IP falls
//! through Rules MARKED and MARKED_FALLBACK (both require `fwmark <MARK>`) and
//! lands on Rule TUNNEL → tunnel table → `0.0.0.0/1 via lightway`.  Strict
//! rp_filter would then consider `SERVER_IP` routed via `lightway`, but the
//! server's reply packet arrived on `wlan0` (or whichever physical interface),
//! producing an interface mismatch and silently **dropping** every pong — which
//! the keepalive mechanism observes as a timeout.
//!
//! Rule SERVER intercepts the unmarked lookup for `<SERVER_IP>/32` and redirects
//! it to *main*, where the WAN default route sends it back out the physical
//! interface.  rp_filter sees a consistent interface and accepts the packet.
//!
//! # Rule MARKED_FALLBACK — loop-breaker
//!
//! `ip rule` falls through to the next rule when the selected table returns no
//! matching route.  During a Wi-Fi roam, the kernel removes the old default
//! route from *main* before a new one arrives.  In that brief window:
//!
//! 1. Rule MARKED: `fwmark <MARK> → lookup main` — no route → **fall through**
//! 2. Rule SERVER: `to <SERVER_IP>/32 → lookup main` — no route → **fall through**
//! 3. Rule MARKED_FALLBACK: (absent without this fix) — skipped
//! 4. Rule TUNNEL: `→ lookup <TABLE>` — `0.0.0.0/1` and `128.0.0.0/1` via `tun`
//!    — the VPN socket's own encrypted packet is read back off the tun device
//!    as an inside packet, re-encapsulated (+69 bytes per lap), and re-sent →
//!    **encapsulation loop**.
//!
//! Rule MARKED_FALLBACK (`fwmark <MARK> unreachable`) intercepts the fall-through:
//! - During normal operation marked packets are already handled by Rule MARKED and
//!   Rule MARKED_FALLBACK is never reached.
//! - During a roam, marked packets fall through Rules MARKED and SERVER (both
//!   consult *main*, which has no route) and hit Rule MARKED_FALLBACK, which
//!   returns `ENETUNREACH` to the caller.  The outside I/O callback already treats
//!   this as a transient send failure, dropping the packet cleanly and preventing
//!   the loop.
//!
//! # Rule SUPPRESS_DEFAULT — prevent LAN traffic routing into tunnel
//!
//! Without this rule, unmarked packets for local subnets (e.g., LAN addresses)
//! would match the default route (`0.0.0.0/0`) in *main*, which points to the
//! WAN gateway. The kernel would then fall through to Rule TUNNEL and send all
//! LAN traffic through the tunnel — incorrect behavior for split-tunneling.
//!
//! Rule SUPPRESS_DEFAULT (`suppress-prefixlen 0 lookup main`) prevents the
//! default route from being matched, allowing more-specific routes (like
//! `192.168.0.0/16` for LAN) to take precedence. Non-default LAN routes in
//! *main* are used before falling through to Rule TUNNEL.
//! `suppress-prefixlen 0` means "match any route except the default route (0/0)".

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use futures::TryStreamExt;
// Use rtnetlink's re-export rather than depending on netlink-packet-route
// directly: that guarantees these types come from the exact same crate version
// rtnetlink itself was built against.
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{Handle, IpVersion};

/// Drop-in file that registers the tunnel routing table name with iproute2.
///
/// iproute2 reads `/etc/iproute2/rt_tables` and, only when that file does not
/// exist, falls back to `/usr/share/iproute2/rt_tables` (where newer releases
/// and some distros ship it). Appending to `/etc/iproute2/rt_tables` would
/// create that file on such systems and shadow the distro one, so `ip` would
/// lose the `main`/`local`/`default` names. The `rt_tables.d/*.conf` drop-in
/// directory is read in both layouts and lets us own a file outright, so
/// cleanup is a plain unlink instead of rewriting a shared file.
const RT_TABLES_DROPIN_DIR: &str = "/etc/iproute2/rt_tables.d";
const RT_TABLES_DROPIN_PATH: &str = "/etc/iproute2/rt_tables.d/lightway.conf";

/// Prefix for all policy-routing names used by Lightway.
///
/// Each rule and the tunnel routing table get a distinct name under this prefix:
///
/// | Rule             | Name                                  | Visible in              |
/// | ---------------- | ------------------------------------- | ----------------------- |
/// | MARKED           | `lightway-marked-0x<fwmark>`          | tracing log             |
/// | SERVER           | `lightway-server`                     | tracing log             |
/// | MARKED_FALLBACK  | `lightway-marked-0x<fwmark>-fallback` | tracing log             |
/// | SUPPRESS_DEFAULT | `lightway-suppress-default`           | tracing log             |
/// | TUNNEL (table)   | `lightway-tunnel`                     | tracing log + rt_tables |
///
/// Only the tunnel routing table name is registered in
/// `/etc/iproute2/rt_tables.d/lightway.conf` because ip rules themselves have
/// no name field; the kernel identifies them by priority alone.
const TABLE_PREFIX: &str = "lightway";

/// Writes `"<id>\t<name>"` to `/etc/iproute2/rt_tables.d/lightway.conf`,
/// creating the directory if it does not yet exist.
///
/// The file is owned by Lightway, so it is simply overwritten: a stale entry
/// from a previous run (possibly with a different id) is replaced rather than
/// appended to. The kernel never reads this file; it only affects how `ip`
/// displays the table.
fn register_rt_table(id: u32, name: &str) -> Result<()> {
    std::fs::create_dir_all(RT_TABLES_DROPIN_DIR)
        .with_context(|| format!("Cannot create {RT_TABLES_DROPIN_DIR}"))?;
    std::fs::write(RT_TABLES_DROPIN_PATH, format!("{id}\t{name}\n"))
        .with_context(|| format!("Cannot write to {RT_TABLES_DROPIN_PATH}"))?;
    tracing::debug!(id, name, "Registered routing table name");
    Ok(())
}

/// Removes `/etc/iproute2/rt_tables.d/lightway.conf`.
///
/// A missing file is not an error: registration may have failed or never run.
fn unregister_rt_table() {
    match std::fs::remove_file(RT_TABLES_DROPIN_PATH) {
        Ok(()) => tracing::debug!("Unregistered routing table name"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("Cannot remove {RT_TABLES_DROPIN_PATH} during cleanup: {e}"),
    }
}

/// Default firewall mark (`SO_MARK`) applied to the outside socket under `RouteMode::Fwmark` (Linux
/// only).
///
/// Helium atomic symbol in Little-Endian byte order with padding
/// number, an uncommon value unlikely to clash with other marks.
pub const DEFAULT_FWMARK: u32 = 0x4865_0000;

/// Priority of the rule matching the tunnel's own (marked) traffic.
pub const RULE_PRIORITY_MARKED: u32 = 100;

/// Priority of the rule that fixes rp_filter for incoming server reply packets.
///
/// See the module-level documentation for a full explanation.
pub const RULE_PRIORITY_SERVER: u32 = 105;

/// Priority of the fallback rule that breaks the encapsulation loop.
///
/// Must be between [`RULE_PRIORITY_SERVER`] and [`RULE_PRIORITY_TUNNEL`].
/// See the module-level documentation for a full explanation.
pub const RULE_PRIORITY_MARKED_FALLBACK: u32 = 107;

/// Suppresses the default route (prefixlen 0) to prevent LAN traffic from being
/// routed into the tunnel. Must be between [`RULE_PRIORITY_MARKED_FALLBACK`]
/// and [`RULE_PRIORITY_TUNNEL`].
pub const RULE_PRIORITY_SUPPRESS_DEFAULT: u32 = 109;

/// Priority of the rule sending everything else into the tunnel table.
pub const RULE_PRIORITY_TUNNEL: u32 = 110;

/// All fwmark policy-routing parameters bundled together.
///
/// Build one from [`crate::config::Config::fwmark_config`] and pass it to
/// [`PolicyRouting::new`] to avoid threading five individual parameters through
/// the call stack.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FWMarkConfig {
    /// Firewall mark (`SO_MARK`) set on the outside socket.
    pub fwmark: u32,
    /// Routing table id that holds the tunnel routes (must be 1..=252).
    pub table: u8,
    /// Priority of the tunnel-socket rule (must be < `rule_priority_marked_fallback`).
    pub rule_priority_marked: u32,
    /// Priority of the rp_filter-bypass rule (must be < `rule_priority_tunnel`).
    pub rule_priority_server: u32,
    /// Priority of the loop-breaker rule (must be < `rule_priority_tunnel`).
    pub rule_priority_marked_fallback: u32,
    /// Priority of the suppress-default rule (must be < `rule_priority_tunnel`).
    pub rule_priority_suppress_default: u32,
    /// Priority of the catch-all tunnel rule (must be > `rule_priority_marked` and `rule_priority_marked_fallback`).
    pub rule_priority_tunnel: u32,
}

/// `main` routing table id.
const RT_TABLE_MAIN: u32 = 254;

/// Installs and removes the policy routing rules for a marked tunnel.
///
/// The installed rules are remembered so that [`Self::cleanup`] removes exactly
/// what was added, rather than deleting anything that happens to match.
pub struct PolicyRouting {
    handle: Handle,
    /// Netlink connection task; dropping it tears the connection down.
    _conn: tokio::task::JoinHandle<()>,
    installed: Vec<RuleMessage>,
    fwmark: u32,
    table: u8,
    server_ipv4: Option<Ipv4Addr>,
    rule_priority_marked: u32,
    rule_priority_server: u32,
    rule_priority_marked_fallback: u32,
    rule_priority_suppress_default: u32,
    rule_priority_tunnel: u32,
    cfg: FWMarkConfig,
}

impl PolicyRouting {
    /// Opens a netlink connection for rule manipulation.
    ///
    /// `server_ip` should be the VPN server's IPv4 address.  It is used to
    /// install the rp_filter-bypass rule (priority [`RULE_PRIORITY_SERVER`]).
    /// Pass `None` for IPv6-only servers where rp_filter handling is not needed.
    pub fn new(cfg: FWMarkConfig, server_ip: std::net::IpAddr) -> Result<Self> {
        let server_ipv4 = match server_ip {
            std::net::IpAddr::V4(a) => Some(a),
            std::net::IpAddr::V6(_) => None,
        };
        let (conn, handle, _) =
            rtnetlink::new_connection().context("Failed to open netlink connection for rules")?;
        let conn = tokio::spawn(async move {
            conn.await;
        });
        Ok(Self {
            handle,
            _conn: conn,
            installed: Vec::new(),
            fwmark: cfg.fwmark,
            table: cfg.table,
            server_ipv4,
            rule_priority_marked: cfg.rule_priority_marked,
            rule_priority_server: cfg.rule_priority_server,
            rule_priority_marked_fallback: cfg.rule_priority_marked_fallback,
            rule_priority_suppress_default: cfg.rule_priority_suppress_default,
            rule_priority_tunnel: cfg.rule_priority_tunnel,
            cfg,
        })
    }

    /// Installs all policy routing rules.
    ///
    /// Call this *before* any tunnel route is installed, so that no traffic can
    /// be routed into the tunnel while only a subset of the rules exists.
    pub async fn install(&mut self) -> Result<()> {
        // Clean up any stale rules from a previous crashed/incomplete start.
        // If the process dies after calling install() but before cleanup(), these
        // rules would remain and cause `File exists` errors on the next start.
        // This ensures idempotence: restarting always cleans up first.
        self.cleanup_old_rules().await;

        let marked_name = format!("{TABLE_PREFIX}-marked-0x{:x}", self.fwmark);
        let server_name = format!("{TABLE_PREFIX}-server");
        let marked_fallback_name = format!("{TABLE_PREFIX}-marked-0x{:x}-fallback", self.fwmark);
        let tunnel_name = format!("{TABLE_PREFIX}-tunnel");

        // Rule MARKED: marked traffic (the tunnel socket) resolves via `main`.
        self.add_rule(
            self.rule_priority_marked,
            Some(self.fwmark),
            RT_TABLE_MAIN,
            &marked_name,
        )
        .await
        .context("Failed to add fwmark rule")?;

        // rp_filter fix — unmarked lookups for the server IP are
        // redirected to main so that strict rp_filter accepts the server's
        // reply packets (which arrive on the physical interface, not the tunnel).
        if let Some(server_ipv4) = self.server_ipv4 {
            self.add_rule_with_destination(
                self.rule_priority_server,
                server_ipv4,
                Ipv4Addr::BITS as u8,
                RT_TABLE_MAIN,
                &server_name,
            )
            .await
            .context("Failed to add server-IP rp_filter rule")?;
        }

        // loop-breaker — if `main` has no route for marked traffic
        // (e.g. during a Wi-Fi roam when the default route is momentarily
        // absent), return ENETUNREACH instead of falling through to
        // rule_priority_tunnel and starting an encapsulation loop.
        self.add_fwmark_unreachable_rule(
            self.rule_priority_marked_fallback,
            self.fwmark,
            &marked_fallback_name,
        )
        .await
        .context("Failed to add fwmark fallback rule")?;

        // Suppress the default route from being matched via main table,
        // allowing more-specific routes (e.g. LAN) to be used instead.
        // This prevents LAN traffic from being incorrectly routed into the tunnel.
        let suppress_name = format!("{TABLE_PREFIX}-suppress-default");
        self.add_suppress_default_rule(
            self.rule_priority_suppress_default,
            RT_TABLE_MAIN,
            &suppress_name,
        )
        .await
        .context("Failed to add suppress-default rule")?;

        // Register the tunnel table name so that `ip rule show` displays
        // `from all lookup lightway-tunnel` instead of a bare table id.
        if let Err(e) = register_rt_table(self.table as u32, &tunnel_name).with_context(|| {
            format!("Failed to register '{tunnel_name}' in {RT_TABLES_DROPIN_PATH}")
        }) {
            tracing::error!("Fail to register table name: {}", e);
        }

        self.add_rule(
            self.rule_priority_tunnel,
            None,
            self.table as u32,
            &tunnel_name,
        )
        .await
        .context("Failed to add tunnel table rule")?;

        tracing::info!(
            fwmark = self.fwmark,
            table = tunnel_name,
            table_id = self.table,
            "Installed policy routing rules"
        );
        Ok(())
    }

    async fn add_rule(
        &mut self,
        priority: u32,
        fwmark: Option<u32>,
        table: u32,
        rule_name: &str,
    ) -> Result<()> {
        let mut req = self
            .handle
            .rule()
            .add()
            .v4()
            .priority(priority)
            .table_id(table)
            .action(RuleAction::ToTable);

        if let Some(mark) = fwmark {
            req = req.fw_mark(mark);
        }

        let message = req.message_mut().clone();
        req.execute().await?;
        self.installed.push(message);

        tracing::debug!(priority, ?fwmark, table, rule_name, "Added ip rule");
        Ok(())
    }

    async fn add_rule_with_destination(
        &mut self,
        priority: u32,
        destination: Ipv4Addr,
        prefix_len: u8,
        table: u32,
        rule_name: &str,
    ) -> Result<()> {
        let mut req = self
            .handle
            .rule()
            .add()
            .v4()
            .priority(priority)
            .table_id(table)
            .action(RuleAction::ToTable)
            .destination_prefix(destination, prefix_len);

        let message = req.message_mut().clone();
        req.execute().await?;
        self.installed.push(message);

        tracing::debug!(priority, %destination, prefix_len, table, rule_name, "Added ip rule with destination");
        Ok(())
    }

    /// Adds a `fwmark <mark> unreachable` rule (no table lookup).
    ///
    /// The kernel maps `FR_ACT_UNREACHABLE` to `ENETUNREACH`, which the
    /// outside-IO send callback already handles as a transient failure.
    async fn add_fwmark_unreachable_rule(
        &mut self,
        priority: u32,
        fwmark: u32,
        rule_name: &str,
    ) -> Result<()> {
        let mut req = self
            .handle
            .rule()
            .add()
            .v4()
            .priority(priority)
            .action(RuleAction::Unreachable)
            .fw_mark(fwmark);

        let message = req.message_mut().clone();
        req.execute().await?;
        self.installed.push(message);

        tracing::debug!(
            priority,
            fwmark,
            rule_name,
            "Added fwmark unreachable ip rule"
        );
        Ok(())
    }

    /// Adds a rule that suppresses the default route from being matched.
    ///
    /// This allows more-specific routes from the main table (like LAN routes) to be
    /// used instead of falling through to the tunnel. The suppress_prefixlen=0 flag
    /// prevents the kernel from matching the default route (0.0.0.0/0).
    /// Traffic to non-default destinations will match main table routes before being
    /// sent to the tunnel table.
    async fn add_suppress_default_rule(
        &mut self,
        priority: u32,
        table: u32,
        rule_name: &str,
    ) -> Result<()> {
        let mut req = self
            .handle
            .rule()
            .add()
            .v4()
            .priority(priority)
            .table_id(table)
            .action(RuleAction::ToTable);

        req.message_mut()
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(0));

        let message = req.message_mut().clone();
        req.execute().await?;
        self.installed.push(message);

        tracing::debug!(priority, table, rule_name, "Added suppress-default ip rule");
        Ok(())
    }

    /// Attempts to delete any stale Lightway rules from a previous incomplete start.
    ///
    /// Called at the start of `install()` to ensure idempotence: if the process
    /// crashes after rules are added but before cleanup() runs, the next start
    /// will clean them up before adding new ones.
    ///
    /// Rules are matched on their full shape (see [`classify_rule`]), never on
    /// priority alone, so a rule that other software installed at the same
    /// priority is left untouched. Each matching rule is deleted by sending the
    /// exact message the kernel reported back to it, which is how
    /// `ip rule flush` works too.
    ///
    /// Failures are logged (stale rules are bad, but silently failing to start
    /// is worse).
    async fn cleanup_old_rules(&self) {
        let mut rules = self.handle.rule().get(IpVersion::V4).execute();
        let mut stale = Vec::new();
        loop {
            match rules.try_next().await {
                Ok(Some(rule)) => {
                    if let Some(name) = classify_rule(&self.cfg, &rule) {
                        stale.push((name, rule));
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("Failed to list ip rules during stale rule cleanup: {e}");
                    break;
                }
            }
        }

        for (name, rule) in stale {
            let priority = rule_priority(&rule);
            match self.handle.rule().del(rule).execute().await {
                Ok(()) => tracing::info!(
                    rule = name,
                    priority,
                    "Removed stale policy routing rule left by a previous run"
                ),
                Err(e) => tracing::warn!(
                    rule = name,
                    priority,
                    "Failed to remove stale policy routing rule: {e}"
                ),
            }
        }
    }

    /// Removes every rule this instance installed and unregisters the table
    /// name from `/etc/iproute2/rt_tables.d/lightway.conf`.
    ///
    /// Failures are logged rather than propagated: leaving a stale rule behind
    /// is bad, but aborting cleanup half way through is worse.
    pub async fn cleanup(&mut self) {
        for message in self.installed.drain(..).rev() {
            if let Err(e) = self.handle.rule().del(message).execute().await {
                tracing::warn!("Failed to delete ip rule during cleanup: {e}");
            }
        }
        unregister_rt_table();
        tracing::info!("Removed policy routing rules");
    }
}

/// Returns the name of the Lightway rule that `rule` (as reported by the
/// kernel) corresponds to, or `None` when it is not one of ours.
///
/// A rule is only recognised when *everything* matches what
/// [`PolicyRouting::install`] would have created: priority, action, table,
/// fwmark, destination prefix and suppress-prefixlen, plus the absence of any
/// other selector (source prefix, interface names, uid or port ranges, ...).
/// Sharing a priority with one of our rules is therefore never enough to be
/// deleted.
///
/// The SERVER rule is matched for *any* IPv4 `/32` destination, not only the
/// current server address, so that a stale rule for a previous server does not
/// keep steering that address around the tunnel.
fn classify_rule(cfg: &FWMarkConfig, rule: &RuleMessage) -> Option<&'static str> {
    let header = &rule.header;
    if header.family != AddressFamily::Inet || header.src_len != 0 || header.tos != 0 {
        return None;
    }

    let mut priority = None;
    let mut fwmark = None;
    let mut table = u32::from(header.table);
    let mut suppress_prefixlen = None;
    let mut destination = None;
    for attr in &rule.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = Some(*p),
            RuleAttribute::FwMark(m) => fwmark = Some(*m),
            RuleAttribute::Table(t) => table = *t,
            RuleAttribute::SuppressPrefixLen(n) => suppress_prefixlen = Some(*n),
            RuleAttribute::Destination(IpAddr::V4(a)) => destination = Some(*a),
            RuleAttribute::Destination(IpAddr::V6(_)) => return None,
            // Reported by the kernel for every rule; they do not narrow the match.
            RuleAttribute::FwMask(_) | RuleAttribute::Protocol(_) => {}
            // Attributes this crate version does not know about. The kernel
            // only reports selectors that are actually set, so one of these
            // could be a selector we cannot see; it is accepted anyway so a
            // newer kernel that adds an always-present attribute does not
            // make our own rules unrecognisable.
            RuleAttribute::Other(_) => {}
            // Any other selector means this rule was not installed by us.
            _ => return None,
        }
    }

    let priority = priority?;
    let to_main = header.action == RuleAction::ToTable && table == RT_TABLE_MAIN;
    let no_destination = destination.is_none() && header.dst_len == 0;

    if priority == cfg.rule_priority_marked
        && to_main
        && fwmark == Some(cfg.fwmark)
        && suppress_prefixlen.is_none()
        && no_destination
    {
        return Some("MARKED");
    }
    if priority == cfg.rule_priority_server
        && to_main
        && fwmark.is_none()
        && suppress_prefixlen.is_none()
        && destination.is_some()
        && header.dst_len == Ipv4Addr::BITS as u8
    {
        return Some("SERVER");
    }
    if priority == cfg.rule_priority_marked_fallback
        && header.action == RuleAction::Unreachable
        && fwmark == Some(cfg.fwmark)
        && suppress_prefixlen.is_none()
        && no_destination
    {
        return Some("MARKED_FALLBACK");
    }
    if priority == cfg.rule_priority_suppress_default
        && to_main
        && fwmark.is_none()
        && suppress_prefixlen == Some(0)
        && no_destination
    {
        return Some("SUPPRESS_DEFAULT");
    }
    if priority == cfg.rule_priority_tunnel
        && header.action == RuleAction::ToTable
        && table == u32::from(cfg.table)
        && fwmark.is_none()
        && suppress_prefixlen.is_none()
        && no_destination
    {
        return Some("TUNNEL");
    }
    None
}

/// Priority attribute of a rule, for logging.
fn rule_priority(rule: &RuleMessage) -> Option<u32> {
    rule.attributes.iter().find_map(|attr| match attr {
        RuleAttribute::Priority(p) => Some(*p),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::route::RouteProtocol;

    fn cfg() -> FWMarkConfig {
        FWMarkConfig {
            fwmark: DEFAULT_FWMARK,
            table: 100,
            rule_priority_marked: RULE_PRIORITY_MARKED,
            rule_priority_server: RULE_PRIORITY_SERVER,
            rule_priority_marked_fallback: RULE_PRIORITY_MARKED_FALLBACK,
            rule_priority_suppress_default: RULE_PRIORITY_SUPPRESS_DEFAULT,
            rule_priority_tunnel: RULE_PRIORITY_TUNNEL,
        }
    }

    /// Builds a rule the way the kernel reports it: `table` in the header,
    /// `FRA_PROTOCOL` always present.
    fn rule(
        priority: u32,
        action: RuleAction,
        table: u32,
        extra: Vec<RuleAttribute>,
    ) -> RuleMessage {
        let mut msg = RuleMessage::default();
        msg.header.family = AddressFamily::Inet;
        msg.header.action = action;
        msg.header.table = table.min(255) as u8;
        msg.attributes.push(RuleAttribute::Priority(priority));
        if table > 255 {
            msg.attributes.push(RuleAttribute::Table(table));
        }
        msg.attributes
            .push(RuleAttribute::Protocol(RouteProtocol::Unspec));
        msg.attributes.extend(extra);
        msg
    }

    #[test]
    fn recognises_own_rules() {
        let c = cfg();

        let marked = rule(
            c.rule_priority_marked,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![
                RuleAttribute::FwMark(c.fwmark),
                RuleAttribute::FwMask(u32::MAX),
            ],
        );
        assert_eq!(classify_rule(&c, &marked), Some("MARKED"));

        let mut server = rule(
            c.rule_priority_server,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![RuleAttribute::Destination(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 7,
            )))],
        );
        server.header.dst_len = 32;
        assert_eq!(
            classify_rule(&c, &server),
            Some("SERVER"),
            "any /32 server IP is ours"
        );

        let fallback = rule(
            c.rule_priority_marked_fallback,
            RuleAction::Unreachable,
            RT_TABLE_MAIN,
            vec![RuleAttribute::FwMark(c.fwmark)],
        );
        assert_eq!(classify_rule(&c, &fallback), Some("MARKED_FALLBACK"));

        let suppress = rule(
            c.rule_priority_suppress_default,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![RuleAttribute::SuppressPrefixLen(0)],
        );
        assert_eq!(classify_rule(&c, &suppress), Some("SUPPRESS_DEFAULT"));

        let tunnel = rule(
            c.rule_priority_tunnel,
            RuleAction::ToTable,
            u32::from(c.table),
            vec![],
        );
        assert_eq!(classify_rule(&c, &tunnel), Some("TUNNEL"));
    }

    #[test]
    fn ignores_foreign_rules_at_same_priority() {
        let c = cfg();

        // Same priority as MARKED, but somebody else's mark.
        let other_mark = rule(
            c.rule_priority_marked,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![RuleAttribute::FwMark(c.fwmark + 1)],
        );
        assert_eq!(classify_rule(&c, &other_mark), None);

        // Same priority as MARKED, no mark at all (e.g. `from all lookup main`).
        let plain_main = rule(
            c.rule_priority_marked,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![],
        );
        assert_eq!(classify_rule(&c, &plain_main), None);

        // Same priority as TUNNEL, but a different table.
        let other_table = rule(
            c.rule_priority_tunnel,
            RuleAction::ToTable,
            u32::from(c.table) + 1,
            vec![],
        );
        assert_eq!(classify_rule(&c, &other_table), None);

        // Looks like MARKED but carries an extra selector.
        let mut with_source = rule(
            c.rule_priority_marked,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![
                RuleAttribute::FwMark(c.fwmark),
                RuleAttribute::Source(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))),
            ],
        );
        with_source.header.src_len = 8;
        assert_eq!(classify_rule(&c, &with_source), None);

        let with_iif = rule(
            c.rule_priority_marked,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![
                RuleAttribute::FwMark(c.fwmark),
                RuleAttribute::Iifname("eth0".into()),
            ],
        );
        assert_eq!(classify_rule(&c, &with_iif), None);

        // Same priority as SERVER, but not a host route.
        let mut subnet = rule(
            c.rule_priority_server,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![RuleAttribute::Destination(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 0,
            )))],
        );
        subnet.header.dst_len = 24;
        assert_eq!(classify_rule(&c, &subnet), None);

        // IPv6 rules are never ours.
        let mut v6 = rule(
            c.rule_priority_marked,
            RuleAction::ToTable,
            RT_TABLE_MAIN,
            vec![RuleAttribute::FwMark(c.fwmark)],
        );
        v6.header.family = AddressFamily::Inet6;
        assert_eq!(classify_rule(&c, &v6), None);
    }
}
