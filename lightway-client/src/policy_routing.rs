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
//! The tunnel routes move out of *main* into a private table, and four rules
//! determine which table is consulted:
//!
//! ```text
//! priority 100:  fwmark <MARK>              lookup main   # (1) tunnel socket → WAN
//! priority 105:  to <SERVER_IP>/32          lookup main   # (2) rp_filter fix (see below)
//! priority 107:  fwmark <MARK>              unreachable   # (3) loop-breaker (see below)
//! priority 110:  (no condition)             lookup <TABLE># (4) all other traffic → tunnel
//! ```
//!
//! The tunnel's outside socket carries `<MARK>`, so its outgoing packets hit
//! Rule MARKED and resolve via *main* — whose default route the kernel keeps
//! current on its own, with no Lightway-managed entry involved.
//!
//! # Rule 105 — rp_filter fix
//!
//! Linux's reverse-path filter (strict mode, `rp_filter=1`) checks incoming
//! packets by looking up the *source* IP through the routing rules — but using
//! the *incoming packet's* mark, which is 0 for plain packets from the WAN.
//!
//! After rule 110 is installed, an unmarked lookup for the server IP falls
//! through rules 100 and 107 (both require `fwmark <MARK>`) and lands on
//! rule 110 → tunnel table → `0.0.0.0/1 via lightway`.  Strict rp_filter
//! would then consider `SERVER_IP` routed via `lightway`, but the server's
//! reply packet arrived on `wlan0` (or whichever physical interface), producing
//! an interface mismatch and silently **dropping** every pong — which the
//! keepalive mechanism observes as a timeout.
//!
//! Rule 105 intercepts the unmarked lookup for `<SERVER_IP>/32` and redirects
//! it to *main*, where the WAN default route sends it back out the physical
//! interface.  rp_filter sees a consistent interface and accepts the packet.
//!
//! # Rule 107 — loop-breaker
//!
//! `ip rule` falls through to the next rule when the selected table returns no
//! matching route.  During a Wi-Fi roam, the kernel removes the old default
//! route from *main* before a new one arrives.  In that brief window:
//!
//! 1. Rule 100: `fwmark <MARK> → lookup main` — no route → **fall through**
//! 2. Rule 105: `to <SERVER_IP>/32 → lookup main` — no route → **fall through**
//! 3. Rule 107: (absent without this fix) — skipped
//! 4. Rule 110: `→ lookup <TABLE>` — `0.0.0.0/1` and `128.0.0.0/1` via `tun`
//!    — the VPN socket's own encrypted packet is read back off the tun device
//!    as an inside packet, re-encapsulated (+69 bytes per lap), and re-sent →
//!    **encapsulation loop**.
//!
//! Rule 107 (`fwmark <MARK> unreachable`) intercepts the fall-through:
//! - During normal operation marked packets are already handled by rule 100 and
//!   rule 107 is never reached.
//! - During a roam, marked packets fall through rules 100 and 105 (both consult
//!   *main*, which has no route) and hit rule 107, which returns `ENETUNREACH`
//!   to the caller.  The outside I/O callback already treats this as a transient
//!   send failure, dropping the packet cleanly and preventing the loop.

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
// Use rtnetlink's re-export rather than depending on netlink-packet-route
// directly: that guarantees these types come from the exact same crate version
// rtnetlink itself was built against.
use rtnetlink::Handle;
use rtnetlink::packet_route::rule::{RuleAction, RuleMessage};

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
pub const RULE_PRIORITY_FWMARK_FALLBACK: u32 = 107;

/// Priority of the rule sending everything else into the tunnel table.
pub const RULE_PRIORITY_TUNNEL: u32 = 110;

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
}

impl PolicyRouting {
    /// Opens a netlink connection for rule manipulation.
    ///
    /// `server_ip` should be the VPN server's IPv4 address.  It is used to
    /// install the rp_filter-bypass rule (priority [`RULE_PRIORITY_SERVER`]).
    /// Pass `None` for IPv6-only servers where rp_filter handling is not needed.
    pub fn new(fwmark: u32, table: u8, server_ip: std::net::IpAddr) -> Result<Self> {
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
            fwmark,
            table,
            server_ipv4,
        })
    }

    /// Installs all policy routing rules.
    ///
    /// Call this *before* any tunnel route is installed, so that no traffic can
    /// be routed into the tunnel while only a subset of the rules exists.
    pub async fn install(&mut self) -> Result<()> {
        // Rule 100: marked traffic (the tunnel socket) resolves via `main`.
        self.add_rule(RULE_PRIORITY_MARKED, Some(self.fwmark), RT_TABLE_MAIN)
            .await
            .context("Failed to add fwmark rule")?;

        // Rule 105: rp_filter fix — unmarked lookups for the server IP are
        // redirected to main so that strict rp_filter accepts the server's
        // reply packets (which arrive on the physical interface, not the tunnel).
        if let Some(server_ipv4) = self.server_ipv4 {
            self.add_rule_with_destination(
                RULE_PRIORITY_SERVER,
                server_ipv4,
                Ipv4Addr::BITS as u8,
                RT_TABLE_MAIN,
            )
            .await
            .context("Failed to add server-IP rp_filter rule")?;
        }

        // Rule 107: loop-breaker — if `main` has no route for marked traffic
        // (e.g. during a Wi-Fi roam when the default route is momentarily
        // absent), return ENETUNREACH instead of falling through to
        // RULE_PRIORITY_TUNNEL and starting an encapsulation loop.
        self.add_fwmark_unreachable_rule(RULE_PRIORITY_FWMARK_FALLBACK, self.fwmark)
            .await
            .context("Failed to add fwmark fallback rule")?;

        // Rule 110: everything else goes to the tunnel table.
        self.add_rule(RULE_PRIORITY_TUNNEL, None, self.table as u32)
            .await
            .context("Failed to add tunnel table rule")?;

        tracing::info!(
            fwmark = self.fwmark,
            table = self.table,
            "Installed policy routing rules"
        );
        Ok(())
    }

    async fn add_rule(&mut self, priority: u32, fwmark: Option<u32>, table: u32) -> Result<()> {
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

        tracing::debug!(priority, ?fwmark, table, "Added ip rule");
        Ok(())
    }

    async fn add_rule_with_destination(
        &mut self,
        priority: u32,
        destination: Ipv4Addr,
        prefix_len: u8,
        table: u32,
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

        tracing::debug!(priority, %destination, prefix_len, table, "Added ip rule with destination");
        Ok(())
    }

    /// Adds a `fwmark <mark> unreachable` rule (no table lookup).
    ///
    /// The kernel maps `FR_ACT_UNREACHABLE` to `ENETUNREACH`, which the
    /// outside-IO send callback already handles as a transient failure.
    async fn add_fwmark_unreachable_rule(&mut self, priority: u32, fwmark: u32) -> Result<()> {
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

        tracing::debug!(priority, fwmark, "Added fwmark unreachable ip rule");
        Ok(())
    }

    /// Removes every rule this instance installed.
    ///
    /// Failures are logged rather than propagated: leaving a stale rule behind
    /// is bad, but aborting cleanup half way through is worse.
    pub async fn cleanup(&mut self) {
        for message in self.installed.drain(..).rev() {
            if let Err(e) = self.handle.rule().del(message).execute().await {
                tracing::warn!("Failed to delete ip rule during cleanup: {e}");
            }
        }
        tracing::info!("Removed policy routing rules");
    }
}
