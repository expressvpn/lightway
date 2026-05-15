use anyhow::Result;
use route_manager::{AsyncRouteListener, RouteChange};
use tracing::{error, info, warn};

/// A simple example that monitors route changes and prints them to the console.
/// This demonstrates how the route monitoring functionality works in the lightway client.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with INFO level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting route monitoring example...");
    info!("This example will monitor system route changes and print them.");
    info!("Press Ctrl+C to exit.");

    // Create an AsyncRouteListener
    let mut listener = match AsyncRouteListener::new() {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to create AsyncRouteListener: {}", e);
            return Err(e.into());
        }
    };

    info!("Route monitoring started successfully!");
    info!("Try changing your network connection or adding/removing routes to see changes.");

    // Listen for route changes in a loop
    loop {
        match listener.listen().await {
            Ok(route_change) => {
                print_route_change(&route_change);
            }
            Err(e) => {
                error!("Error listening for route changes: {}", e);
                // Continue monitoring even on errors with a small delay
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Prints information about a route change in a human-readable format
fn print_route_change(route_change: &RouteChange) {
    match route_change {
        RouteChange::Add(route) => {
            info!("🟢 ROUTE ADDED:");
            print_route_details(route);
        }
        RouteChange::Delete(route) => {
            warn!("🔴 ROUTE DELETED:");
            print_route_details(route);
        }
        RouteChange::Change(route) => {
            info!("🟡 ROUTE CHANGED:");
            print_route_details(route);
        }
    }
    println!(); // Add a blank line for readability
}

/// Prints detailed information about a route
fn print_route_details(route: &route_manager::Route) {
    if route.destination().is_ipv6() {
        return;
    }
    println!("   Destination: {}/{}", route.destination(), route.prefix());

    if let Some(gateway) = route.gateway() {
        println!("   Gateway: {}", gateway);
    } else {
        println!("   Gateway: Direct (no gateway)");
    }

    if let Some(if_index) = route.if_index() {
        println!("   Interface Index: {}", if_index);
    }

    // metric is only supported in linux and windows
    #[cfg(any(windows, linux))]
    if let Some(metric) = route.metric() {
        println!("   Metric: {}", metric);
    }

    // Filter out IPv6 routes for clarity in this example, but still show them
    if route.destination().is_ipv6() {
        println!("   Type: IPv6 route");
    } else {
        println!("   Type: IPv4 route");

        // Show if this is a default route (commonly watched in VPN scenarios)
        if route.prefix() == 0 {
            println!("   ⚠️  This is a DEFAULT ROUTE (0.0.0.0/0) - important for VPN routing!");
        }

        // Show if this is a host route
        if route.prefix() == 32 {
            println!("   📍 This is a HOST ROUTE (/32) - specific destination");
        }
    }
}
