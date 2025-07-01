use clap_mangen::Man;
use std::fs;
use std::io::Write;
use std::path::Path;

// Import the config structs from the client and server
use lightway_client::args::Config as ClientConfig;
use lightway_server::args::Config as ServerConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create output directory
    let out_dir = Path::new("man");
    fs::create_dir_all(out_dir)?;

    println!("Generating man pages...");

    // Generate client man page
    let client_cmd = ClientConfig::command_for_manpage();
    let client_man = Man::new(client_cmd);
    let mut client_buffer = Vec::new();
    client_man.render(&mut client_buffer)?;

    let mut client_file = fs::File::create(out_dir.join("lightway-client.1"))?;
    client_file.write_all(&client_buffer)?;
    println!("Generated lightway-client.1");

    // Generate server man page
    let server_cmd = ServerConfig::command_for_manpage();
    let server_man = Man::new(server_cmd);
    let mut server_buffer = Vec::new();
    server_man.render(&mut server_buffer)?;

    let mut server_file = fs::File::create(out_dir.join("lightway-server.1"))?;
    server_file.write_all(&server_buffer)?;
    println!("Generated lightway-server.1");

    println!("Man pages generated successfully in {}", out_dir.display());

    Ok(())
}
