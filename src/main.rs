/**
 * A utility for checking ZooKeeper is up.
 * You can specify a command line parameter to specify a name
 * or zookeeper connection string. If no parameter is provided
 * it will use the ZK_HOST environment variable.
 * The utility will repeatedly look up names and try connect to
 * all resolved addresses until it can successfully see a leader
 * or standalone node. This works specifically well from a kubernetes
 * init container, where a headless name is repeatedly looked up
 * and returns more addresses as pods come online.
 * It also works with IPv4 an IPv6 addressses.
 * To run in verbose mode, set the RUST_LOG=zk_wait_rust=debug environment
 * variable.
 */
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate regex;

use clap::{App, Arg, ArgMatches};
use log::Level;
use parse_duration;
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::io::prelude::*;
use std::net::IpAddr;
use std::net::TcpStream;
use std::net::*;
use std::process;
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::u16;
use trust_dns_resolver::Resolver;

const SRVR_COMMAND: &[u8] = b"srvr\n";
const ZOOKEEPER_CLIENT_PORT: u16 = 2181;

const CONNECT_TIMEOUT_SECONDS: u64 = 5;
const READ_TIMEOUT_SECONDS: u64 = 5;
const WRITE_TIMEOUT_SECONDS: u64 = 5;

#[derive(PartialEq, Debug, Clone, Copy)]
enum ZooKeeperMode {
    Leader,
    Follower,
    Standalone,
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
enum IpStrategy {
    Ipv4Only,
    Ipv6Only,
    Ipv4thenIpv6,
}

/// Get the ZooKeeper mode for the provided address.
/// This sets IO timeouts, and returns ZooKeeperMode::Unknown
/// if anything goes wrong, so it gets retried on the next pass
fn get_zookeeper_mode(address: &SocketAddr) -> Result<ZooKeeperMode, String> {
    debug!("connecting to {}", address);
    let connect_timeout = Duration::new(CONNECT_TIMEOUT_SECONDS, 0);
    let mut stream;
    match TcpStream::connect_timeout(address, connect_timeout) {
        Ok(s) => {
            stream = s;
        }
        Err(e) => {
            return Err(format!(
                "Failed to connect to {} in {:?}: {}",
                &address, &connect_timeout, e
            ));
        }
    }
    // set read/write timeouts so that we don't get hung up by one stuck server
    let write_timeout = Duration::new(WRITE_TIMEOUT_SECONDS, 0);
    if let Err(e) = stream.set_write_timeout(Some(write_timeout)) {
        return Err(format!(
            "failed to set write timeout to {:?}: {}",
            &write_timeout, e
        ));
    }
    let read_timeout = Duration::new(READ_TIMEOUT_SECONDS, 0);
    if let Err(e) = stream.set_read_timeout(Some(read_timeout)) {
        return Err(format!(
            "failed to set read timeout to {:?}: {}",
            &read_timeout, e
        ));
    }
    if let Err(e) = stream.write(&SRVR_COMMAND) {
        return Err(format!("failed to write the srvr command: {}", e));
    }
    let mut buffer = String::new();
    if let Err(e) = stream.read_to_string(&mut buffer) {
        return Err(format!("failed to read from the server: {}", e));
    }

    lazy_static! {
        static ref MODE_RE: Regex = Regex::new(r"Mode: ([[:alpha:]]+)\r?\n").unwrap();
    }

    match MODE_RE.find(&buffer) {
        Some(matched) => {
            debug!("{} is {:?}", address, matched.as_str());

            match matched.as_str() {
                "leader" => Ok(ZooKeeperMode::Leader),
                "follower" => Ok(ZooKeeperMode::Follower),
                "standalone" => Ok(ZooKeeperMode::Standalone),
                _ => Err(format!("unknown mode {}", matched.as_str())),
            }
        }
        None => Err("no Mode found in response".to_string()),
    }
}

fn parse_name(name_string: &str, ip_strategy: IpStrategy) -> Vec<SocketAddr> {
    // Get a DNS resolver configured from the system, so /etc/resolv.conf gets used
    // I can't see a way of overriding the resolver options config::ResolverOpts::ip_strategy
    // afterwards, so we can to implement the
    let resolver = Resolver::from_system_conf().unwrap();

    // Typically the "name" will be a DNS name, which resolves to multiple IP
    // addresses. But we also want to support ZK_HOST-style strings, which
    // contain hostnames/ipv4/ipv6 addresses with optional client ports separated by comma.

    let names: Vec<&str> = name_string.split(',').map(|x| x.trim()).collect();
    let mut address_list = Vec::new();

    for name in names {
        // SocketAddr requires a port 192.0.2.0:123 and [2001:db8::1]:123
        match name.parse::<SocketAddr>() {
            Ok(a) => {
                debug!("parsed SocketAddr address {}: {:?}", name, a);
                if (a.is_ipv4()
                    && (ip_strategy == IpStrategy::Ipv4Only
                        || ip_strategy == IpStrategy::Ipv4thenIpv6))
                    || (a.is_ipv6()
                        && (ip_strategy == IpStrategy::Ipv6Only
                            || ip_strategy == IpStrategy::Ipv4thenIpv6))
                {
                    address_list.push(a);
                }
                continue;
            }
            Err(e) => {
                debug!("could not parse address {} as a SocketAddr: {}", name, e);
            }
        }
        // IpAddr requires no port
        match name.parse::<IpAddr>() {
            Ok(a) => {
                debug!("parsed IpAddr address {}: {:?}", name, a);
                let sa = SocketAddr::new(a, ZOOKEEPER_CLIENT_PORT);
                if (sa.is_ipv4()
                    && (ip_strategy == IpStrategy::Ipv4Only
                        || ip_strategy == IpStrategy::Ipv4thenIpv6))
                    || (sa.is_ipv6()
                        && (ip_strategy == IpStrategy::Ipv6Only
                            || ip_strategy == IpStrategy::Ipv4thenIpv6))
                {
                    address_list.push(sa);
                }
                continue;
            }
            Err(e) => debug!("could not parse address {} as a IpAddr: {}", name, e),
        }

        // We were not able to parse it as an IP address, so assume it is a name
        // to be looked up in the DNS, with or without port number
        let hostname: &str;
        let mut port: u16 = ZOOKEEPER_CLIENT_PORT;
        match name.rfind(':') {
            Some(offset) => {
                let (hostportion, portstr) = name.split_at(offset);
                hostname = hostportion;
                if portstr.len() > 1 {
                    port = u16::from_str_radix(&portstr[1..], 10).unwrap();
                }
            }
            None => {
                hostname = name;
            }
        }

        if ip_strategy == IpStrategy::Ipv4Only || ip_strategy == IpStrategy::Ipv4thenIpv6 {
            debug!("ipv4 lookup for {}", &hostname);
            let lookup_result = resolver.ipv4_lookup(hostname);
            match lookup_result {
                Ok(result) => {
                    for address in result.iter() {
                        let socket_address = SocketAddr::new(IpAddr::V4(*address), port);
                        debug!("found {}", &socket_address);
                        address_list.push(socket_address);
                    }
                }
                Err(e) => debug!("ipv4 lookup failed for {}: {}", hostname, e),
            }
        }
        if ip_strategy == IpStrategy::Ipv6Only || ip_strategy == IpStrategy::Ipv4thenIpv6 {
            debug!("ipv6 lookup for {}", &hostname);
            let lookup_result = resolver.ipv6_lookup(hostname);
            match lookup_result {
                Ok(result) => {
                    for address in result.iter() {
                        let socket_address = SocketAddr::new(IpAddr::V6(*address), port);
                        debug!("found {}", &socket_address);
                        address_list.push(socket_address);
                    }
                }
                Err(e) => debug!("ipv6 lookup failed for {}: {}", hostname, e),
            }
        }
    }

    address_list
}

fn get_app<'a, 'b>() -> App<'a, 'b> {
    App::new("zk-wait-rust")
        .version("1.0")
        .about("Waits for things")
        .arg(
            Arg::with_name("max-wait")
                .long("max-wait")
                .help("Maximum time to wait in seconds")
                .value_name("SECS")
                .takes_value(true)
                .default_value("180"),
        )
        .arg(
            Arg::with_name("wait-seconds")
                .long("wait-seconds")
                .help("Time to sleep between attempts in seconds")
                .value_name("SECS")
                .takes_value(true)
                .default_value("5"),
        )
        .arg(
            Arg::with_name("ipv4")
                .short("4")
                .long("ipv4")
                .takes_value(false)
                .help("Only use IPv4 addresses"),
        )
        .arg(
            Arg::with_name("ipv6")
                .short("6")
                .long("ipv6")
                .takes_value(false)
                .help("Only use IPv6 addresses"),
        )
        .arg(Arg::with_name("name").multiple(false).takes_value(false))
}

fn get_duration_arg(arg_matches: &ArgMatches, name: &str) -> Duration {
    let arg_string = arg_matches.value_of(name).unwrap();
    match parse_duration::parse(arg_string) {
        Ok(v) => {
            debug!("{} = {:?}", name, v);
            v
        }
        Err(e) => {
            error!(
                "could not parse {} value '{:?}' as a duration: {}",
                name, &arg_string, e
            );
            process::exit(1);
        }
    }
}

fn get_ip_strategy_arg(arg_matches: &ArgMatches) -> IpStrategy {
    let ip_strategy;
    if arg_matches.is_present("ipv4") && arg_matches.is_present("ipv6") {
        ip_strategy = IpStrategy::Ipv4thenIpv6;
    } else if arg_matches.is_present("ipv4") {
        ip_strategy = IpStrategy::Ipv4Only;
    } else if arg_matches.is_present("ipv6") {
        ip_strategy = IpStrategy::Ipv6Only;
    } else {
        ip_strategy = IpStrategy::Ipv4thenIpv6;
    }
    debug!("ip_strategy = {:?}", ip_strategy);
    ip_strategy
}

fn get_name_arg(arg_matches: &ArgMatches) -> std::string::String {
    match arg_matches.value_of("name") {
        Some(name) => {
            name.to_string()
        }
        None => {
            env::var("ZK_HOST").unwrap_or_else(|_e| {
                error!("You must specify a name as command-line parameter or set ZK_HOST");
                process::exit(1);
            })
        }
    }
}

fn process_name(
    name: &str,
    ip_strategy: IpStrategy,
    nodes: &mut HashMap<SocketAddr, ZooKeeperMode>,
) {
    // we re-parse every time so that we repeat any DNS lookups,
    // as more IP addresses may have been added for names
    let socket_addresses = parse_name(&name, ip_strategy);
    if log_enabled!(Level::Debug) {
        debug!("adresses:");
        for socket_address in &socket_addresses {
            debug!("  {:?}", &socket_address);
        }
    }

    for socket_address in &socket_addresses {
        match get_zookeeper_mode(&socket_address) {
            Ok(mode) => {
                info!("node {} is {:?}", &socket_address, &mode);
                if mode == ZooKeeperMode::Standalone || mode == ZooKeeperMode::Leader {
                    process::exit(0);
                }
                if nodes.get(&socket_address.clone()).is_none() {
                    nodes.insert(socket_address.clone(), mode);
                }
            }
            Err(e) => {
                debug!(
                    "Could not get ZooKeeper mode for {:?}: {}",
                    &socket_address, e
                );
            }
        }
    }
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    env_logger::init();

    let matches = get_app().get_matches();

    let max_wait_duration = get_duration_arg(&matches, "max-wait");
    let wait_duration = get_duration_arg(&matches, "wait-seconds");
    let ip_strategy = get_ip_strategy_arg(&matches);
    let name = get_name_arg(&matches);
    info!("Looking for {}", &name);

    let start_time = Instant::now();
    let mut nodes: HashMap<SocketAddr, ZooKeeperMode> = HashMap::new();

    while start_time.elapsed() < max_wait_duration {
        process_name(&name, ip_strategy, &mut nodes);

        debug!("sleeping for {:?}", wait_duration);
        sleep(wait_duration);
    }

    println!("Could not find a ZooKeeper leader or standalone");
    process::exit(2);
}
