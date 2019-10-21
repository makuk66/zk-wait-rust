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

use clap::{App, Arg};
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
    Unknown,
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
fn get_zookeeper_mode(address: &SocketAddr) -> ZooKeeperMode {
    debug!("connecting to {}", address);
    let connect_timeout = Duration::new(CONNECT_TIMEOUT_SECONDS, 0);
    let mut stream;
    match TcpStream::connect_timeout(address, connect_timeout) {
        Ok(s) => {
            stream = s;
        }
        Err(e) => {
            debug!(
                "Failed to connect to {} in {:?}: {}",
                &address, &connect_timeout, e
            );
            return ZooKeeperMode::Unknown;
        }
    }
    // set read/write timeouts so that we don't get hung up by one stuck server
    let write_timeout = Duration::new(WRITE_TIMEOUT_SECONDS, 0);
    match stream.set_write_timeout(Some(write_timeout)) {
        Ok(_) => {}
        Err(e) => {
            error!("failed to set write timeout to {:?}: {}", &write_timeout, e);
        }
    }
    let read_timeout = Duration::new(READ_TIMEOUT_SECONDS, 0);
    match stream.set_read_timeout(Some(read_timeout)) {
        Ok(_) => {}
        Err(e) => {
            error!("failed to set read timeout to {:?}: {}", &read_timeout, e);
        }
    }
    match stream.write(&SRVR_COMMAND) {
        Ok(_) => {}
        Err(e) => {
            debug!("failed to write the srvr command: {}", e);
            return ZooKeeperMode::Unknown;
        }
    }
    let mut buffer = String::new();
    loop {
        match stream.read_to_string(&mut buffer) {
            Ok(_) => break,
            Err(e) => {
                debug!("failed to read from the server: {}", e);
                return ZooKeeperMode::Unknown;
            }
        };
    }

    lazy_static! {
        static ref MODE_RE: Regex = Regex::new(r"Mode: ([[:alpha:]]+)\r?\n").unwrap();
    }

    match MODE_RE.captures(&buffer) {
        Some(captures) => match captures.get(1) {
            Some(matched) => {
                let mode = matched.as_str();
                debug!("{} is {:?}", address, mode);

                match mode.as_ref() {
                    "leader" => return ZooKeeperMode::Leader,
                    "follower" => return ZooKeeperMode::Follower,
                    "standalone" => return ZooKeeperMode::Standalone,
                    _ => return ZooKeeperMode::Unknown,
                }
            }
            None => {}
        },
        None => debug!("no Mode found in response"),
    }
    return ZooKeeperMode::Unknown;
}

fn parse_name(name_string: &str, ip_strategy: &IpStrategy) -> Vec<SocketAddr> {
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
                    && (ip_strategy == &IpStrategy::Ipv4Only
                        || ip_strategy == &IpStrategy::Ipv4thenIpv6))
                    || (a.is_ipv6()
                        && (ip_strategy == &IpStrategy::Ipv6Only
                            || ip_strategy == &IpStrategy::Ipv4thenIpv6))
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
                    && (ip_strategy == &IpStrategy::Ipv4Only
                        || ip_strategy == &IpStrategy::Ipv4thenIpv6))
                    || (sa.is_ipv6()
                        && (ip_strategy == &IpStrategy::Ipv6Only
                            || ip_strategy == &IpStrategy::Ipv4thenIpv6))
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

        if ip_strategy == &IpStrategy::Ipv4Only || ip_strategy == &IpStrategy::Ipv4thenIpv6 {
            debug!("ipv4 lookup for {}", &hostname);
            let lookup_result = resolver.ipv4_lookup(hostname);
            match lookup_result {
                Ok(result) => {
                    for address in result.iter() {
                        let socket_address = SocketAddr::new(IpAddr::V4(address.clone()), port);
                        debug!("found {}", &socket_address);
                        address_list.push(socket_address);
                    }
                }
                Err(e) => debug!("ipv4 lookup failed for {}: {}", hostname, e),
            }
        }
        if ip_strategy == &IpStrategy::Ipv6Only || ip_strategy == &IpStrategy::Ipv4thenIpv6 {
            debug!("ipv6 lookup for {}", &hostname);
            let lookup_result = resolver.ipv6_lookup(hostname);
            match lookup_result {
                Ok(result) => {
                    for address in result.iter() {
                        let socket_address = SocketAddr::new(IpAddr::V6(address.clone()), port);
                        debug!("found {}", &socket_address);
                        address_list.push(socket_address);
                    }
                }
                Err(e) => debug!("ipv6 lookup failed for {}: {}", hostname, e),
            }
        }
    }

    return address_list;
}

fn get_app<'a, 'b>() -> App<'a, 'b> {
    return App::new("zk-wait-rust")
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
        .arg(
            Arg::with_name("v")
                .short("v")
                .long("verbose")
                .multiple(true)
                .takes_value(false)
                .help("Sets the level of verbosity"),
        )
        .arg(Arg::with_name("name").multiple(false).takes_value(false));
}

fn main() {
    env_logger::init();

    let app = get_app();
    let matches = app.get_matches();

    let max_wait_duration;
    let max_wait_string = matches.value_of("max-wait").unwrap();
    match parse_duration::parse(&max_wait_string) {
        Ok(v) => max_wait_duration = v,
        Err(e) => {
            error!(
                "could not parse max-wait value '{:?}' as a duration: {}",
                &max_wait_string, e
            );
            process::exit(1);
        }
    }
    debug!("max_wait_duration = {:?}", max_wait_duration);

    let wait_duration;
    let wait_seconds_string = matches.value_of("wait-seconds").unwrap();
    match parse_duration::parse(&wait_seconds_string) {
        Ok(v) => wait_duration = v,
        Err(e) => {
            error!(
                "could not parse wait-seconds value '{:?}' as a duration: {}",
                &wait_seconds_string, e
            );
            process::exit(1);
        }
    }
    debug!("wait_duration = {:?}", wait_duration);
    let ip_strategy;
    if matches.is_present("ipv4") && matches.is_present("ipv6") {
        debug!("both");
        ip_strategy = IpStrategy::Ipv4thenIpv6;
    } else if matches.is_present("ipv4") {
        debug!("4");
        ip_strategy = IpStrategy::Ipv4Only;
    } else if matches.is_present("ipv6") {
        debug!("6");
        ip_strategy = IpStrategy::Ipv6Only;
    } else {
        debug!("default");
        ip_strategy = IpStrategy::Ipv4thenIpv6;
    }
    debug!("ip_strategy = {:?}", ip_strategy);

    let mut name = String::new();
    match matches.value_of("name") {
        Some(n) => {
            name = n.to_string();
        }
        None => {
            for (key, value) in env::vars() {
                if key == "ZK_HOST" {
                    name = value.to_string();
                }
            }
        }
    }

    if name.len() == 0 {
        error!("You must specify a name as command-line parameter or set ZK_HOST");
        process::exit(1);
    }
    info!("Looking for {}", &name);

    let start_time = Instant::now();

    let mut nodes = HashMap::new();

    while start_time.elapsed() < max_wait_duration {
        // we re-parse every time so that we repeat any DNS lookups,
        // as more IP addresses may have been added for names
        let socket_addresses = parse_name(&name, &ip_strategy);
        if log_enabled!(Level::Debug) {
            debug!("adresses:");
            for socket_address in &socket_addresses {
                debug!("  {:?}", &socket_address);
            }
        }

        for socket_address in &socket_addresses {
            let mode = get_zookeeper_mode(&socket_address);
            if mode == ZooKeeperMode::Standalone || mode == ZooKeeperMode::Leader {
                process::exit(0);
            } else if mode == ZooKeeperMode::Follower {
                match nodes.get(&socket_address.clone()) {
                    Some(_) => {}
                    None => {
                        info!("node {} is {:?}", &socket_address, &mode);
                        nodes.insert(socket_address.clone(), mode);
                    }
                }
            }
        }
        debug!("sleeping for {:?}", wait_duration);
        sleep(wait_duration);
    }

    println!("Could not find a ZooKeeper leader or standalone");
    process::exit(2);
}