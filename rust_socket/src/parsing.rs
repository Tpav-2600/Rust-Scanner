use clap::{Parser};
use std::{net::Ipv4Addr};
use pnet::util::MacAddr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]

pub struct Args {
    #[arg(long = "src_ip")]
    pub src_ip: Option<Ipv4Addr>,

    #[arg(long = "dst_ip")]
    pub dst_ip: Option<Ipv4Addr>,

    #[arg(long = "dest_port")]
    pub dest_port: Option<u16>,

    #[arg(long = "src_mac")]
    pub src_mac: Option<MacAddr>,

    #[arg(long = "dst_mac")]
    pub dst_mac: Option<MacAddr>,

    #[arg(long = "l4_protocol", value_parser = clap::value_parser!(L4Protocol))]
    pub l4_protocol: Option<L4Protocol>,

    #[arg(long = "timeout_ms", default_value_t = 1000)]
    pub timeout_ms: u64,

    #[arg(long = "debug_file")]
    pub debug_file: Option<String>,

    #[arg(long = "debug_format", value_parser = clap::value_parser!(DebugFormat))]
    pub debug_format: Option<DebugFormat>,

    #[arg(long = "ip_bitfield", value_parser = parse_hex)]
    pub ip_bitfield: Option<u8>,

    #[arg(long = "dry_run", action)]
    pub dry_run: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]

pub enum L4Protocol {
    Udp,
    Tcp,
}

// Parsing de la valeurs renreigné comme protocol / erreur en cas de mauvais format
impl std::str::FromStr for L4Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(L4Protocol::Tcp),
            "udp" => Ok(L4Protocol::Udp),
            _ => Err(format!("'{}' n'est pas un protocole udp| tcp", s)),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DebugFormat {
    Json,
    Pcap,
}

// Parsing du debug format / erreur en cas d'un mauvais format rensiegné
impl std::str::FromStr for DebugFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(DebugFormat::Json),
            "pcap" => Ok(DebugFormat::Pcap),
            _ => Err(format!("'{}' n'est pas prise en compte format authorisé json/pcap", s)),
        }
    }
}

// parsing de la valeurs hexadécimal renseigné pour ip_bitfield
fn parse_hex(s: &str) -> Result<u8, std::num::ParseIntError> {
    let value = s.strip_prefix("0x").unwrap_or(s);
    u8::from_str_radix(value, 16)
}