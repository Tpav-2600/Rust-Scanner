
use clap::{Parser};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use anyhow::{Context, Result};
use std::process::ExitCode;

mod parsing;
mod packet;
mod debugs;

use parsing::{Args, L4Protocol};

use crate::packet::packet_builder; 

fn build() -> Result<()> {
    let args = Args::parse();

    let src_mac = args.src_mac.unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 1));
    let dst_mac = args.src_mac.unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 2));
    let src_ip = args.src_ip.unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let dst_ip = args.src_ip.unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let src_port = 51000;
    let dst_port = args.dest_port.unwrap_or(80);
    let protocol = args.l4_protocol.unwrap_or(L4Protocol::Tcp);


    let mut buffer_paket = [0u8; 60];
    let size_paket = packet_builder(&mut buffer_paket, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, args.ip_bitfield)?;
    let fin_pack = &buffer_paket[..size_paket];

    if args.dry_run {
        println!("Dry_run Activé: Pas de paquet envoyé");
        let (file, format) = (
            args.debug_file.context("--debug_file requis pour le mode --dry_run")?,
            args.debug_format.context("--debug_format requis pour le mode --dry_run")?,
        );
        debugs::packet_to_debug_file(&file, format, fin_pack)?;
        println!("Paquet ecrit dzns le fichier {}", file);
    }
    
    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = build() {
        eprintln!("Erreur: {:?}", e);
        return ExitCode::FAILURE;
    }
    return ExitCode::SUCCESS;
}
