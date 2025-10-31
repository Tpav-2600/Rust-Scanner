use anyhow::{Context, Ok, Result};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;


use crate::parsing::DebugFormat;

#[derive(Serialize)]
struct PaketInfo {
    l2_layer: L2Info,
    l3_layer: L3Info,
    l4_layer: L4Info,
}

#[derive(Serialize)]
struct L2Info { source_mac: String, destination_mac: String }
#[derive(Serialize)]
struct L3Info { source_ip: String, destination_ip: String, checksum: u16 }
#[derive(Serialize)]
struct L4Info { protocol: String, source_port: u16, destination_port: u16, checksum: u16 }


pub fn packet_to_debug_file(file_path: &str, format: DebugFormat, buffer_package: &[u8]) -> Result<()> {
    match format {
        DebugFormat::Json => debug_by_json_file(file_path, buffer_package),
        DebugFormat::Pcap => debug_by_pcap_file(file_path, buffer_package),
    }
}

fn debug_by_json_file(file_path: &str, buffer_package: &[u8]) -> Result<()> {
    let eth_paket = EthernetPacket::new(buffer_package).context("Packet EThernet invalide")?;
    let ipv4_paket = Ipv4Packet::new(eth_paket.payload()).context("Packet IPV4 invalide")?;

    let l4_info = if let Some(tcp) = TcpPacket::new(ipv4_paket.payload()) {
        L4Info {
            protocol: "tcp".into(),
            source_port: tcp.get_source(),
            destination_port: tcp.get_destination(),
            checksum: tcp.get_checksum(),
        }
    }  else if let Some(udp) = UdpPacket::new(ipv4_paket.payload()) {
        L4Info {
            protocol: "udp".into(),
            source_port: udp.get_source(),
            destination_port: udp.get_destination(),
            checksum: udp.get_checksum(),
        }
    } else {
        anyhow::bail!("Unsupported L4 protocol");
    };

    let info = PaketInfo {
        l2_layer: L2Info {
            source_mac: eth_paket.get_source().to_string(),
            destination_mac: eth_paket.get_destination().to_string(),
        },
        l3_layer: L3Info {
            source_ip: ipv4_paket.get_source().to_string(),
            destination_ip: ipv4_paket.get_destination().to_string(),
            checksum: ipv4_paket.get_checksum(),
        },
        l4_layer: l4_info,
    };
    
    let mut file = File::create(file_path).context("Impossible de créer le fichier JSON")?;
    let json_string = serde_json::to_string_pretty(&info)?;
    file.write_all(json_string.as_bytes())?;

    Ok(())
}

fn debug_by_pcap_file(file_path: &str, buffer_package: &[u8]) -> Result<()> {
    let file = File::create(file_path).context("Impossible de crée le fichier pcap")?;
    let mut pcap_read_writer = PcapWriter::new(file).context("Impossible d'ecrire les données pcap dans le fichier")?;
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let pcap_paket = PcapPacket::new(time ,time.subsec_micros(), buffer_package);

    pcap_read_writer.write_packet(&pcap_paket).context("Impossible d'ecrie le paquet pcap dans le fichier")?;
    Ok(())
}