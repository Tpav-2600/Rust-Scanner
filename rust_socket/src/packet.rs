use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use pnet::packet::MutablePacket;
use anyhow::{Context, Ok, Result};

use crate::parsing::L4Protocol;

pub fn packet_builder(buffer: &mut[u8], src_mac: MacAddr, dst_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, 
    dst_port: u16, protocol: L4Protocol, ip_bitfield: Option<u8>) -> Result<usize> {
    
    let len_l4: usize = match protocol {
        L4Protocol::Tcp => 20,
        L4Protocol::Udp => 8,
    };

    let total_len = 14 + 20 + len_l4;
    
    let mut eth_paket = MutableEthernetPacket::new(&mut buffer[..total_len]).context("Impossible de crer un packet ethernet")?;
    eth_paket.set_destination(dst_mac);
    eth_paket.set_source(src_mac);
    eth_paket.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(eth_paket.payload_mut()).context("Pas possible de crée un packet IPV4")?;
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((20 + len_l4) as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_next_level_protocol(match protocol {
        L4Protocol::Tcp => IpNextHeaderProtocols::Tcp,
        L4Protocol::Udp => IpNextHeaderProtocols::Udp,
    });

    if let Some(field_value) = ip_bitfield {
        let flags = ipv4_packet.get_flags();
        let flags_and_frag = flags | field_value;
        ipv4_packet.set_flags(flags_and_frag);  
    }

    match protocol {
        L4Protocol::Tcp => {
            let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).context("Impossible de cree un packet TCP")?;
            tcp_packet.set_source(src_port);
            tcp_packet.set_destination(dst_port);
            tcp_packet.set_sequence(0);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(65535);

            let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
            tcp_packet.set_checksum(checksum);
        }
        L4Protocol::Udp => {
            let mut udp_packet = MutableUdpPacket::new(ipv4_packet.packet_mut()).context("Impossible de crée un packet Udp")?;
            udp_packet.set_source(src_port);
            udp_packet.set_destination(dst_port);
            udp_packet.set_length(8 as u16);

            let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
            udp_packet.set_checksum(checksum);
        }
    }

    let _ipv4_checksum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(_ipv4_checksum);

    Ok(total_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    #[test]
    fn test_build_trame_package() {
        let mut buffer= [0u8; 64];
        let src_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let dst_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let src_ip = Ipv4Addr::new(192, 168, 1, 20);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 20);
        let src_port = 2020;
        let dst_port = 80;

        let size_packet = packet_builder(&mut buffer, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, L4Protocol::Tcp, Some(0x04)).unwrap();
        assert_eq!(size_packet, (14 + 20 + 20));

        // verification des headers
        let eth_paket = EthernetPacket::new(&buffer).unwrap();
        assert_eq!(eth_paket.get_source(), src_mac);
        assert_eq!(eth_paket.get_destination(), dst_mac);
        assert_eq!(eth_paket.get_ethertype(), EtherTypes::Ipv4);

        let ipv4_paket = Ipv4Packet::new(eth_paket.payload()).unwrap();
        assert_eq!(ipv4_paket.get_source(), src_ip);
        assert_eq!(ipv4_paket.get_destination(), dst_ip);
        // check du bit à 1 donc 0x04
        assert_eq!(ipv4_paket.get_flags() & 0b100, 0b100);

        let tcp_packet = TcpPacket::new(ipv4_paket.payload()).unwrap();
        assert_eq!(tcp_packet.get_source(), src_port);
        assert_eq!(tcp_packet.get_destination(), dst_port);
        assert_ne!(tcp_packet.get_checksum(), 0);
        
    }
}