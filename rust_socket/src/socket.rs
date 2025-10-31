/*use pnet::packet::{
    ethernet::{EtherType, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::MutableUdpPacket,
    Packet,
};
use pnet::util::MacAddr;
use socket2::{Domain, Protocol, Socket, Type};
use pnet::packet::ip::IpNextHeaderProtocol;

use std::net::SocketAddr;

fn build_ethernet_packet(src_mac: MacAddr, dst_mac: MacAddr, type_ether: EtherType, payload: &[u8]){
    let mut eth_buffer = vec![0u8; 14 + payload.len()];
    let mut eth_pack= MutableEthernetPacket::new(&mut eth_buffer).unwrap();
    eth_pack.set_source(src_mac);
    eth_pack.set_destination(dst_mac);
    eth_pack.set_ethertype(type_ether);
    eth_pack.set_payload(payload);
}

fn build_ipv4_packet(src_ip: std::net::Ipv4Addr, dst_ip: std::net::Ipv4Addr, protocol: IpNextHeaderProtocol , payload: &[u8], ip_batfield: u8) {
    let mut ipv4_buff = vec![0u8; 20 + payload.len()];
    let mut ipv4_pack = MutableIpv4Packet::new(&mut ipv4_buff).unwrap();
    ipv4_pack.set_version(4);
    ipv4_pack.set_header_length(5);
    ipv4_pack.set_total_length((20 + payload.len()) as u16);
    ipv4_pack.set_identification(0x1234);
    ipv4_pack.set_flags(ip_batfield & 0x07);
    ipv4_pack.set_fragment_offset(ip_batfield as u16 & 0x1F);
    ipv4_pack.set_ttl(64);
    ipv4_pack.set_next_level_protocol(protocol);
    ipv4_pack.set_source(src_ip);
    ipv4_pack.set_destination(dst_ip);
    ipv4_pack.set_payload(payload);
    ipv4_pack.set_checksum(0);
    // let checksum = pnet::util::ipv4_checksum(&ipv4_pack.to_immutable());
}

fn build_tcp_packet(src_port: u16, dst_port: u16, payload: &[u8]) {
    let mut tcp_buffer = vec![0u8; 20 + payload.len()];
    let mut tcp_paket = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    tcp_paket.set_source(src_port);
    tcp_paket.set_destination(dst_port);
    tcp_paket.set_sequence(0x12345678);
    tcp_paket.set_acknowledgement(0);
    tcp_paket.set_data_offset(5);
    //tcp_paket.set_syn(true);
    tcp_paket.set_payload(payload);
    tcp_paket.set_checksum(0);
}

fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) {
    let mut udp_buffer = vec![0u8; 8 + payload.len()];
    let mut udp_paket = MutableUdpPacket::new(&mut udp_buffer).unwrap();
    udp_paket.set_source(src_port);
    udp_paket.set_destination(dst_port);
    udp_paket.set_length(8 + payload.len() as u16);
    udp_paket.set_payload(payload);
    udp_paket.set_checksum(0);
}

//fn create_raw_socket() {
//    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IpNextHeaderProtocols::Tcp as i32)))?;
//}
*/