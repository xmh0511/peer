use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    os::macos::raw,
};

use futures::{Sink, SinkExt, StreamExt};
use packet::{builder::Builder, icmp, ip, Packet};
use std::io::Error;
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::codec::{Encoder, Framed};
use tun::{AsyncDevice, Configuration, TunPacket, TunPacketCodec};

const CURRENT_IP: [u8; 4] = [10, 0, 0, 2];

async fn write_packet_to_socket(packet: TunPacket, stream: &mut TcpStream) {
    let buff = packet.get_bytes();
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(buff);
    stream.write(&write_buffer).await.unwrap();
}
async fn parse_tun_packet<F>(
    packet: Option<Result<TunPacket, Error>>,
    framed: &mut F,
    stream: &mut TcpStream,
) where
    F: SinkExt<TunPacket> + Unpin + StreamExt,
    F::Error: Debug,
{
    match packet {
        Some(packet) => match packet {
            Ok(raw_pkt) => match ip::Packet::new(raw_pkt.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {
                    //println!("");
                    // IP V4 packet
                    match icmp::Packet::new(pkt.payload()) {
                        Ok(icmp) => {
                            // packet is icmp echo
                            match icmp.echo() {
                                Ok(icmp) => {
                                    if pkt.destination() == Ipv4Addr::from(CURRENT_IP) {
                                        //target myself
                                        let reply = ip::v4::Builder::default()
                                            .id(0x42)
                                            .unwrap()
                                            .ttl(64)
                                            .unwrap()
                                            .source(pkt.destination())
                                            .unwrap()
                                            .destination(pkt.source())
                                            .unwrap()
                                            .icmp()
                                            .unwrap()
                                            .echo()
                                            .unwrap()
                                            .reply()
                                            .unwrap()
                                            .identifier(icmp.identifier())
                                            .unwrap()
                                            .sequence(icmp.sequence())
                                            .unwrap()
                                            .payload(icmp.payload())
                                            .unwrap()
                                            .build()
                                            .unwrap();
                                        //tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                        //framed.next().await;
                                        //println!("reply to {}",icmp.sequence());
                                        framed.send(TunPacket::new(reply)).await.unwrap();
                                    } else {
                                        write_packet_to_socket(
                                            TunPacket::new(raw_pkt.get_bytes().to_owned()),
                                            stream,
                                        )
                                        .await;
                                    }
                                    return;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                    // maybe TCP, UDP packet
                    if pkt.destination() == Ipv4Addr::from(CURRENT_IP) {
                        //target myself
                        framed.send(raw_pkt).await.unwrap();
                    } else {
                        write_packet_to_socket(raw_pkt, stream).await;
                    }
                }
                Err(err) => {
                    println!("Received an invalid packet: {:?}", err);
                }
                _ => {}
            },
            Err(err) => {
                println!("Error: {:?}", err);
            }
        },
        None => {}
    }
}

async fn parse_socket_packet<F>(
    packet: Option<Result<TunPacket, Error>>,
    framed: &mut F,
    stream: &mut TcpStream,
) where
    F: SinkExt<TunPacket> + Unpin,
    F::Error: Debug,
{
    match packet {
        Some(packet) => match packet {
            Ok(raw_pkt) => match ip::Packet::new(raw_pkt.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {
                    //println!("");
                    // IP V4 packet
                    match icmp::Packet::new(pkt.payload()) {
                        Ok(icmp) => {
                            // packet is icmp echo
                            match icmp.echo() {
                                Ok(icmp) => {
                                    if pkt.destination() == Ipv4Addr::from(CURRENT_IP) {
                                        //target myself
                                        if icmp.is_request() {
                                            let reply = ip::v4::Builder::default()
                                                .id(0x42)
                                                .unwrap()
                                                .ttl(64)
                                                .unwrap()
                                                .source(pkt.destination())
                                                .unwrap()
                                                .destination(pkt.source())
                                                .unwrap()
                                                .icmp()
                                                .unwrap()
                                                .echo()
                                                .unwrap()
                                                .reply()
                                                .unwrap()
                                                .identifier(icmp.identifier())
                                                .unwrap()
                                                .sequence(icmp.sequence())
                                                .unwrap()
                                                .payload(icmp.payload())
                                                .unwrap()
                                                .build()
                                                .unwrap();
                                            write_packet_to_socket(TunPacket::new(reply), stream)
                                                .await;
                                        } else if icmp.is_reply() {
                                            framed
                                                .send(TunPacket::new(
                                                    raw_pkt.get_bytes().to_owned(),
                                                ))
                                                .await
                                                .unwrap();
                                        }
                                    }
                                    return;
                                }
                                _ => {
                                    return;
                                }
                            }
                        }
                        _ => {}
                    }
                    // maybe TCP, UDP packet
                    if pkt.destination() == Ipv4Addr::from(CURRENT_IP) {
                        //target myself
                        framed.send(raw_pkt).await.unwrap();
                    }
                }
                Err(err) => {
                    println!("Received an invalid packet: {:?}", err);
                }
                _ => {}
            },
            Err(err) => {
                println!("Error: {:?}", err);
            }
        },
        None => {}
    }
}

#[tokio::main]
async fn main() {
    let rely_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
    let mut config = Configuration::default();

    config
        .address(Ipv4Addr::from(CURRENT_IP))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    let mut framed = dev.into_framed();

    let mut stream = match TcpStream::connect(rely_server.clone()).await {
        Ok(stream) => {
            stream
            // let mut buff = Vec::new();
            // let len = 20u16;
            // buff.extend_from_slice(&len.to_be_bytes());
            // for _ in 0..20{
            //     buff.push(b'a');
            // }
            // stream.write_all(&buff).await.unwrap();
        }
        Err(e) => {
            panic!("cannot connection {e:?}");
        }
    };

    //let mut buff_len = [0u8; 2];
    // let r = stream.read(& mut buff_len).await;

    async fn read_data_len(stream: &mut TcpStream) -> Option<u16> {
        let mut buff_len = [0u8; 2];
        let mut read_size = 0;
        loop {
            match stream.read(&mut buff_len[read_size..]).await {
                Ok(size) => {
                    if size == 0 {
                        return None;
                    }
                    read_size += size;
                    if read_size == 2 {
                        let len = u16::from_be_bytes(buff_len);
                        return Some(len);
                    } else {
                        continue;
                    }
                }
                Err(_) => {
                    return None;
                }
            }
        }
    }

    async fn read_body(len: u16, reader: &mut TcpStream) -> Option<Vec<u8>> {
        let len = len as usize;
        let mut buf = Vec::new();
        buf.resize(len as usize, b'\0');
        let mut read_len = 0;
        loop {
            match reader.read(&mut buf[read_len..]).await {
                Ok(size) => {
                    if size == 0 {
                        return None;
                    }
                    read_len += size;
                    if read_len == len {
                        return Some(buf);
                    } else {
                        continue;
                    }
                }
                Err(_) => {
                    return None;
                }
            }
        }
    }

    async fn reconnect(stream: &mut TcpStream, rely_server: SocketAddr) {
        println!("try to reconnect!!!!");
        match TcpStream::connect(rely_server.clone()).await {
            Ok(new_stream) => {
                *stream = new_stream;
            }
            Err(e) => {
                panic!("cannot connection {e:?}");
            }
        };
    }

    loop {
        tokio::select! {
            pkt = framed.next() =>{
                parse_tun_packet(pkt,& mut framed, & mut stream).await;
            }
            size = read_data_len(& mut stream) =>{
                //println!("read packet from network");
                match size{
                    Some(size)=>{
                        match read_body(size,& mut stream).await{
                            Some(buf)=>{
                                let packet = TunPacket::new(buf);
                                //framed.send(packet).await.unwrap();
                                parse_socket_packet(Some(Ok(packet)),& mut framed,& mut stream).await;
                            }
                            None=>{
                                reconnect(& mut stream,rely_server.clone()).await;
                            }
                        }
                    }
                    None=>{
                        reconnect(& mut stream,rely_server.clone()).await;
                    }
                }
            }
        }
    }
}
