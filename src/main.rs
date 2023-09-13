use std::fmt::Debug;

use futures::{Sink, SinkExt, StreamExt};
use packet::{builder::Builder, icmp, ip, Packet};
use std::io::Error;
use std::net::Ipv4Addr;
use tokio::{io::{AsyncWriteExt, AsyncReadExt}, net::TcpStream};
use tokio_util::codec::{Encoder, Framed};
use tun::{AsyncDevice, Configuration, TunPacket, TunPacketCodec};

async fn write_packet_to_socket(packet:TunPacket,stream:& mut TcpStream){
    let buff = packet.get_bytes();
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(buff);
    stream.write(&write_buffer).await.unwrap();
}
async fn parse_tun_packet<F>(packet: Option<Result<TunPacket, Error>>, framed: &mut F, stream:& mut TcpStream)
where
    F: SinkExt<TunPacket> + Unpin,
    F::Error: Debug,
{
    match packet {
        Some(packet) => match packet {
            Ok(raw_pkt) => match ip::Packet::new(raw_pkt.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {
                    println!("");
                    match icmp::Packet::new(pkt.payload()) {
                        Ok(icmp) => match icmp.echo() {
                            Ok(icmp) => {
                                if pkt.destination() == Ipv4Addr::new(10, 0, 0, 2) {
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
                                    //framed.send(TunPacket::new(reply)).await.unwrap();
                                    write_packet_to_socket(raw_pkt,stream);
                                }
                                return;
                            }
                            _ => {
                            }
                        },
                        _ => {
                        }
                    }
                    write_packet_to_socket(raw_pkt,stream);
                    //framed.send(raw_pkt).await.unwrap();
                }
                Err(err) => println!("Received an invalid packet: {:?}", err),
                _ => {}
            },
            Err(err) => panic!("Error: {:?}", err),
        },
        None => {}
    }
}

#[tokio::main]
async fn main() {
    let mut config = Configuration::default();

    config
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    let mut framed = dev.into_framed();

    let mut stream = match TcpStream::connect("192.168.1.11:3000").await {
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

    let mut buff_len = [0u8;2];
    // let r = stream.read(& mut buff_len).await;

    tokio::select! {
        pkt = framed.next() =>{
            parse_tun_packet(pkt, & mut framed,& mut stream).await;
        }
        Ok(size) = stream.read(& mut buff_len) =>{
            if size == 2{
                let len = u16::from_be_bytes(buff_len);
                let mut buff = Vec::new();
                buff.resize(len as usize, b'\0');
                stream.read(& mut buff).await.unwrap();
                let packet = TunPacket::new(buff);
                parse_tun_packet(Some(Ok(packet)), & mut framed,& mut stream).await;
            }
        }
    }
}
