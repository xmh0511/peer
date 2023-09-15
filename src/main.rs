use std::{fmt::Debug, net::SocketAddr};

use config_file::FromConfigFile;
use futures::{SinkExt, StreamExt};
use packet::{builder::Builder, icmp, ip, ip::Protocol, Packet};
use std::io::Error;
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tun::{Configuration, TunPacket};


async fn write_packet_to_socket(packet: TunPacket, stream: &mut TcpStream) {
    let buff = packet.get_bytes();
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(buff);
    stream.write_all(&write_buffer).await.unwrap();
}
async fn parse_tun_packet<F>(
    packet: Option<Result<TunPacket, Error>>,
    framed: &mut F,
    stream: &mut TcpStream,
    current_ip: Ipv4Addr,
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
                    if pkt.protocol() == Protocol::Icmp {
                        match icmp::Packet::new(pkt.payload()) {
                            Ok(icmp) => {
                                // packet is icmp echo
                                match icmp.echo() {
                                    Ok(icmp) => {
                                        if pkt.destination() == current_ip {
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
                                    _ => {
                                        // println!("icmp packet from tun but not echo");
                                        // write_packet_to_socket(raw_pkt, stream).await;
                                        // return;
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        // maybe TCP, UDP or other packets
                        if pkt.destination() == current_ip {
                            //target myself
                            framed.send(raw_pkt).await.unwrap();
                        } else {
                            write_packet_to_socket(raw_pkt, stream).await;
                        }
                    }
                }
                Err(err) => {
                    println!("Received an invalid packet: {:?}", err);
                }
                _ => {
                    println!("non-ip-v4 packet!!!!!");
                }
            },
            Err(err) => {
                println!("Error: {:?}", err);
            }
        },
        None => {}
    }
}

async fn parse_socket_packet<F>(
    raw_pkt: TunPacket,
    framed: &mut F,
    stream: &mut TcpStream,
    current_ip: Ipv4Addr,
) where
    F: SinkExt<TunPacket> + Unpin,
    F::Error: Debug,
{
    match ip::Packet::new(raw_pkt.get_bytes()) {
        Ok(ip::Packet::V4(pkt)) => {
            //println!("ip v4 packet from socket");
            // IP V4 packet
            if pkt.protocol() == Protocol::Icmp {
                match icmp::Packet::new(pkt.payload()) {
                    Ok(icmp) => {
                        // packet is icmp echo
                        //println!("icmp packet from socket!!!!!");
                        match icmp.echo() {
                            Ok(icmp) => {
                                if pkt.destination() == current_ip {
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
                                        write_packet_to_socket(TunPacket::new(reply), stream).await;
                                    } else if icmp.is_reply() {
                                        framed
                                            .send(TunPacket::new(raw_pkt.get_bytes().to_owned()))
                                            .await
                                            .unwrap();
                                    }
                                }
                                return;
                            }
                            _ => {
                                // println!("icmp packet but not icmp echo");
                                // framed.send(raw_pkt).await.unwrap();
                                // return;
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // maybe TCP, UDP packet or other packets
                //println!("tcp packet from socket!!!!!");
                if pkt.destination() == current_ip {
                    //target myself
                    framed.send(raw_pkt).await.unwrap();
                }
            }
        }
        Err(err) => {
            println!("Received an invalid packet: {:?}", err);
        }
        _ => {
            println!("non-ip-v4 packet!!!!!");
        }
    };
}

use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    rely: String,
    vir_addr: String,
    route: String,
	try_times:i32
}

#[tokio::main]
async fn main() {
    let config_file = Config::from_config_file("./config.toml").unwrap();

    let rely_server: SocketAddr = config_file.rely.parse().unwrap();
    let current_vir_ip: Ipv4Addr = config_file.vir_addr.parse().unwrap();

    let mut config = Configuration::default();

    config
        .address(current_vir_ip.clone())
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));

    #[cfg(target_os = "macos")]
    {
        let s = format!(
            "sudo route -n add -net {} {}",
            config_file.route, config_file.vir_addr
        );
        let command = std::process::Command::new("sh")
            .arg("-c")
            .arg(s)
            .output()
            .unwrap();
        if !command.status.success() {
            panic!("cannot establish route to tun device");
        }
    };

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

    async fn reconnect(stream: &mut TcpStream, rely_server: SocketAddr,times:i32) {
		let mut times = times;
		while times >0{
			println!("try to reconnect!!!!");
			match TcpStream::connect(rely_server.clone()).await {
				Ok(new_stream) => {
					*stream = new_stream;
				}
				Err(e) => {
					panic!("cannot connection {e:?}");
				}
			};
			times-=1;
		}
    }

    loop {
        tokio::select! {
            pkt = framed.next() =>{
                //let time = chrono::Local::now().timestamp_millis();
                //println!("read packet from tun     {time}");
                parse_tun_packet(pkt,& mut framed, & mut stream,current_vir_ip.clone()).await;
            }
            size = read_data_len(& mut stream) =>{
                // let time = chrono::Local::now().timestamp_millis();
                // println!("read packet from network {time}");
                match size{
                    Some(size)=>{
                        match read_body(size,& mut stream).await{
                            Some(buf)=>{
                                //framed.send(packet).await.unwrap();
                                parse_socket_packet(TunPacket::new(buf),& mut framed,& mut stream,current_vir_ip.clone()).await;
                            }
                            None=>{
                                reconnect(& mut stream,rely_server.clone(),config_file.try_times).await;
                            }
                        }
                    }
                    None=>{
                        reconnect(& mut stream,rely_server.clone(),config_file.try_times).await;
                    }
                }
            }
        }
    }
}
