use std::{net::SocketAddr, sync::Arc};

use config_file::FromConfigFile;
use futures::{SinkExt, StreamExt};
use futures_util::stream::SplitSink;
use packet::{builder::Builder, icmp, ip, ip::Protocol, Packet};
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::codec::Framed;
use tun::{AsyncDevice, Configuration, TunPacket, TunPacketCodec};

use tokio::sync::Mutex;

use packet::Error as PktError;
use std::io::Error as StdError;

enum Error {
    Packet(PktError),
    IO(StdError),
    Network(StdError),
}

impl From<PktError> for Error {
    fn from(value: PktError) -> Self {
        Error::Packet(value)
    }
}

impl From<StdError> for Error {
    fn from(value: StdError) -> Self {
        Error::IO(value)
    }
}

//struct Reconnection;

async fn write_packet_to_socket(packet: TunPacket, stream: &OwnedWriteHalf) -> Result<(), Error> {
    let buff = packet.get_bytes();
    let len = buff.len() as u16;
    let bytes = len.to_be_bytes();
    let mut write_buffer = Vec::new();
    write_buffer.extend_from_slice(&bytes);
    write_buffer.extend_from_slice(buff);
    let total_size = write_buffer.len();
    let mut write_size = 0;
    loop {
        let _ = stream.writable().await;
        match stream.try_write(&write_buffer[write_size..]) {
            Ok(size) => {
                if size == 0 {
                    //todo
                    return Err(Error::Network(StdError::new(
                        std::io::ErrorKind::NotConnected,
                        "",
                    )));
                }
                write_size += size;
                if write_size == total_size {
                    break;
                }
            }
            Err(e) => {
                return Err(Error::Network(e));
            }
        }
    }
    Ok(())
}

fn build_icmp_reply_packet<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    pkt: &ip::v4::Packet<T>,
    icmp: &icmp::echo::Packet<U>,
) -> Result<Vec<u8>, Error> {
    Ok(ip::v4::Builder::default()
        .id(0x42)?
        .ttl(64)?
        .source(pkt.destination())?
        .destination(pkt.source())?
        .icmp()?
        .echo()?
        .reply()?
        .identifier(icmp.identifier())?
        .sequence(icmp.sequence())?
        .payload(icmp.payload())?
        .build()?)
}

type TunHalfWriter = SplitSink<Framed<AsyncDevice, TunPacketCodec>, TunPacket>;

async fn parse_tun_packet(
    raw_pkt: TunPacket,
    framed: &mut TunHalfWriter,
    stream: &OwnedWriteHalf,
    current_ip: Ipv4Addr,
) -> Result<(), Error> {
    return match ip::Packet::new(raw_pkt.get_bytes()) {
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
                                    let reply = build_icmp_reply_packet(&pkt, &icmp)?;
                                    //tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    //framed.next().await;
                                    //println!("reply to {}",icmp.sequence());
                                    framed.send(TunPacket::new(reply)).await?;
                                } else {
                                    write_packet_to_socket(
                                        TunPacket::new(raw_pkt.get_bytes().to_owned()),
                                        stream,
                                    )
                                    .await?;
                                }
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
                    framed.send(raw_pkt).await?;
                } else {
                    write_packet_to_socket(raw_pkt, stream).await?;
                }
            }
            Ok(())
        }
        Err(err) => {
            println!("Received an invalid packet: {:?}", err);
            Err(err.into())
        }
        _ => {
            println!("non-ip-v4 packet!!!!!");
            Ok(())
        }
    };
}

async fn parse_socket_packet(
    raw_pkt: TunPacket,
    framed: &mut TunHalfWriter,
    stream: &OwnedWriteHalf,
    current_ip: Ipv4Addr,
) -> Result<(), Error> {
    return match ip::Packet::new(raw_pkt.get_bytes()) {
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
                                        let reply = build_icmp_reply_packet(&pkt, &icmp)?;
                                        write_packet_to_socket(TunPacket::new(reply), stream)
                                            .await?;
                                    } else if icmp.is_reply() {
                                        framed
                                            .send(TunPacket::new(raw_pkt.get_bytes().to_owned()))
                                            .await?;
                                    }
                                }
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
                    framed.send(raw_pkt).await?;
                }
            }
            Ok(())
        }
        Err(err) => {
            println!("Received an invalid packet: {:?}", err);
            Err(err.into())
        }
        _ => {
            println!("non-ip-v4 packet!!!!!");
            Ok(())
        }
    };
}

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

enum Message {
    SetSocketWriter(Arc<OwnedWriteHalf>),
    DataFromSocket(TunPacket),
    DataFromTun(TunPacket),
}

use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    rely: String,
    vir_addr: String,
    #[allow(dead_code)]
    route: String,
    try_times: i32,
    identifier: String,
}

#[tokio::main]
async fn main() {
    let config_file = Config::from_config_file("./config.toml").unwrap();

    let rely_server: SocketAddr = config_file.rely.parse().unwrap();
    let current_vir_ip: Ipv4Addr = config_file.vir_addr.parse().unwrap();

    let unique_identifier = config_file.identifier;
    if unique_identifier.len() != 32 {
        panic!("invalid identifier, whose len is not 32");
    }
    println!("your identifier is {unique_identifier}");

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

    let framed = dev.into_framed();

    let stream = match TcpStream::connect(rely_server.clone()).await {
        Ok(mut stream) => {
            stream
                .write_all(unique_identifier.as_bytes())
                .await
                .unwrap(); // must panic
            stream
        }
        Err(e) => {
            panic!("cannot connection {e:?}");
        }
    };

    //let mut buff_len = [0u8; 2];
    // let r = stream.read(& mut buff_len).await;

    async fn read_data_len(stream: &mut OwnedReadHalf) -> Option<u16> {
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

    async fn read_body(len: u16, reader: &mut OwnedReadHalf) -> Option<Vec<u8>> {
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

    // async fn reconnect(
    //     rely_server: SocketAddr,
    //     times: &mut i32,
    //     unique_identifier: String,
    // ) -> TcpStream {
    // }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (tun_writer, mut tun_reader) = framed.split();

	//let (request_reconn, mut rx_reconn) =  tokio::sync::mpsc::unbounded_channel();

    let write_task = tokio::spawn(async move {
        let mut socket_handler: Option<Arc<OwnedWriteHalf>> = None;
        let tun_writer = Arc::new(Mutex::new(tun_writer));
        loop {
            match rx.recv().await {
                Some(Message::DataFromTun(packet)) => match &socket_handler {
                    Some(socket) => {
                        let tun_writer = Arc::clone(&tun_writer);
                        let socket = Arc::clone(socket);
						//let request_reconn = request_reconn.clone();
                        tokio::spawn(async move {
                            let mut tun_writer = tun_writer.lock().await;
                            match parse_tun_packet(
                                packet,
                                &mut tun_writer,
                                &socket,
                                current_vir_ip.clone(),
                            )
                            .await{
								Err(Error::Network(_))=>{
									//let _ = request_reconn.send(Reconnection);
								}
								_=>{}
							};
                        });
                    }
                    None => {
					}
                },
                Some(Message::DataFromSocket(packet)) => match &socket_handler {
                    Some(socket) => {
                        let tun_writer = Arc::clone(&tun_writer);
                        let socket = Arc::clone(socket);
						//let request_reconn = request_reconn.clone();
                        tokio::spawn(async move {
                            let mut tun_writer = tun_writer.lock().await;
                            match parse_socket_packet(
                                packet,
                                &mut tun_writer,
                                &socket,
                                current_vir_ip.clone(),
                            )
                            .await{
								Err(Error::Network(_))=>{
									//let _ = request_reconn.send(Reconnection);
								}
								_=>{}
							}
                        });
                    }
                    None => {}
                },
                Some(Message::SetSocketWriter(socket_writer)) => {
                    socket_handler = Some(socket_writer);
                }
                None => {}
            }
        }
    });

    let tx_in_socket = tx.clone();

    let tun_read_task = tokio::spawn(async move {
        loop {
            while let Some(v) = tun_reader.next().await {
                match v {
                    Ok(packet) => {
                        let _ = tx.send(Message::DataFromTun(packet));
                    }
                    Err(_) => {}
                }
            }
        }
    });

    let try_to_reconnect_network = move |mut times: i32| {
        //let rely_server = rely_server.clone();
        async move {
            let total_times = times;
            while times > 0 {
                println!("try to reconnect!!!!");
                match TcpStream::connect(rely_server.clone()).await {
                    Ok(mut new_stream) => {
                        new_stream
                            .write_all(unique_identifier.as_bytes())
                            .await
                            .unwrap(); // must panic
                        let (socket_reader, socket_writer) = new_stream.into_split();
                        return (socket_reader, socket_writer);
                    }
                    Err(e) => {
                        println!("reconnect fail due to {e:?}");
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                };
                times -= 1;
            }
            panic!("cannot reconnect to server in {total_times} times");
        }
    };

    let (mut socket_reader, socket_writer) = stream.into_split();

    let _ = tx_in_socket.send(Message::SetSocketWriter(Arc::new(socket_writer)));

    let socket_read_task = tokio::spawn(async move {
        loop {
            match read_data_len(&mut socket_reader).await {
                Some(size) => match read_body(size, &mut socket_reader).await {
                    Some(buf) => {
                        let _ = tx_in_socket.send(Message::DataFromSocket(TunPacket::new(buf)));
                    }
                    None => {
                        let (r, w) = try_to_reconnect_network.clone()(config_file.try_times).await;
                        let _ = tx_in_socket.send(Message::SetSocketWriter(Arc::new(w)));
                        socket_reader = r;
                    }
                },
                None => {
                    let (r, w) = try_to_reconnect_network.clone()(config_file.try_times).await;
                    let _ = tx_in_socket.send(Message::SetSocketWriter(Arc::new(w)));
                    socket_reader = r;
                }
            }
        }
    });

    socket_read_task.await.unwrap();
    write_task.await.unwrap();
    tun_read_task.await.unwrap();

    // loop {
    //     tokio::select! {
    //         (pkt,now) = async {
    //             let now = std::time::Instant::now();
    //             (framed.next().await,now)

    //         } =>{
    //             println!("read tun {:?}",now.elapsed());
    //             parse_tun_packet(pkt,& mut framed, & mut stream,current_vir_ip.clone()).await;
    //         }
    //         (size,now) = async {
    //             let now = std::time::Instant::now();
    //             (read_data_len(& mut stream).await,now)
    //         } =>{
    //             let time = chrono::Local::now().timestamp_millis();
    //             println!("read network {:?}",now.elapsed());
    //             match size{
    //                 Some(size)=>{
    //                     match read_body(size,& mut stream).await{
    //                         Some(buf)=>{
    //                             //framed.send(packet).await.unwrap();
    //                             parse_socket_packet(TunPacket::new(buf),& mut framed,& mut stream,current_vir_ip.clone()).await;
    //                         }
    //                         None=>{
    //                             reconnect(& mut stream,rely_server.clone(),& mut re_connect_times,unique_identifier.clone()).await;
    //                         }
    //                     }
    //                 }
    //                 None=>{
    //                     reconnect(& mut stream,rely_server.clone(),& mut re_connect_times,unique_identifier.clone()).await;
    //                 }
    //             }
    //         }
    //     }
    // }
}
