use std::{fs::File, io::Seek, net::UdpSocket};

use pcap_parser::{LegacyPcapReader, traits::PcapReaderIterator, PcapBlockOwned};


const SOURCE_ADDR: &str = "127.0.0.1:8081";

pub fn run(args: Args) {
    let mut file = File::open(args.input).unwrap();

    let dest_addr = if let Some(port) = args.port {
        format!("255.255.255.255:{}", port)
    } else {
        format!("255.255.255.255:8080")
    };
    println!("UDP broadcast {} -> {}", SOURCE_ADDR, dest_addr);

    let sender = UdpSender::new(dest_addr);

    if args.repeat {
        loop {
            file.seek(std::io::SeekFrom::Start(0)).unwrap();
            let reader = LegacyPcapReader::new(65536, &mut file).unwrap();
            play(&sender, reader);
        }
    } else {
        let reader = LegacyPcapReader::new(65536, &mut file).unwrap();
        play(&sender, reader);
    }
}

pub struct Args {
    input: String,
    port: Option<u16>,
    repeat: bool,
}

pub fn parse_args(args: &Vec<String>) -> Args {
    let mut opts = getopts::Options::new();
    opts.optopt("p", "port", "port number", "PORT");
    opts.optflag("r", "repeat", "repeat");
    let matches = opts.parse(&args[1..]).unwrap();
    let input = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        println!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    };
    let port = matches.opt_str("p").map(|s| s.parse().unwrap());
    let repeat = matches.opt_present("r");
    Args {
        input,
        port,
        repeat,
    }
}

fn play(sender: &UdpSender, mut reader: LegacyPcapReader<&mut File>) {
    let mut num_packets = 0;
    let start = std::time::Instant::now();
    let mut time_offset: Option<i64> = None;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                // num_packets += 1;
                match block {
                    PcapBlockOwned::Legacy(packet) => {
                        // etherのヘッダ長は14byte
                        let ether_data = &packet.data[14..];
                        // ipv4のヘッダ長は可変(基本20byte)
                        let ip_header_size = ((ether_data[0] & 15) * 4) as usize;
                        let packet_size = (((ether_data[2] as u32) << 8) + ether_data[3] as u32) as usize;
                        let ip_data = &ether_data[ip_header_size..packet_size];
                        // udpのヘッダ長は8byte
                        let udp_data = &ip_data[8..ip_data.len()];

                        let timestamp_us = (packet.ts_usec as i64) + (packet.ts_sec as i64) * 1000000;
                        if time_offset.is_none() {
                            time_offset = Some(timestamp_us - (start.elapsed().as_micros() as i64));
                        }

                        let wait_us = (timestamp_us - time_offset.unwrap()) - start.elapsed().as_micros() as i64;
                        if wait_us > 0 {
                            if num_packets % 1000 == 0 {
                                println!("running early {}: {}us", num_packets, wait_us);
                            }
                            spin_sleep::sleep(std::time::Duration::from_micros(wait_us as u64));
                        }
                        else if wait_us < 0 {
                            if num_packets % 1000 == 0 {
                                println!("running late {}: {}us", num_packets, wait_us);
                            }
                        }
                        sender.send(udp_data);
                        
                        num_packets += 1;
                    },
                    _ => ()
                }
                reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(err) => panic!("packet read failed: {:?}", err),
        }    
    }
    println!("{} packets in {}sec", num_packets, start.elapsed().as_secs_f32());
}

struct UdpSender {
    sock: UdpSocket,
    dest_addr: String,
}

impl UdpSender {
    fn new(dest_addr: String) -> Self {
        let sock = UdpSocket::bind(SOURCE_ADDR).unwrap();
        sock.set_broadcast(true).unwrap();
        Self {
            sock,
            dest_addr,
        }
    }

    fn send(&self, data: &[u8]) {
        self.sock.send_to(data, &self.dest_addr).unwrap();
    }
}
