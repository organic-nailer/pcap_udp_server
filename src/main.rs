use std::net::UdpSocket;
use std::env;
use std::fs::File;
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use spin_sleep;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <filename>", args[0]);
        return;
    }

    let filename = &args[1];
    let mut file = File::open(filename).unwrap();
    let mut reader = LegacyPcapReader::new(65536, &mut file).unwrap();

    let sock = UdpSocket::bind("127.0.0.1:8081").unwrap();
    sock.set_broadcast(true).unwrap();

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
                        sock.send_to(udp_data, "255.255.255.255:8080").unwrap();
                        
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
    println!("num_packets: {}", num_packets);
    println!("elapsed: {} ms", start.elapsed().as_millis());
}
