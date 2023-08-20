use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let args = pcap_udp_server::parse_args("pcap_udp_server", &args);

    pcap_udp_server::run(args);
}
