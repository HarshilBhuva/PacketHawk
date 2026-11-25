//! Offline PCAP/PCAPNG ingestion and bounded packet metadata decoding.

use std::{
    fs::File,
    io::{self, BufReader, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use thiserror::Error;

use crate::models::{NormalizedPacket, TransportProtocol};

const MAX_CAPTURE_BYTES: u64 = 512 * 1024 * 1024;
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("failed to read capture: {0}")]
    Io(#[from] io::Error),
    #[error("capture exceeds the configured safety limit of {MAX_CAPTURE_BYTES} bytes")]
    TooLarge,
    #[error("unsupported or unrecognized capture format")]
    UnknownFormat,
    #[error("malformed capture: {0}")]
    Malformed(&'static str),
    #[error("unsupported link-layer type: {0}")]
    UnsupportedLinkType(u32),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CaptureStats {
    pub decoded_packets: usize,
    pub skipped_packets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaptureReport {
    pub packets: Vec<NormalizedPacket>,
    pub skipped_packets: usize,
}

/// Reads a capture from disk. Input is capped to avoid unbounded allocations.
pub struct CaptureReader;

impl CaptureReader {
    pub fn read_path(path: impl AsRef<Path>) -> Result<CaptureReport, CaptureError> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        if size > MAX_CAPTURE_BYTES {
            return Err(CaptureError::TooLarge);
        }
        Self::read(file)
    }

    /// Visit decoded packets without retaining the complete classic-PCAP packet list.
    ///
    /// Classic PCAP records are read and decoded one at a time. PCAPNG currently
    /// uses the compatibility parser and therefore materializes its packet list.
    pub fn visit_path(
        path: impl AsRef<Path>,
        mut visitor: impl FnMut(NormalizedPacket),
    ) -> Result<CaptureStats, CaptureError> {
        let path = path.as_ref();
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_CAPTURE_BYTES {
            return Err(CaptureError::TooLarge);
        }
        let mut reader = BufReader::new(file);
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                CaptureError::Malformed("truncated PCAP global header")
            } else {
                CaptureError::Io(error)
            }
        })?;

        if magic == [0x0a, 0x0d, 0x0a, 0x0a] {
            return Err(CaptureError::UnknownFormat);
        }
        if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            let report = Self::read_path(path)?;
            let stats = CaptureStats {
                decoded_packets: report.packets.len(),
                skipped_packets: report.skipped_packets,
            };
            for packet in report.packets {
                visitor(packet);
            }
            return Ok(stats);
        }

        visit_classic_pcap(reader, magic, &mut visitor)
    }

    pub fn read(reader: impl Read) -> Result<CaptureReport, CaptureError> {
        let mut bytes = Vec::new();
        reader.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CAPTURE_BYTES {
            return Err(CaptureError::TooLarge);
        }
        if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
            parse_pcapng(&bytes)
        } else {
            parse_pcap(&bytes)
        }
    }
}


fn read_bounded<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    bytes_read: &mut u64,
) -> Result<(), CaptureError> {
    let next_size = bytes_read.saturating_add(buffer.len() as u64);
    if next_size > MAX_CAPTURE_BYTES {
        return Err(CaptureError::TooLarge);
    }
    reader.read_exact(buffer)?;
    *bytes_read = next_size;
    Ok(())
}

fn visit_classic_pcap<R: Read>(
    mut reader: R,
    magic: [u8; 4],
    visitor: &mut impl FnMut(NormalizedPacket),
) -> Result<CaptureStats, CaptureError> {
    let (endian, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => return Err(CaptureError::UnknownFormat),
    };

    let mut global_header = [0u8; 20];
    let mut bytes_read = 4u64;
    read_bounded(&mut reader, &mut global_header, &mut bytes_read).map_err(|error| match error {
        CaptureError::Io(ref io_error) if io_error.kind() == io::ErrorKind::UnexpectedEof => {
            CaptureError::Malformed("truncated PCAP global header")
        }
        other => other,
    })?;
    let link_type = endian.u32(&global_header[16..20]);
    validate_link_type(link_type)?;

    let mut stats = CaptureStats::default();
    loop {
        let mut packet_header = [0u8; 16];
        let first = reader.read(&mut packet_header[..1])?;
        if first == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(1);
        if bytes_read > MAX_CAPTURE_BYTES {
            return Err(CaptureError::TooLarge);
        }
        read_bounded(&mut reader, &mut packet_header[1..], &mut bytes_read).map_err(|error| {
            match error {
                CaptureError::Io(ref io_error)
                    if io_error.kind() == io::ErrorKind::UnexpectedEof =>
                {
                    CaptureError::Malformed("truncated PCAP packet header")
                }
                other => other,
            }
        })?;

        let seconds = endian.u32(&packet_header[0..4]) as u128;
        let fraction = endian.u32(&packet_header[4..8]) as u128;
        let captured = endian.u32(&packet_header[8..12]) as usize;
        let original = endian.u32(&packet_header[12..16]) as usize;
        if captured > original {
            return Err(CaptureError::Malformed(
                "invalid or truncated PCAP packet data",
            ));
        }

        let mut frame = vec![0u8; captured];
        read_bounded(&mut reader, &mut frame, &mut bytes_read).map_err(|error| match error {
            CaptureError::Io(ref io_error) if io_error.kind() == io::ErrorKind::UnexpectedEof => {
                CaptureError::Malformed("invalid or truncated PCAP packet data")
            }
            other => other,
        })?;

        let timestamp_ns = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(if nanos {
                fraction
            } else {
                fraction.saturating_mul(1_000)
            });
        if let Some(packet) = decode_frame(link_type, &frame, timestamp_ns) {
            stats.decoded_packets = stats.decoded_packets.saturating_add(1);
            visitor(packet);
        } else {
            stats.skipped_packets = stats.skipped_packets.saturating_add(1);
        }
    }
    Ok(stats)
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        let value = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(value),
            Self::Big => u16::from_be_bytes(value),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(value),
            Self::Big => u32::from_be_bytes(value),
        }
    }

    fn i64(self, bytes: &[u8]) -> i64 {
        let value: [u8; 8] = bytes[..8].try_into().expect("length checked by caller");
        match self {
            Self::Little => i64::from_le_bytes(value),
            Self::Big => i64::from_be_bytes(value),
        }
    }
}

fn parse_pcap(bytes: &[u8]) -> Result<CaptureReport, CaptureError> {
    if bytes.len() < 24 {
        return Err(CaptureError::Malformed("truncated PCAP global header"));
    }
    let (endian, nanos) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => return Err(CaptureError::UnknownFormat),
    };
    let link_type = endian.u32(&bytes[20..24]);
    validate_link_type(link_type)?;

    let mut offset = 24;
    let mut report = CaptureReport {
        packets: Vec::new(),
        skipped_packets: 0,
    };
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(CaptureError::Malformed("truncated PCAP packet header"));
        }
        let header = &bytes[offset..offset + 16];
        let seconds = endian.u32(&header[0..4]) as u128;
        let fraction = endian.u32(&header[4..8]) as u128;
        let captured = endian.u32(&header[8..12]) as usize;
        let original = endian.u32(&header[12..16]) as usize;
        offset += 16;
        if captured > original || captured > bytes.len().saturating_sub(offset) {
            return Err(CaptureError::Malformed(
                "invalid or truncated PCAP packet data",
            ));
        }
        let timestamp_ns = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(if nanos {
                fraction
            } else {
                fraction.saturating_mul(1_000)
            });
        if let Some(packet) =
            decode_frame(link_type, &bytes[offset..offset + captured], timestamp_ns)
        {
            report.packets.push(packet);
        } else {
            report.skipped_packets += 1;
        }
        offset += captured;
    }
    Ok(report)
}

#[derive(Clone, Copy)]
struct Interface {
    link_type: u32,
    timestamp_units_per_second: u64,
    timestamp_offset: i64,
}

fn parse_pcapng(bytes: &[u8]) -> Result<CaptureReport, CaptureError> {
    let mut offset = 0usize;
    let mut endian = None;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut report = CaptureReport {
        packets: Vec::new(),
        skipped_packets: 0,
    };

    while offset < bytes.len() {
        if bytes.len() - offset >= 4
            && bytes[offset..offset + 4] == [0x0a, 0x0d, 0x0d, 0x0a]
            && bytes.len() - offset < 28
        {
            return Err(CaptureError::Malformed("truncated PCAPNG section header"));
        }
        if bytes.len() - offset < 12 {
            return Err(CaptureError::Malformed("truncated PCAPNG block header"));
        }
        let block_type_bytes = &bytes[offset..offset + 4];
        if block_type_bytes == [0x0a, 0x0d, 0x0d, 0x0a] {
            endian = Some(match &bytes[offset + 8..offset + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                _ => return Err(CaptureError::Malformed("invalid PCAPNG byte-order magic")),
            });
            interfaces.clear();
        }
        let order = endian.ok_or(CaptureError::Malformed(
            "PCAPNG block before section header",
        ))?;
        let block_len = order.u32(&bytes[offset + 4..offset + 8]) as usize;
        if block_len < 12 || block_len % 4 != 0 || block_len > bytes.len() - offset {
            return Err(CaptureError::Malformed("invalid PCAPNG block length"));
        }
        let block = &bytes[offset..offset + block_len];
        if order.u32(&block[block_len - 4..]) as usize != block_len {
            return Err(CaptureError::Malformed(
                "PCAPNG block length trailer mismatch",
            ));
        }

        match order.u32(block_type_bytes) {
            0x0a0d0d0a => {}
            1 => {
                if block_len < 20 {
                    return Err(CaptureError::Malformed(
                        "truncated interface description block",
                    ));
                }
                let link_type = order.u16(&block[8..10]) as u32;
                let mut interface = Interface {
                    link_type,
                    timestamp_units_per_second: 1_000_000,
                    timestamp_offset: 0,
                };
                parse_interface_options(&block[16..block_len - 4], order, &mut interface)?;
                interfaces.push(interface);
            }
            6 => {
                if block_len < 32 {
                    return Err(CaptureError::Malformed("truncated enhanced packet block"));
                }
                let interface_id = order.u32(&block[8..12]) as usize;
                let interface = *interfaces
                    .get(interface_id)
                    .ok_or(CaptureError::Malformed("unknown PCAPNG interface id"))?;
                validate_link_type(interface.link_type)?;
                let ticks =
                    ((order.u32(&block[12..16]) as u64) << 32) | order.u32(&block[16..20]) as u64;
                let captured = order.u32(&block[20..24]) as usize;
                let original = order.u32(&block[24..28]) as usize;
                let padded = captured
                    .checked_add(3)
                    .ok_or(CaptureError::Malformed("packet length overflow"))?
                    & !3;
                if captured > original || 28 + padded > block_len - 4 {
                    return Err(CaptureError::Malformed("invalid enhanced packet length"));
                }
                let timestamp_ns = ticks_to_ns(ticks, interface);
                if let Some(packet) =
                    decode_frame(interface.link_type, &block[28..28 + captured], timestamp_ns)
                {
                    report.packets.push(packet);
                } else {
                    report.skipped_packets += 1;
                }
            }
            3 => {
                if block_len < 16 {
                    return Err(CaptureError::Malformed("truncated simple packet block"));
                }
                let interface = *interfaces.first().ok_or(CaptureError::Malformed(
                    "simple packet block has no interface",
                ))?;
                validate_link_type(interface.link_type)?;
                let original = order.u32(&block[8..12]) as usize;
                let available = block_len - 16;
                let captured = original.min(available);
                if let Some(packet) =
                    decode_frame(interface.link_type, &block[12..12 + captured], 0)
                {
                    report.packets.push(packet);
                } else {
                    report.skipped_packets += 1;
                }
            }
            _ => {}
        }
        offset += block_len;
    }
    Ok(report)
}

fn parse_interface_options(
    options: &[u8],
    endian: Endian,
    interface: &mut Interface,
) -> Result<(), CaptureError> {
    let mut offset = 0;
    while offset + 4 <= options.len() {
        let code = endian.u16(&options[offset..offset + 2]);
        let length = endian.u16(&options[offset + 2..offset + 4]) as usize;
        offset += 4;
        if code == 0 {
            break;
        }
        let padded = length
            .checked_add(3)
            .ok_or(CaptureError::Malformed("option length overflow"))?
            & !3;
        if offset + padded > options.len() {
            return Err(CaptureError::Malformed("truncated PCAPNG interface option"));
        }
        let value = &options[offset..offset + length];
        match code {
            9 if length == 1 => {
                let exponent = value[0];
                interface.timestamp_units_per_second = if exponent & 0x80 == 0 {
                    10u64.checked_pow(exponent as u32)
                } else {
                    2u64.checked_pow((exponent & 0x7f) as u32)
                }
                .ok_or(CaptureError::Malformed("timestamp resolution overflow"))?;
            }
            14 if length == 8 => interface.timestamp_offset = endian.i64(value),
            _ => {}
        }
        offset += padded;
    }
    Ok(())
}

fn ticks_to_ns(ticks: u64, interface: Interface) -> u128 {
    let base = (ticks as u128).saturating_mul(1_000_000_000)
        / interface.timestamp_units_per_second.max(1) as u128;
    if interface.timestamp_offset >= 0 {
        base.saturating_add((interface.timestamp_offset as u128).saturating_mul(1_000_000_000))
    } else {
        base.saturating_sub(
            (interface.timestamp_offset.unsigned_abs() as u128).saturating_mul(1_000_000_000),
        )
    }
}

fn validate_link_type(link_type: u32) -> Result<(), CaptureError> {
    match link_type {
        LINKTYPE_ETHERNET | LINKTYPE_RAW | LINKTYPE_LINUX_SLL => Ok(()),
        other => Err(CaptureError::UnsupportedLinkType(other)),
    }
}

fn decode_frame(link_type: u32, frame: &[u8], timestamp_ns: u128) -> Option<NormalizedPacket> {
    let (ether_type, payload) = match link_type {
        LINKTYPE_ETHERNET => ethernet_payload(frame)?,
        LINKTYPE_RAW => {
            let version = frame.first()? >> 4;
            let protocol = if version == 4 {
                0x0800
            } else if version == 6 {
                0x86dd
            } else {
                return None;
            };
            (protocol, frame)
        }
        LINKTYPE_LINUX_SLL => {
            if frame.len() < 16 {
                return None;
            }
            (u16::from_be_bytes([frame[14], frame[15]]), &frame[16..])
        }
        _ => return None,
    };

    let (source_ip, destination_ip, protocol_number, transport) = match ether_type {
        0x0800 => {
            if payload.len() < 20 || payload[0] >> 4 != 4 {
                return None;
            }
            let header_len = ((payload[0] & 0x0f) as usize).checked_mul(4)?;
            if header_len < 20 || payload.len() < header_len {
                return None;
            }
            let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
            if total_len < header_len || payload.len() < total_len {
                return None;
            }
            let fragment = u16::from_be_bytes([payload[6], payload[7]]);
            if fragment & 0x1fff != 0 {
                return None;
            }
            let source = IpAddr::V4(Ipv4Addr::new(
                payload[12],
                payload[13],
                payload[14],
                payload[15],
            ));
            let destination = IpAddr::V4(Ipv4Addr::new(
                payload[16],
                payload[17],
                payload[18],
                payload[19],
            ));
            (
                source,
                destination,
                payload[9],
                &payload[header_len..total_len],
            )
        }
        0x86dd => {
            if payload.len() < 40 || payload[0] >> 4 != 6 {
                return None;
            }
            let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
            if payload.len() < 40 + payload_len {
                return None;
            }
            let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[8..24]).ok()?));
            let destination =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[24..40]).ok()?));
            let next = payload[6];
            if matches!(next, 0 | 43 | 44 | 51 | 60) {
                return None;
            }
            (source, destination, next, &payload[40..40 + payload_len])
        }
        _ => return None,
    };

    let (protocol, source_port, destination_port, tcp_flags) = match protocol_number {
        6 if transport.len() >= 20 => {
            let header_len = ((transport[12] >> 4) as usize).checked_mul(4)?;
            if header_len < 20 || transport.len() < header_len {
                return None;
            }
            (
                TransportProtocol::Tcp,
                Some(u16::from_be_bytes([transport[0], transport[1]])),
                Some(u16::from_be_bytes([transport[2], transport[3]])),
                Some(transport[13]),
            )
        }
        17 if transport.len() >= 8 => {
            let length = u16::from_be_bytes([transport[4], transport[5]]) as usize;
            if length < 8 || transport.len() < length {
                return None;
            }
            (
                TransportProtocol::Udp,
                Some(u16::from_be_bytes([transport[0], transport[1]])),
                Some(u16::from_be_bytes([transport[2], transport[3]])),
                None,
            )
        }
        1 => (TransportProtocol::Icmp, None, None, None),
        58 => (TransportProtocol::IcmpV6, None, None, None),
        other => (TransportProtocol::Other(other), None, None, None),
    };

    let dns_query_name = if protocol == TransportProtocol::Udp
        && (source_port == Some(53) || destination_port == Some(53))
    {
        parse_dns_query_name(transport.get(8..)?)
    } else {
        None
    };

    Some(NormalizedPacket {
        timestamp_ns,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
        packet_size: frame.len().min(u32::MAX as usize) as u32,
        tcp_flags,
        dns_query_name,
    })
}

fn parse_dns_query_name(message: &[u8]) -> Option<String> {
    if message.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let questions = u16::from_be_bytes([message[4], message[5]]);
    if flags & 0x8000 != 0 || questions == 0 {
        return None;
    }

    let mut cursor = 12usize;
    let mut consumed_end = None;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut wire_length = 0usize;
    let mut labels = Vec::new();

    loop {
        let length = *message.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let second = *message.get(cursor + 1)?;
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= message.len() {
                return None;
            }
            if !jumped {
                consumed_end = Some(cursor + 2);
            }
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        cursor += 1;
        if length == 0 {
            if !jumped {
                consumed_end = Some(cursor);
            }
            break;
        }

        let label_length = length as usize;
        if label_length > 63 || labels.len() >= 127 {
            return None;
        }
        let end = cursor.checked_add(label_length)?;
        let label_bytes = message.get(cursor..end)?;
        let label = std::str::from_utf8(label_bytes).ok()?;
        if !label.is_ascii() {
            return None;
        }
        wire_length = wire_length.checked_add(label_length + 1)?;
        if wire_length > 253 {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        cursor = end;
    }

    let end = consumed_end?;
    if end.checked_add(4)? > message.len() || labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

fn ethernet_payload(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.len() < 14 {
        return None;
    }
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    let mut vlan_depth = 0;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if vlan_depth == 2 || frame.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
        vlan_depth += 1;
    }
    Some((ether_type, &frame[offset..]))
}
