pub const ECHO_REPLY_TYPE: u8 = 0;
pub const DESTINATION_UNREACHABLE_TYPE: u8 = 3;
pub const ECHO_REQUEST_TYPE: u8 = 8;
pub const ECHO_REQUEST_CODE: u8 = 0;
pub const TIME_EXCEEDED_TYPE: u8 = 11;
pub const ICMP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIcmpResponse {
    pub icmp_type: u8,
    pub identifier: u16,
    pub sequence_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoRequest {
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: Vec<u8>,
}

impl EchoRequest {
    pub fn new(identifier: u16, sequence_number: u16, payload: Vec<u8>) -> Self {
        Self {
            identifier,
            sequence_number,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(ICMP_HEADER_LEN + self.payload.len());

        packet.push(ECHO_REQUEST_TYPE);
        packet.push(ECHO_REQUEST_CODE);

        // The checksum field must be zero while we calculate the checksum for
        // the rest of the packet.
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&self.identifier.to_be_bytes());
        packet.extend_from_slice(&self.sequence_number.to_be_bytes());
        packet.extend_from_slice(&self.payload);

        let checksum = internet_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }
}

pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;

    for chunk in bytes.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => unreachable!("chunks(2) only yields slices of length 1 or 2"),
        };

        sum += u32::from(word);

        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }

    !(sum as u16)
}

pub fn parse_icmp_response(packet: &[u8]) -> Option<ParsedIcmpResponse> {
    let outer_icmp = extract_icmp_packet(packet)?;
    let icmp_type = *outer_icmp.first()?;

    match icmp_type {
        ECHO_REPLY_TYPE => {
            let (identifier, sequence_number) = icmp_identifier_and_sequence(outer_icmp)?;

            Some(ParsedIcmpResponse {
                icmp_type,
                identifier,
                sequence_number,
            })
        }
        TIME_EXCEEDED_TYPE | DESTINATION_UNREACHABLE_TYPE => {
            // Routers include the original IPv4 header and the first 8 bytes of
            // the original payload, which is enough to recover the ICMP Echo
            // Request identifier and sequence number.
            let embedded_original_packet = outer_icmp.get(ICMP_HEADER_LEN..)?;
            let embedded_icmp = extract_icmp_packet(embedded_original_packet)?;

            if embedded_icmp.first().copied()? != ECHO_REQUEST_TYPE {
                return None;
            }

            let (identifier, sequence_number) = icmp_identifier_and_sequence(embedded_icmp)?;

            Some(ParsedIcmpResponse {
                icmp_type,
                identifier,
                sequence_number,
            })
        }
        _ => None,
    }
}

fn extract_icmp_packet(packet: &[u8]) -> Option<&[u8]> {
    let offset = ipv4_header_len(packet).unwrap_or(0);
    packet.get(offset..)
}

fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    let first_byte = *packet.first()?;

    if first_byte >> 4 != 4 {
        return None;
    }

    let header_len = usize::from(first_byte & 0x0f) * 4;
    if packet.len() < header_len {
        return None;
    }

    Some(header_len)
}

fn icmp_identifier_and_sequence(packet: &[u8]) -> Option<(u16, u16)> {
    if packet.len() < ICMP_HEADER_LEN {
        return None;
    }

    Some((
        u16::from_be_bytes([packet[4], packet[5]]),
        u16::from_be_bytes([packet[6], packet[7]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ECHO_REPLY_TYPE, ECHO_REQUEST_CODE, ECHO_REQUEST_TYPE, EchoRequest, ICMP_HEADER_LEN,
        ParsedIcmpResponse, TIME_EXCEEDED_TYPE, internet_checksum, parse_icmp_response,
    };

    #[test]
    fn internet_checksum_matches_rfc_1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];

        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn internet_checksum_pads_odd_length_inputs() {
        let data = [0x01, 0x02, 0x03];

        assert_eq!(internet_checksum(&data), 0xfbfd);
    }

    #[test]
    fn echo_request_packet_has_expected_layout() {
        let packet = EchoRequest::new(0x1234, 0x0001, b"rust".to_vec()).to_bytes();

        assert_eq!(packet.len(), ICMP_HEADER_LEN + 4);
        assert_eq!(packet[0], ECHO_REQUEST_TYPE);
        assert_eq!(packet[1], ECHO_REQUEST_CODE);
        assert_eq!(&packet[2..4], &[0xff, 0xe0]);
        assert_eq!(&packet[4..6], &[0x12, 0x34]);
        assert_eq!(&packet[6..8], &[0x00, 0x01]);
        assert_eq!(&packet[8..], b"rust");
        assert_eq!(internet_checksum(&packet), 0x0000);
    }

    #[test]
    fn parse_icmp_response_extracts_echo_reply_identifier_and_sequence() {
        let mut icmp_reply = vec![ECHO_REPLY_TYPE, 0, 0, 0];
        icmp_reply.extend_from_slice(&0x1234_u16.to_be_bytes());
        icmp_reply.extend_from_slice(&0x0007_u16.to_be_bytes());
        icmp_reply.extend_from_slice(b"rust");

        let packet = ipv4_packet(&icmp_reply);

        assert_eq!(
            parse_icmp_response(&packet),
            Some(ParsedIcmpResponse {
                icmp_type: ECHO_REPLY_TYPE,
                identifier: 0x1234,
                sequence_number: 0x0007,
            })
        );
    }

    #[test]
    fn parse_icmp_response_extracts_embedded_echo_request_from_time_exceeded() {
        let original_request = EchoRequest::new(0x1234, 0x0007, b"rust".to_vec()).to_bytes();
        let embedded_original_packet = ipv4_packet(&original_request);

        let mut time_exceeded = vec![TIME_EXCEEDED_TYPE, 0, 0, 0];
        time_exceeded.extend_from_slice(&[0, 0, 0, 0]);
        time_exceeded.extend_from_slice(&embedded_original_packet);

        let packet = ipv4_packet(&time_exceeded);

        assert_eq!(
            parse_icmp_response(&packet),
            Some(ParsedIcmpResponse {
                icmp_type: TIME_EXCEEDED_TYPE,
                identifier: 0x1234,
                sequence_number: 0x0007,
            })
        );
    }

    #[test]
    fn parse_icmp_response_ignores_time_exceeded_without_embedded_echo_request() {
        let mut non_echo_icmp = vec![3, 0, 0, 0];
        non_echo_icmp.extend_from_slice(&[0, 0, 0, 0]);
        let embedded_original_packet = ipv4_packet(&non_echo_icmp);

        let mut time_exceeded = vec![TIME_EXCEEDED_TYPE, 0, 0, 0];
        time_exceeded.extend_from_slice(&[0, 0, 0, 0]);
        time_exceeded.extend_from_slice(&embedded_original_packet);

        let packet = ipv4_packet(&time_exceeded);

        assert_eq!(parse_icmp_response(&packet), None);
    }

    fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + payload.len()) as u16;
        let mut packet = vec![
            0x45, 0x00, total_len.to_be_bytes()[0], total_len.to_be_bytes()[1], 0x12, 0x34, 0x00,
            0x00, 64, 1, 0x00, 0x00, 192, 0, 2, 1, 198, 51, 100, 1,
        ];
        packet.extend_from_slice(payload);
        packet
    }
}
