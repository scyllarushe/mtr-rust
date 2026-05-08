pub const ECHO_REQUEST_TYPE: u8 = 8;
pub const ECHO_REQUEST_CODE: u8 = 0;
pub const ICMP_HEADER_LEN: usize = 8;

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

#[cfg(test)]
mod tests {
    use super::{ECHO_REQUEST_CODE, ECHO_REQUEST_TYPE, EchoRequest, ICMP_HEADER_LEN, internet_checksum};

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
}
