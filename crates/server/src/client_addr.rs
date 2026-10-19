//! The client address of spec 035-server-ops R3, and the trusted proxies it
//! believes: IP addresses and CIDR blocks, matched with `std::net` only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The widest prefix of each family: a bare address is a block of one.
const V4_BITS: u8 = 32;
const V6_BITS: u8 = 128;

/// An IP address or a CIDR block of `PRIVATECHAT_TRUSTED_PROXIES` (spec 035
/// R1), canonical: no bit set past its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// `text` as an address, or as `address/prefix` with a prefix of decimal
    /// digits no wider than its family. A block with a host bit set is
    /// refused rather than masked: `10.0.0.1/8` may mean one proxy or a
    /// whole /8, and the wider reading would trust every address in it.
    pub(crate) fn parse(text: &str) -> Option<IpNet> {
        let (addr, prefix) = match text.split_once('/') {
            None => (text, None),
            Some((addr, prefix)) => (addr, Some(prefix)),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let bits = match addr {
            IpAddr::V4(_) => V4_BITS,
            IpAddr::V6(_) => V6_BITS,
        };
        let prefix = match prefix {
            None => bits,
            Some(prefix) if !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()) => {
                prefix.parse().ok().filter(|prefix| *prefix <= bits)?
            }
            Some(_) => return None,
        };
        let net = IpNet { addr, prefix };
        (net.network() == addr).then_some(net)
    }

    /// The address with every bit past the prefix cleared.
    fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(v4) => {
                let mask = u32::MAX.checked_shl(u32::from(V4_BITS.saturating_sub(self.prefix)));
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask.unwrap_or(0)))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX.checked_shl(u32::from(V6_BITS.saturating_sub(self.prefix)));
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask.unwrap_or(0)))
            }
        }
    }
}
