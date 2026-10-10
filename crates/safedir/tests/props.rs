//! Property tests for SAFE-ID handling.

use proptest::prelude::*;
use safedir::safe_id::{Domain, IdKind, SafeId};

fn any_uuid(a: u64, b: u64) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        a as u16,
        (b >> 48) as u16,
        b & 0xffff_ffff_ffff
    )
}

prop_compose! {
    fn any_domain()(choice in 0u8..5) -> Domain {
        match choice {
            0 => Domain::Brak,
            1 => Domain::BenProd,
            2 => Domain::BNotkProduktiv,
            3 => Domain::Justiz,
            _ => Domain::Other("Steuerberaterkammer".to_owned()),
        }
    }
}

proptest! {
    #[test]
    fn compose_parses_round_trip(a in any::<u64>(), b in any::<u64>(), domain in any_domain()) {
        let uuid = any_uuid(a, b);
        let id = SafeId::compose(&domain, &uuid).unwrap();
        let s = id.to_string();
        let reparsed: SafeId = s.parse().unwrap();
        prop_assert_eq!(&reparsed, &id);
        let is_modern = matches!(reparsed.kind(), IdKind::Modern { .. });
        prop_assert!(is_modern);
    }

    #[test]
    fn tampered_checksum_rejected(a in any::<u64>(), b in any::<u64>()) {
        let uuid = any_uuid(a, b);
        let id = SafeId::compose(&Domain::Justiz, &uuid).unwrap();
        let s = id.to_string();
        // Flip the last hex character of the checksum segment.
        let last = s.chars().last().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        let tampered = format!("{}{}", &s[..s.len() - 1], flipped);
        prop_assert!(tampered.parse::<SafeId>().is_err());
    }

    #[test]
    fn legacy_ids_parse(millis in 1_000_000_000u64..4_294_967_295u64, seq in any::<u32>()) {
        let raw = format!("safe-sp1-{millis}-{seq:09}");
        let id: SafeId = raw.parse().unwrap();
        prop_assert_eq!(id.to_string(), raw);
        let is_legacy = matches!(id.kind(), IdKind::Legacy { .. });
        prop_assert!(is_legacy);
    }

    #[test]
    fn upper_case_body_still_validates(a in any::<u64>(), b in any::<u64>()) {
        // The checksum is computed over the lowercased body; upper-casing
        // domain/UUID must not break validation (checksum kept as-is).
        let uuid = any_uuid(a, b);
        let id = SafeId::compose(&Domain::Brak, &uuid).unwrap();
        let s = id.to_string();
        let (body, checksum) = s.split_at(s.len() - 5); // body + ".xxxx"
        let candidate = format!("{}{}", body.to_uppercase(), checksum);
        prop_assert!(candidate.parse::<SafeId>().is_ok());
    }
}
