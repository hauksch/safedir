//! Advisory addressability: may a sender with these role values address a
//! postbox with those role values?
//!
//! **This is a client-side guard, not a security boundary.** The role-pair
//! matrix is transcribed from *Teilnahme von Drittanwendungen am
//! OSCI-gestützten elektronischen Rechtsverkehr — Anforderungen* v1.8
//! (20 Apr 2022), section 5.3, and the communication rules of the
//! ERV-Leitfaden v1.6, section 4.2:
//!
//! - beA, beN, beSt and beBPo address each other, the justice postboxes and
//!   Behörden — and are addressable by all senders except `egvp_buerger`
//!   and `egvp_test`.
//! - eBO addresses justiz/besondere Postfächer plus `buerger_rueck` (not
//!   `egvp_behoerde`); eBO↔eBO only via
//!   additional intermediary services ("eBO-plus") — with statutory
//!   exceptions for Gerichtsvollzieher, Patentanwälte and parties'
//!   representatives (ERV-Leitfaden footnote 10).
//! - MJP (`ozg_postfach`) is subject to the same visibility as eBO but can
//!   neither address nor be addressed by eBO or other MJP.
//! - `egvp_buerger` addresses only authorities; `buerger_hin`/`buerger_rueck`
//!   (Gerichtsvollzieher) additionally address citizen postboxes.
//! - `egvp_test` is visible only among itself.
//!
//! OSCI intermediaries do **not** enforce any of this, and whether the
//! production VAS filters results by requester role is not publicly
//! documented. Treat every verdict as "should a well-behaved sender do
//! this?" — and always re-resolve immediately before sending (A14).

use crate::entry::{EntryState, SafeEntry};
use crate::roles::RoleValue;

/// Verdict of the advisory check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Addressability {
    /// Nothing speaks against addressing this recipient.
    Addressable,
    /// Addressing is possible only under the stated condition.
    Conditional(Condition),
    /// Addressing is ruled out, with the reason.
    NotAddressable(Reason),
}

/// Conditions under which addressing becomes possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Condition {
    /// eBO → eBO requires "eBO-plus" (additional intermediary services) or
    /// the statutory exception for Gerichtsvollzieher, Patentanwälte and
    /// representable organizations (ERV-Leitfaden 4.2 + footnote 10).
    EboToEboRequiresPlusOrException,
}

/// Reasons why addressing is ruled out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// No combination of sender/receiver role values allows the exchange.
    RoleVisibility {
        /// Sender role that was evaluated.
        sender: RoleValue,
        /// Receiver roles found on the entry.
        receiver_roles: Vec<RoleValue>,
    },
    /// The sender has no usable role values.
    SenderHasNoRoles,
    /// The entry carries no role values (ERR20 analogue).
    Inactive,
    /// The entry is shielded for a certificate changeover.
    CertificateChange,
    /// All known encryption certificates expired at the reference time
    /// (the directories would silently hide such entries, A9).
    CertsExpired,
    /// Certificates exist but are not yet valid.
    CertsNotYetValid,
    /// No recipient or reader certificates — unencryptable.
    NoCerts,
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RoleVisibility {
                sender,
                receiver_roles,
            } => write!(
                f,
                "role visibility: sender role {} may not address roles {:?}",
                sender.token(),
                receiver_roles
            ),
            Self::SenderHasNoRoles => write!(f, "sender has no role values"),
            Self::Inactive => write!(f, "postbox is inactive (no role values, ERR20-analogue)"),
            Self::CertificateChange => write!(f, "postbox is shielded for certificate changeover"),
            Self::CertsExpired => write!(f, "all known encryption certificates expired"),
            Self::CertsNotYetValid => write!(f, "certificates not yet valid"),
            Self::NoCerts => write!(f, "no encryption certificates"),
        }
    }
}

/// Receiver role values a sender role may address, per the matrix below.
/// Note: `egvp_test` is deliberately absent from every list except its own.
fn allowed_receivers(sender: &RoleValue) -> &'static [RoleValue] {
    use RoleValue::*;
    // Decoded from the §5.3 table (Anforderungspapier p. 19, layout-aware
    // extraction, cross-checked against the per-role prose; see research
    // report §3.5). Rows = sender, columns = addressable receiver.
    match sender {
        // Everyone except test; only justiz also reaches zuzu.
        EgvpJustiz => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            EgvpEbo,
            OzgPostfach,
            EgvpBuerger,
            BuergerHin,
            BuergerRueck,
            Zuzu,
        ],
        EgvpBehoerde => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            EgvpEbo,
            OzgPostfach,
            EgvpBuerger,
            BuergerHin,
            BuergerRueck,
        ],
        // Gerichtsvollzieher: everything except test.
        BuergerHin | BuergerRueck => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            EgvpEbo,
            OzgPostfach,
            EgvpBuerger,
            BuergerHin,
            BuergerRueck,
            Zuzu,
        ],
        // Besondere Postfächer: authorities + GV + each other + eBO + MJP
        // (not egvp_buerger, not zuzu). beBPo additionally reaches
        // egvp_buerger.
        EgvpBea | EgvpBen | EgvpBest => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            EgvpEbo,
            OzgPostfach,
            BuergerHin,
            BuergerRueck,
        ],
        EgvpBebpo => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            EgvpEbo,
            OzgPostfach,
            EgvpBuerger,
            BuergerHin,
            BuergerRueck,
        ],
        // eBO and MJP: besondere Postfächer + justiz + the GV reply
        // channel (buerger_rueck); NOT behoerde, buerger, each other.
        // eBO→eBO is surfaced as Conditional (eBO-plus), MJP has none.
        EgvpEbo | OzgPostfach => &[
            EgvpJustiz,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            BuergerRueck,
        ],
        // egvp_buerger: authorities (incl. beBPo) and reply-capable GV.
        EgvpBuerger => &[EgvpJustiz, EgvpBehoerde, EgvpBebpo, BuergerRueck],
        // Test sees only test.
        EgvpTest => &[EgvpTest],
        // Shield state, the additive zuzu consent, and unknown role values
        // grant no visibility (conservative; zuzu has no row in §5.3).
        Zertifikatswechsel | Zuzu | Other(_) => &[],
    }
}

/// Full advisory verdict for a sender (all of its role values) against an
/// entry, at a reference time (Unix seconds).
///
/// Semantics: addressable if *any* sender role may address *any* receiver
/// role (OR across sender roles, per the standard's Oder-Suche for role
/// filters). If no role pair matches but the eBO→eBO constellation is
/// present, the condition is surfaced; entry states override everything.
#[must_use]
pub fn addressability(
    sender_roles: &[RoleValue],
    receiver: &SafeEntry,
    now_unix: i64,
) -> Addressability {
    match receiver.state(now_unix) {
        EntryState::CertificateChange => {
            return Addressability::NotAddressable(Reason::CertificateChange);
        }
        EntryState::Inactive => return Addressability::NotAddressable(Reason::Inactive),
        EntryState::CertsExpired => {
            return Addressability::NotAddressable(Reason::CertsExpired);
        }
        EntryState::CertsNotYetValid => {
            return Addressability::NotAddressable(Reason::CertsNotYetValid);
        }
        EntryState::NoCerts => return Addressability::NotAddressable(Reason::NoCerts),
        EntryState::Active | EntryState::CertsUnknown => {}
    }

    if sender_roles.is_empty() {
        return Addressability::NotAddressable(Reason::SenderHasNoRoles);
    }

    let mut first_sender: Option<&RoleValue> = None;
    let mut ebo_to_ebo = false;
    for sender in sender_roles {
        if first_sender.is_none() {
            first_sender = Some(sender);
        }
        let allowed = allowed_receivers(sender);
        if receiver.roles.iter().any(|r| allowed.contains(r)) {
            return Addressability::Addressable;
        }
        if *sender == RoleValue::EgvpEbo && receiver.has_role(RoleValue::EgvpEbo) {
            ebo_to_ebo = true;
        }
    }

    if ebo_to_ebo {
        return Addressability::Conditional(Condition::EboToEboRequiresPlusOrException);
    }
    Addressability::NotAddressable(Reason::RoleVisibility {
        sender: first_sender.cloned().unwrap_or(RoleValue::EgvpBuerger),
        receiver_roles: receiver.roles.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::test_support::TEST_CERT_PEM;
    use crate::entry::{CertRef, Directory, OsciEndpoint};

    const NOW: i64 = 1_760_000_000;

    fn mk(roles: &[RoleValue]) -> SafeEntry {
        SafeEntry {
            safe_id: "DE.Justiz.dbf3d18a-5c6e-4a0b-9f1e-2a7c8e4d1b30.10dd"
                .parse()
                .unwrap(),
            directory: Directory::Justiz,
            vorname: None,
            name: "Amt".into(),
            beruf: None,
            kanzlei: None,
            abteilung: None,
            strasse: None,
            hausnummer: None,
            plz: None,
            ort: None,
            bundesland: None,
            land: None,
            telefon: None,
            mobil: None,
            dienststellen_ids: Vec::new(),
            roles: roles.to_vec(),
            osci: OsciEndpoint {
                intermediary_url: "https://x/".into(),
                intermediary_cipher: CertRef::__test_with_validity(
                    TEST_CERT_PEM,
                    NOW - 1000,
                    NOW + 1000,
                ),
                recipient_cipher: vec![CertRef::__test_with_validity(
                    TEST_CERT_PEM,
                    NOW - 1000,
                    NOW + 1000,
                )],
                reader_cipher: vec![],
            },
            warnings: Vec::new(),
        }
    }

    use RoleValue as R;

    // Table transcribed from the requirements paper §5.3 prose + the
    // ERV-Leitfaden 4.2 communication rules.
    #[test]
    fn matrix_cases() {
        let cases: &[(R, R, bool)] = &[
            // Transcribed from the layout-decoded §5.3 table (verified
            // 2026-10-11, see research report §3.5).
            // beA addresses everyone relevant incl. GV, is addressed by all.
            (R::EgvpBea, R::EgvpJustiz, true),
            (R::EgvpBea, R::EgvpBea, true),
            (R::EgvpBea, R::EgvpBen, true),
            (R::EgvpBea, R::EgvpBest, true),
            (R::EgvpBea, R::EgvpBebpo, true),
            (R::EgvpBea, R::EgvpEbo, true),
            (R::EgvpBea, R::OzgPostfach, true),
            (R::EgvpBea, R::EgvpBehoerde, true),
            (R::EgvpBea, R::BuergerHin, true),
            (R::EgvpBea, R::BuergerRueck, true),
            (R::EgvpBea, R::EgvpBuerger, false),
            (R::EgvpBea, R::Zuzu, false),
            // Justiz and (legacy) Behörden: everything except test; only
            // justiz also reaches zuzu.
            (R::EgvpJustiz, R::EgvpEbo, true),
            (R::EgvpJustiz, R::OzgPostfach, true),
            (R::EgvpJustiz, R::EgvpBuerger, true),
            (R::EgvpJustiz, R::EgvpJustiz, true),
            (R::EgvpJustiz, R::BuergerRueck, true),
            (R::EgvpJustiz, R::Zuzu, true),
            (R::EgvpJustiz, R::EgvpTest, false),
            (R::EgvpBehoerde, R::EgvpBuerger, true),
            (R::EgvpBehoerde, R::Zuzu, false),
            // Gerichtsvollzieher: everything except test.
            (R::BuergerHin, R::EgvpBuerger, true),
            (R::BuergerHin, R::EgvpBea, true),
            (R::BuergerRueck, R::EgvpEbo, true),
            (R::BuergerRueck, R::EgvpBea, true),
            (R::BuergerRueck, R::OzgPostfach, true),
            (R::BuergerRueck, R::Zuzu, true),
            (R::BuergerRueck, R::BuergerHin, true),
            (R::BuergerRueck, R::EgvpTest, false),
            // eBO/MJP: besondere + justiz + buerger_rueck only.
            (R::EgvpEbo, R::EgvpJustiz, true),
            (R::EgvpEbo, R::EgvpBea, true),
            (R::EgvpEbo, R::EgvpBebpo, true),
            (R::EgvpEbo, R::BuergerRueck, true),
            (R::EgvpEbo, R::EgvpBehoerde, false),
            (R::EgvpEbo, R::EgvpBuerger, false),
            (R::EgvpEbo, R::OzgPostfach, false),
            (R::OzgPostfach, R::EgvpJustiz, true),
            (R::OzgPostfach, R::EgvpBea, true),
            (R::OzgPostfach, R::BuergerRueck, true),
            (R::OzgPostfach, R::EgvpEbo, false),
            (R::OzgPostfach, R::OzgPostfach, false),
            (R::OzgPostfach, R::EgvpBehoerde, false),
            // egvp_buerger: authorities + reply-capable GV only.
            (R::EgvpBuerger, R::EgvpJustiz, true),
            (R::EgvpBuerger, R::EgvpBebpo, true),
            (R::EgvpBuerger, R::BuergerRueck, true),
            (R::EgvpBuerger, R::BuergerHin, false),
            (R::EgvpBuerger, R::EgvpBea, false),
            (R::EgvpBuerger, R::EgvpBuerger, false),
            // beBPo: besondere set plus egvp_buerger.
            (R::EgvpBebpo, R::EgvpBuerger, true),
            (R::EgvpBebpo, R::BuergerHin, true),
            (R::EgvpBebpo, R::Zuzu, false),
            // Test only among itself.
            (R::EgvpTest, R::EgvpTest, true),
            (R::EgvpTest, R::EgvpJustiz, false),
            // beN/beSt behave like beA.
            (R::EgvpBen, R::EgvpEbo, true),
            (R::EgvpBest, R::OzgPostfach, true),
        ];

        for (sender, receiver, expected) in cases {
            let entry = mk(std::slice::from_ref(receiver));
            let verdict = addressability(std::slice::from_ref(sender), &entry, NOW);
            let got = matches!(verdict, Addressability::Addressable);
            assert_eq!(got, *expected, "{sender:?} -> {receiver:?}: {verdict:?}");
        }
    }

    #[test]
    fn ebo_to_ebo_is_conditional() {
        let entry = mk(&[R::EgvpEbo]);
        assert_eq!(
            addressability(&[R::EgvpEbo], &entry, NOW),
            Addressability::Conditional(Condition::EboToEboRequiresPlusOrException)
        );
    }

    #[test]
    fn multiple_sender_roles_or() {
        // Entry has egvp_buerger; sender with [egvp_ebo, egvp_justiz] is
        // addressable via the justiz role even though ebo alone is not.
        let entry = mk(&[R::EgvpBuerger]);
        assert!(matches!(
            addressability(&[R::EgvpEbo, R::EgvpJustiz], &entry, NOW),
            Addressability::Addressable
        ));
        // And an entry with two receiver roles matches on either.
        let entry = mk(&[R::EgvpBuerger, R::BuergerRueck]);
        assert!(matches!(
            addressability(&[R::EgvpBuerger], &entry, NOW),
            Addressability::Addressable
        ));
    }

    #[test]
    fn entry_states_override() {
        let shielded = mk(&[R::Zertifikatswechsel]);
        assert!(matches!(
            addressability(&[R::EgvpJustiz], &shielded, NOW),
            Addressability::NotAddressable(Reason::CertificateChange)
        ));

        let mut expired = mk(&[R::EgvpJustiz]);
        expired.osci.recipient_cipher = vec![CertRef::__test_with_validity(
            TEST_CERT_PEM,
            NOW - 2000,
            NOW - 1000,
        )];
        assert!(matches!(
            addressability(&[R::EgvpJustiz], &expired, NOW),
            Addressability::NotAddressable(Reason::CertsExpired)
        ));

        let inactive = mk(&[]);
        assert!(matches!(
            addressability(&[R::EgvpJustiz], &inactive, NOW),
            Addressability::NotAddressable(Reason::Inactive)
        ));
    }

    #[test]
    fn exotic_senders_and_receivers_are_conservative() {
        let justiz_entry = mk(&[R::EgvpJustiz]);
        // zuzu (additive consent) and unknown roles grant no visibility.
        assert!(matches!(
            addressability(&[R::Zuzu], &justiz_entry, NOW),
            Addressability::NotAddressable(_)
        ));
        assert!(matches!(
            addressability(&[R::Other("egvp_future".into())], &justiz_entry, NOW),
            Addressability::NotAddressable(_)
        ));
        // A receiver carrying only an unknown role is not addressable.
        let other_entry = mk(&[R::Other("egvp_future".into())]);
        assert!(matches!(
            addressability(&[R::EgvpJustiz], &other_entry, NOW),
            Addressability::NotAddressable(_)
        ));
    }

    #[test]
    fn no_sender_roles() {
        let entry = mk(&[R::EgvpJustiz]);
        assert!(matches!(
            addressability(&[], &entry, NOW),
            Addressability::NotAddressable(Reason::SenderHasNoRoles)
        ));
    }
}
