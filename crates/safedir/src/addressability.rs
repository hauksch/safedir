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
//!   (Behörden) — and can be addressed by everyone incl. eBO/MJP holders.
//! - eBO addresses justiz/Behörden/besondere Postfächer; eBO↔eBO only via
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
            Self::Inactive => write!(f, "postbox is inactive (no role values, ERR20)"),
            Self::CertificateChange => write!(f, "postbox is shielded for certificate changeover"),
            Self::CertsExpired => write!(f, "all known encryption certificates expired"),
        }
    }
}

/// Receiver role values a sender role may address, per the matrix below.
/// Note: `egvp_test` is deliberately absent from every list except its own.
fn allowed_receivers(sender: &RoleValue) -> &'static [RoleValue] {
    use RoleValue::*;
    match sender {
        // Justiz and (legacy) Behörden address everyone except test
        // postboxes.
        EgvpJustiz | EgvpBehoerde => &[
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
        // Besondere Postfächer: each other, justice/authorities, eBO, MJP.
        EgvpBea | EgvpBen | EgvpBest | EgvpBebpo => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
            EgvpEbo,
            OzgPostfach,
        ],
        // eBO and MJP: justice/authorities + besondere Postfächer only.
        // eBO→eBO is handled as Conditional, MJP neither eBO nor MJP.
        EgvpEbo | OzgPostfach => &[
            EgvpJustiz,
            EgvpBehoerde,
            EgvpBea,
            EgvpBen,
            EgvpBest,
            EgvpBebpo,
        ],
        // egvp_buerger: authorities (incl. beBPo) and reply-capable GV.
        EgvpBuerger => &[EgvpJustiz, EgvpBehoerde, EgvpBebpo, BuergerRueck],
        // Gerichtsvollzieher: authorities plus citizen postboxes
        // ("Bürgerpostfächer" = eBO + egvp_buerger; not MJP).
        BuergerHin | BuergerRueck => &[EgvpJustiz, EgvpBehoerde, EgvpBebpo, EgvpBuerger, EgvpEbo],
        // Test sees only test.
        EgvpTest => &[EgvpTest],
        // Shield state, the additive zuzu consent, and unknown role values
        // grant no visibility (conservative).
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
            // beA addresses everyone relevant, is addressed by everyone.
            (R::EgvpBea, R::EgvpJustiz, true),
            (R::EgvpBea, R::EgvpBea, true),
            (R::EgvpBea, R::EgvpBen, true),
            (R::EgvpBea, R::EgvpBest, true),
            (R::EgvpBea, R::EgvpBebpo, true),
            (R::EgvpBea, R::EgvpEbo, true),
            (R::EgvpBea, R::OzgPostfach, true),
            (R::EgvpBea, R::EgvpBehoerde, true),
            // Justiz addresses everyone incl. citizens.
            (R::EgvpJustiz, R::EgvpEbo, true),
            (R::EgvpJustiz, R::OzgPostfach, true),
            (R::EgvpJustiz, R::EgvpBuerger, true),
            (R::EgvpJustiz, R::EgvpJustiz, true),
            (R::EgvpJustiz, R::BuergerRueck, true),
            // eBO: justice + besondere only.
            (R::EgvpEbo, R::EgvpJustiz, true),
            (R::EgvpEbo, R::EgvpBea, true),
            (R::EgvpEbo, R::EgvpBebpo, true),
            (R::EgvpEbo, R::EgvpBuerger, false),
            (R::EgvpEbo, R::OzgPostfach, false),
            // MJP: like eBO, but never eBO.
            (R::OzgPostfach, R::EgvpJustiz, true),
            (R::OzgPostfach, R::EgvpBea, true),
            (R::OzgPostfach, R::EgvpEbo, false),
            (R::OzgPostfach, R::OzgPostfach, false),
            // egvp_buerger: authorities + reply-capable GV only.
            (R::EgvpBuerger, R::EgvpJustiz, true),
            (R::EgvpBuerger, R::EgvpBebpo, true),
            (R::EgvpBuerger, R::BuergerRueck, true),
            (R::EgvpBuerger, R::BuergerHin, false),
            (R::EgvpBuerger, R::EgvpBea, false),
            (R::EgvpBuerger, R::EgvpBuerger, false),
            // Gerichtsvollzieher reach citizen postboxes.
            (R::BuergerHin, R::EgvpBuerger, true),
            (R::BuergerRueck, R::EgvpEbo, true),
            (R::BuergerRueck, R::EgvpBea, false),
            // Test only among itself.
            (R::EgvpTest, R::EgvpTest, true),
            (R::EgvpTest, R::EgvpJustiz, false),
            (R::EgvpJustiz, R::EgvpTest, false),
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
    fn no_sender_roles() {
        let entry = mk(&[R::EgvpJustiz]);
        assert!(matches!(
            addressability(&[], &entry, NOW),
            Addressability::NotAddressable(Reason::SenderHasNoRoles)
        ));
    }
}
