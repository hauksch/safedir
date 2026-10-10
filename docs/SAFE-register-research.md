# The German SAFE Register, EGVP, OSCI and XJustiz — Research Report

**Purpose:** groundwork for a Rust library that finds and resolves ERV (elektronischer Rechtsverkehr) recipients by SAFE-ID.
**Date of research:** 10 October 2026. All facts were verified against primary sources during research; source URLs are given inline. Local copies of the most important specifications are in [`docs/specs/`](specs/).

> **Terminology warning up front:** "SAFE" is *not* a single central register run by one company. It is a **federation of four directory services** (Justiz, BRAK, BNotK, BStBK) searched through a central hub called the **VAS (Virtueller Attribut-Service)**. The former public web search at `www.safe-register.de` **no longer exists** — the domain does not resolve any more. Searching is a function *inside* the licensed/participating ERV client software.

---

## 1. Executive summary

1. The German justice system exchanges court documents over the **EGVP infrastructure** (Elektronisches Gerichts- und Verwaltungspostfach, live since December 2004), using the **OSCI 1.2** transport protocol (SOAP/XML, store-and-forward via intermediaries, "double envelope" encryption) and the **XJustiz** XML standard for structured metadata (`xjustiz_nachricht.xml` is a mandatory attachment of *every* message).
2. Every participant has a postbox registered in a **SAFE directory** ("Secure Access to Federated E-Justice/E-Government"). Each identity gets an immutable, unique **SAFE-ID** with a defined format (`DE.<Domain>.<UUID>.<hash-suffix>`) and a check-digit rule that is trivially implementable in Rust.
3. Recipient resolution = querying the federated directories through the **VAS** using standardized `search`/`lookup` operations built on **OASIS SPML 2.0 over SOAP** with a Liberty ID-SIS-PP data model. The governing standard is *"Standard für die Suche in den SAFE-Verzeichnissen der ERV-Kommunikationsinfrastruktur"*, version 1.5, dated 21 May 2026, issued by the **BLK-AG IT-Standards** (the IT standards working group of the Bund-Länder commission for IT in the justice system).
4. **The critical constraint for a library:** the VAS endpoint and its authentication are **not publicly documented**; access is granted to software products that have gone through the **third-party product registration procedure** of the BLK-AG IT-Standards (or that embed a registered product / use the free **EGVP-Enterprise** server component). A Rust library can implement everything *around* the interface (SAFE-ID parsing/validation, SPML message construction, XJustiz, VHN verification) offline and perfectly well, but live directory access requires being (or working for) a registered participant.
5. Corrected after deeper digging: the **OSCI-Transport-1.2 reference library by Governikus *is* open source** (`de.osci:osci-bibliothek`, dual-licensed EUPL-1.2/MIT, on Maven Central — latest 2.6.1, Aug 2026; canonical repo [gitlab.opencode.de/governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java)), and a **public registration-free OSCI 1.2 test intermediary exists at `gov.test.osci.de`**. Still true: **no Rust crate** for any part of this stack, and no Rust-native OSCI implementation — though [rosci](https://github.com/hauksch/rosci) (MIT) wraps the Java library behind a Rust CLI/REST interface. XJustiz *tooling* exists as open source (Java/Python/TypeScript); open source never touched the justice **directory** layer — that is safedir's gap.
6. Integration testing is possible: a **SAFE test environment** exists (`safetest.safe-justiz.de`), a dedicated **`egvp_test` role** shields test postboxes in the production system, a **Test-VHN CA** exists, and the complete XJustiz schema/Schematron packages plus a validator ("XJustiz-Werkzeuge") are freely downloadable. The **OSCI-Transport 1.2 specification is free as well** (ITZBund Bezugsstelle, maintained — Korrigendum 10 of Feb 2026) — what is *not* public is the VAS endpoint and live intermediary access.

---

## 2. The ecosystem in one page

### 2.1 Timeline

| Year | Event |
|---|---|
| 2001 | Zustellungsreformgesetz + Formvorschriftenanpassungsgesetz introduce the electronic form (§ 130a ZPO) |
| 2004 | EGVP infrastructure goes live (conceived by BVerwG/BFH with BSI, OVG Münster, Bremen & Hessen) |
| 2005 | XJustiz basis (OT-Leit-ERV) approved by the BLK, 13 May 2005 |
| 2011 | OSCI-Leitstelle becomes **KoSIT** (Koordinierungsstelle für IT-Standards, hosted by the Free Hanseatic City of Bremen) |
| 2016 | beA goes live (28 Nov 2016), runs "on the SAFE concept"; XJustiz 2.0 published 31 Dec 2016 |
| 2017 | ERVV adopted: **Verordnung vom 24.11.2017 (BGBl. I S. 3803)**; beBPo + beN connected 1 Jan 2018 |
| 2017 | OSCI 1.2 transport library CVEs (CVE-2017-10668/10669/10670, BSI CB-K17/1100) |
| 2021 | ERV-Ausbaugesetz (17 Sep 2021); VHN 2 specification (v2.2, 9 Dec 2021) |
| 2022 | Active e-filing duty for lawyers/authorities/jPöR (§ 130d ZPO, 1 Jan 2022); eBO legally live 1 Jan 2022, available 1 Jun 2022; new EGVP transport profile (project_coco/vhn_coco) released 1 Jun 2022 |
| 2023 | MJP (Mein Justizpostfach) pilot starts 12 Oct 2023 (§ 13 ERVV, free, BundID with trust level "hoch") |
| 2025 | ERVB 2025 (16 Jul 2025, BAnz AT 29.07.2025 B2) — current technical limits; BehAktÜbVO since 30 Apr 2025 |
| 2026 | XJustiz 3.6.2 valid (30 Apr 2026 – 30 Apr 2027); XJustiz 4.0.0 published 12 May 2026, valid from 30 Apr 2027; SAFE search standard v1.5 (21 May 2026) |

### 2.2 The postbox types and who operates them

| Postbox | Since | Operator / responsibility | SAFE domain |
|---|---|---|---|
| EGVP-Postfach (Justiz: courts, prosecutions, GV) | 2004 | Länder justice IT (each Land runs OSCI intermediaries) | `DE.Justiz` (SAFE public) |
| beA (lawyers) | 2016 | BRAK; developed/operated initially by Atos, since 2020 by **Wesroc GbR** (Westernacher Solutions + rockenstein AG) | `DE.BRAK` |
| beN (notaries) | 2018 | BNotK | `DE.BEN_PROD` / `DE.BNotK_Produktiv` |
| beSt (tax advisors) | ~2022+ | BStBK (Steuerberaterplattform) | BStBK domain |
| beBPo (authorities) | 2018 | Justiz-operated SAFE public; identification via per-Land **beBPo-Prüfstelle** (§ 7 ERVV) | `DE.Justiz` |
| eBO (citizens & organizations) | 2022 | SAFE public; registration with eID (Online-Ausweisfunktion) | `DE.Justiz` |
| MJP (Mein Justizpostfach) | pilot 2023 | Governikus GmbH & Co. KG on behalf of BMI; § 13 ERVV; **not** an eBO | `DE.Justiz` (role `ozg_postfach`) |
| De-Mail | 2012 | **discontinued** — mandatory federal use ended Jul 2024; last provider (FP DBS) shuts down 31 Dec 2026 | (converter-based, dead end) |

Sources: [egvp.justiz.de](https://egvp.justiz.de/), Wikipedia articles on beA/beBPo/eBO/MJP/EGVP, [steuerberaterplattform-bstbk.de](https://steuerberaterplattform-bstbk.de/best), VHN 2.2 spec § B, [ERV-Leitfaden v1.6 (2025)](https://justiz.de/ervvoe/leitfaden_erv_pdf.pdf) ch. 2 & 4.2.

### 2.3 Legal framework (as of Oct 2026)

- **§ 130a ZPO** (and parallels: § 55a VwGO, § 46c ArbGG, § 65a SGG, § 52a FGO, § 32a StPO): electronic documents satisfy the written form if (a) qualified-electronically signed (qeS) or (b) "einfache Signatur" + transmission over a **sicherer Übermittlungsweg** (secure path). A document is "filed" when it is stored on the intermediary (§ 130a Abs. 5 ZPO) — *not* when fetched.
- **§ 130d ZPO** (+ § 14b FamFG etc.): since 1 Jan 2022 lawyers, authorities and jPöR **must** file electronically.
- **Secure paths** per § 130a Abs. 4 Nr. 1–5 ZPO: beA, beN, beSt, beBPo, eBO, and the Postfach-/Versanddienst eines OZG-Nutzerkontos (MJP).
- **ERVV** — *Verordnung über die technischen Rahmenbedingungen des elektronischen Rechtsverkehrs und über das besondere elektronische Behördenpostfach*, **24 Nov 2017, BGBl. I S. 3803** (BJNR 380300017), last amended 5 Oct 2021. Key sections: § 2 (document/metadata requirements), § 4 (qeS rules; **container signatures prohibited**, Abs. 2), §§ 6–9 (beBPo incl. Prüfstelle), §§ 10–13 (eBO, identification, **MJP**), §§ 14–15 (criminal), §§ 16–17 (notary/court genehmigungsverfahren). <https://www.gesetze-im-internet.de/ervv/>
- **ERVB** — the BMJ bulletin under § 5 ERVV fixing concrete technical parameters. Current: **ERVB 2025** (16 Jul 2025, BAnz AT 29.07.2025 B2, in force 30 Jul 2025). Published at <https://justiz.de/laender-bund-europa/elektronische_kommunikation/index.php> (local copy: `docs/specs/ervb2025.pdf`).
- **ERV-Ausbaugesetz** (17 Sep 2021), **BehAktÜbVO** (Behördenaktenübermittlung, since 30 Apr 2025), RAVPV §§ 19–29 (beA), § 31a BRAO (BRAK must provision a beA per lawyer).
- A separate "E-Rechtsverkehrs-Gesetz (ERVG)" does **not** exist on gesetze-im-internet.de as of Oct 2026 (checked; `/ervg/` returns 404). Current law = ERVV + ERVB.

---

## 3. SAFE in depth

### 3.1 What SAFE is

SAFE = **S**ecure **A**ccess to **F**ederated **E**-Justice/E-Government. It is the identity & directory layer of the EGVP infrastructure: every postbox holder is registered in exactly one SAFE directory with personal data, role value(s), certificates, and the connection parameters of their OSCI intermediary. Without registration "neither an initial data exchange nor a reply to an ERV participant is possible" (SAFE search standard, § 1).

**Four federated directories** (SAFE instances), each run by its professional body:

1. **SAFE public (Justiz)** — courts, prosecutions (Staatsanwaltschaften), JVA, authorities (beBPo), citizens/organizations (eBO/MJP), Gerichtsvollzieher, Dolmetscher, Patentanwälte.
2. **SAFE-BRAK** — Rechtsanwälte, Syndikusrechtsanwälte, Berufsausübungsgesellschaften (BAGen), Rechtsanwaltskammern, Anwaltsgericht, Schlichtungsstelle.
3. **SAFE-BNotK** — Notarinnen/Notare, Notariatsverwalter.
4. **SAFE-BStBK** — Steuerberater/Steuerbevollmächtigte, BAGen, Steuerberaterkammern.

The **VAS (Virtueller Attribut-Service)** is the central hub that fans a search out to all directories and merges the results.

### 3.2 SAFE portals (Justiz domain)

| Portal | Purpose |
|---|---|
| `https://safe.safe-justiz.de/safe-registration-client/` | SAFE registration client — users register and manage their access data ("SAFE ist die Nutzerverwaltungsplattform der Justiz") |
| `https://safe.safe-justiz.de/safe-identity-admin/` | SAFE identity administration — restricted to SAFE identity administrators of the Länder/institutions |
| `https://zertifikate.safe-justiz.de/UserCertificateManagementUI/` | Web app for downloading software certificates (VHN, SAFE identity admins, SAFE users, eBOs); guide v1.2 (Dec 2021) |
| `https://safetest.safe-justiz.de/safe-registration-client/` | **Test environment** for the SAFE registration client |

Administration model (from the BNotK "SAFE Identitätsadministration" guide v1.4, 10 Oct 2024, local copy `/tmp` → see sources): identity administrators **cannot create** SAFE users; they confirm and manage already-registered ones, assign role types (BNotK-ZTR for the zentrales Testamentsregister, EGVP, ZSSR for the zentrales staatsanwaltschaftliches Verfahrensregister), and maintain per-user: personal/address data, login data, the **EGVP tab (URL of the OSCI-Manager/intermediary, the "Externe-ID" = Dienststellen-ID, certificates)**, soft- and hardware certificates. SAFE is thus also the user administration for other justice registers (ZTR, ZSSR), not just postboxes.

### 3.3 The SAFE-ID

From *„SAFE-ID — Abbildungsvorschrift, Stand Juli 2017"* (local copy `docs/specs/SAFE_Abbildungsvorschrift_SAFE_ID_V2.pdf`):

- Every identity in a SAFE-conformant IdM system gets a **unique, immutable** SAFE-ID.
- **Current format:** `DE.<Domain>.<UUID>.<checkdigits>`
  - Example: `DE.BNotK_Produktiv.024565fc-8d9d-11e3-aa83-2c768a4f9bf4.85ed`
  - Domains in use: `DE.BRAK` (beA), `DE.BEN_PROD` (beN), `DE.Justiz` (justice/SAFE public), `DE.BNotK_Produktiv`.
  - **Check digits:** SHA-256 over the *lowercased normalized* ID (everything before the final dot); append `.` + the **first two bytes of the hash in hex** (4 hex chars).
  - beA/beN IDs are minted in their own domains since 1 Jan 2016; justice-domain identities since 1 Aug 2017.
- **Legacy formats** (pre-2016/2017, still valid): `safe-sp1-1357225160794-021568182`, `govello-1235989964420-000174375`, `safe-prod-1498121242459-016499869`.
- Mapping rules are coordinated in the BLK-AG IT-Standards and published on justiz.de.

**Rust implication:** a `safe-id` parser/validator is a perfect first crate — enum over domain, UUID parsing, checksum verification, Display/FromStr, serde support.

### 3.4 The directory search standard (VAS, SPML, search/lookup)

Source: *„Standard für die Suche in den SAFE-Verzeichnissen der ERV-Kommunikationsinfrastruktur"*, **v1.5, 21 May 2026** (history: v1.0 24 Nov 2025 final → v1.5 May 2026), by BLK-AG IT-Standards, agreed with BRAK/BNotK/BStBK. Local copy: `docs/specs/Standard_SAFE_Verzeichnisdienst.pdf`. Key content:

- Scope: **only** the `search` and `lookup` interfaces; provisioning (identity creation) is governed by each directory operator separately.
- **Protocol:** SOAP with OASIS **SPML 2.0** (`urn:oasis:names:tc:SPML:2:0`, `…:search`, `…:suspend` etc.) and Liberty ID-SIS-PP person-profile namespaces (`urn:liberty:id-sis-pp:200505`), extended by SAFE/FIM namespaces `urn:de:egov:names:safe:1.0:*` (e.g. `…:search:orderby`, `…:spmlCapabilityData`, `…:id-sispp:extension`, `…:iterate:navigate`) and beA (`urn:de:egov:names:bea:1.0:id-sispp:extension`). The example lookup request is a `lookupRequest` with `executionMode="synchronous"` and a `psoID` element.
- **Attributes** (searchable / returned per attribute, DIN SPEC 91379 datatypes, max 255 chars unless noted) with their canonical XPaths:

  | Attribute | XPath (abbreviated) | Searchable | Notes |
  |---|---|---|---|
  | Vorname | `/CommonName/AnalyzedName/FN` | substring ≥2 chars | |
  | Name/Organisation | `/CommonName/AnalyzedName/SN` | substring ≥2 chars | |
  | Berufsbezeichnung | `/Extension/EJusticeAttributes/ProfessionProperty` | — | values per directory (Anlage b) |
  | Kanzlei | `/Extension/EJusticeAttributes/Kanzlei` | substring/exact/prefix ≥3 | only RAE & StB; BAG repeats `Name` |
  | Abteilung/Fachbereich | `/Extension/EJusticeAttributes/AlternativeOrganization` | substring ≥3 | not in BRAK/BNotK/BStBK dirs |
  | Straße / Hausnummer / PLZ / Ort / Bundesland / Land | `/AddressCard/Address/…` | mixed (B/C) | Bundesland not in BRAK/BStBK, not for MJP/eBO |
  | Mobil / Telefon | `MsgContact[MsgTechnology=…]/MsgAccount` | substring ≥5 (C) | not in BNotK/BStBK dirs |
  | **SAFE-ID** | `/safe.id` | exact match; lookup **and** search (since v1.1) | |
  | **Dienststellen-ID** | `/Extension/EJusticeAttributes/ExternalID` | exact | only SAFE public; cardinality 1..n |
  | **Postfach** (role values) | `/Extension/EJusticeAttributes/Roles/RoleValue` | exact | the "who may I address" filter |
  | **OSCI-Intermediärsadresse** | `MsgContact[MsgTechnology="urn:de:egov:names:safe:1.0:idsis-pp:msgTechnology:osci12Postbox"]/Extension/OsciMsgParameter/IntermedAddress` | no | URL to send to |
  | **Intermediär-Verschlüsselungszertifikat** | `…/OsciMsgParameter/IntermedEncryptKey` | no | cert to encrypt the outer envelope for |
  | **Empfänger-/Leser-Verschlüsselungszertifikat** | `…/RecipientEncryptKey` / `…/ReaderEncryptKey` | no (SAFE public: hash search on recipient cert possible) | the inner envelope keys |

- **Search semantics:** AND across parameters, case-insensitive; multi-word "contains" searches AND per word; three search kinds (begins-with / contains / equals) with per-attribute minimum lengths; **filters** map to role values and route the query to the right directories (OR within selected filters).
- **Result cap: 100 hits** per query (ERR40 otherwise); users must refine.
- **Error/hint codes:** ERR10 (illegal attribute), ERR11 (Kanzlei n/a), ERR12 (Abteilung/„zu Händen von" n/a), ERR13 (Bundesland n/a), ERR14 (Dienststellen-ID n/a), ERR20 (postbox inactive/role not activated), ERR30 (too few chars), ERR40 (>100 hits), ERR50 (illegal option/OR-search), ERR60 (search kind ignored), ERR70 (syntactically invalid query), ERR100 (one SAFE system unreachable → result may be incomplete).
- **`lookup` by Dienstellen-ID:** prefix trick — `<psoID ID="Dienststellen-ID:301125T" …/>` (301125T is an example court ID; Dienststellen-IDs are maintained as **Werteliste Typ 3** in the XJustiz standard and published in the **XRepository**). This is the standard way to turn "AG Bonn" into a postbox without knowing the SAFE-ID.
- **Silent exclusion:** directories must **not** return postbox holders whose encryption certificates have expired (no user-visible hint).
- All disclosed attributes must conform to **DIN SPEC 91379** (the "eGovernment" character set — relevant for a Rust implementation: normalization/validation rules exist).

**Rust implication:** the SPML/Liberty request/response model maps cleanly to typed structs + a SOAP layer. But note the *authentication and endpoint* are **not** in the public standard — they are handed to registered ERV-SES (send/receive software) vendors. The example shows `wsu:Id`-addressed SOAP bodies (XML-DSig style), so client certificates + WS-Security-ish signing are to be expected.

### 3.5 Roles and the visibility matrix

From the third-party requirements paper (§ 5.3, v1.8) — general role values:

`egvp_justiz`, `egvp_bea`, `egvp_ben`, `egvp_best`, `egvp_bebpo`, `egvp_ebo`, `ozg_postfach` (MJP/OZG account), `egvp_buerger` (non-secure-path participants), `egvp_behoerde` (legacy), `buerger_hin` / `buerger_rueck` (Gerichtsvollzieher: can address citizen postboxes with/without receiving replies), `zuzu` (eBO organizations consenting to general service of documents per § 173 Abs. 4 S. 3 ZPOZustZustG), `egvp_test` (test postboxes visible **only among themselves**).

Communication rules (ERV-Leitfaden 4.2): beA/beN/beSt/beBPo can address everyone incl. each other, eBO and MJP; **eBO ↔ eBO** only via paid third-party intermediary services ("**eBO-plus**") — exception: Gerichtsvollzieher, Patentanwälte and representable organizations may address eBOs for service; **MJP ↔ MJP and MJP ↔ eBO impossible**.

### 3.6 Who feeds the directories?

- Justiz/SAFE public: the **beBPo-Prüfstellen** (§ 6 Abs. 1 Nr. 3, § 7 ERVV), the Länder for their courts/prosecutions, automated eBO registration (role `egvp_ebo` granted automatically during the eID-based registration process), the MJP/OZG onboarding.
- BRAK/BNotK/BStBK: the chambers' member onboarding (data basis e.g. the amtliches Anwaltsverzeichnis).
- Identity admins manage but do not create users (BNotK guide § 2.1). "Opting out" of registration must not be offered by third-party products (requirement A6).

---

## 4. Obtaining a postbox (per role)

| Role | How to get the postbox | Identification / artifacts | Cost |
|---|---|---|---|
| **Lawyer (beA)** | Automatically provisioned by BRAK per § 31a BRAO; activation via chamber; access via beA-Webanwendung (bea.brak.de) or the beA-Client Security program (Win/macOS/Linux) | First login requires a chip card (beA-Karte); daily login via card or software certificate + PIN. beA-Karte Basis 29.90 €/yr, Signatur 49.90 €/yr, Mitarbeiterkarte 12.90 €/yr, software cert 4.90 €/yr (net, Wikipedia/beA) | postbox free; cards/certs paid |
| **Notary (beN)** | Via BNotK (beN since 2018); SAFE domain BEN_PROD | BNotK PKI | included for members |
| **Tax advisor (beSt)** | Via BStBK Steuerberaterplattform; use through Fachsoftware via the **beSt-API** or the free basis client "COM Vibilia StB Edition" (Governikus-based) | BStBK infrastructure | basis client free |
| **Authority (beBPo)** | Apply at the Land's **beBPo-Prüfstelle** (§ 7 ERVV); Prüfstelle identifies the applicant and enters the postbox into SAFE | Requires a **Postfach-Zertifikat** (encryption; sometimes self-generated) and a **VHN-Zertifikat** (downloaded from zertifikate.safe-justiz.de; the VHN PKI is operated by the **BNotK**); determine authorized natural persons (§ 8 ERVV) | free |
| **Citizen/organization (eBO)** | Buy/use one of the paid eBO-capable products (Governikus COM Vibilia eBO Edition, Procilon proDESK/eBO, FP Justiz Connect, eBOnaut, Juppi eBO Edition, eBO.connect) and register in the SAFE registration client | eID (Online-Ausweisfunktion des Personalausweises); role `egvp_ebo` assigned automatically; orgs may add `zuzu` | product cost |
| **Citizen (MJP)** | Register at `https://mjp.justiz.de` (also mjpserviceportal.de / mein-justizpostfach.bund.de) — free web app, pilot since 12 Oct 2023 | **BundID with trust level "hoch"** (requires eID/NFC Personalausweis); not an eBO; § 13 ERVV | free |
| **Court/prosecution (EGVP)** | Set up by the Land's justice IT; every court/StA has its EGVP postbox (plus special postboxes e.g. Grundbuch) | Land-operated | — |
| **Software vendor** | Register a **Drittprodukt** with the BLK-AG IT-Standards (see § 8.3) or apply for the free **EGVP-Enterprise** server component | Registration ID (appears in VHN `Technisch/HerstellerInformation/Registrierungs_ID`) | free (EGVP-Enterprise) |

---

## 5. Sending and receiving messages (OSCI / EGVP transport profile)

### 5.1 OSCI-Transport basics

- OSCI (Online Services Computer Interface) was developed by **bremen online services (bos)** in the Media@Komm era; the OSCI-Leitstelle became **KoSIT** on 1 Apr 2011 (KoSIT sits in the Bremen state administration; see <https://www.osci.de/>). The current KoSIT website only presents the XÖV standards family, but the **OSCI-Transport 1.2 specification is freely downloadable** (no registration, no cost) from the **OSCI/XÖV-Bezugsstelle at ITZBund**: <https://www.itzbund.de/DE/itloesungen/standardloesungen/xoev/oscixoevbezugsstelle/oscixoevbezugsstelle.html>. Available there: base spec (Fassung 2002-06-06, 75 pp.), Korrigenda 1–7 (2020-12-15), 8 (2024-01-12), 9 (2025-05-26), **10 (2026-02-13 — i.e. actively maintained)**, and the supplement "Effiziente Übertragung großer Datenmengen" (2017-10-25). Alternatives: paid CD-ROM order, and deposit at the Bundesarchiv Koblenz. Local copies in `docs/specs/`.
- **Spec licensing (verbatim from the base spec, p. 2):** the specification is copyright-protected, all usage rights rest with the Herausgeber (OSCI-Leitstelle/KoSIT), *but* — "Herstellern wird zur Implementation von Bürger-, Kommunal-, Intermediär- oder Dienstleistersystemen **unentgeltlich ein einfaches Nutzungsrecht eingeräumt**" — implementers of such systems are granted a **free, simple (non-exclusive) usage right**. Distribution in unmodified form is permitted within that purpose; modifications/translations require consultation with the Herausgeber. An independent Rust implementation is therefore squarely within the granted licence. (Note: only OSCI-Transport **1.2** is on the ITZBund list; the newer OSCI-Transport 2.0 is not offered there — its availability would have to be clarified separately, but EGVP uses 1.2 anyway.)
- EGVP uses **OSCI-Transport 1.2** (requirement: "Der Versand und Empfang von Nachrichten muss gemäß dem Transportprotokollstandard OSCI-1.2 erfolgen" — Drittprodukte requirements § 3.1).
- **Store-and-forward via intermediaries (OSCI-Manager/Intermediär):** each postbox holder is reachable at the URL of *their* intermediary; the sender uploads to the recipient's intermediary, the recipient polls. Intermediaries create the **MessageID**, verify required elements, log everything on **Laufzettel** (process sheets), check certificates, and store messages in the recipient's OSCI account.
- **Double envelope ("Prinzip des Doppelten Umschlags"):** usage data encrypted *for the intermediary*, content encrypted *for the reader* only; each container can be signed/encrypted independently. Hybrid encryption: random symmetric key, wrapped with the recipient's public key (Wikipedia EGVP).
- **OSCI roles:** Autor (author), Sender, OSCI-Manager, Empfänger (receiver), Leser (reader). In EGVP, Leser≡Empfänger and Autor≡Sender are typically merged (requirements A11). The separation explains the three certificates in SAFE (intermediary, recipient, reader encryption keys).
- **Security history:** CVE-2017-10668/10669/10670 in the OSCI 1.2 transport library (BSI CB-K17/1100).
- XML/SOAP/W3C XML-Signature & Encryption; eIDAS-conforming signature integration; quittungs mechanisms with timestamps.

### 5.2 The EGVP message structure (transport profile)

Since 1 June 2022 the EGVP transport profile mandates **two ContentContainers** inside `ContentDataOSCI`:

```
ContentDataOSCI
├── ContentContainer "project_coco"      ← encrypted FOR THE RECIPIENT
│   ├── Attachment (n×)  <Dokumentdateien>
│   └── Attachment       xjustiz_nachricht.xml
└── ContentContainer "vhn_coco"          ← NOT encrypted for the recipient
    ├── Attachment       vhn.xml
    └── Attachment       vhn.xml.p7s
```

- The whole message must additionally be encrypted for the **recipient's intermediary** (outer envelope).
- **No message text** may be placed inside the containers (A17). No qualified signature on the message itself — container signatures are prohibited per § 4 Abs. 2 ERVV (A15). Qualified signatures apply to *documents* (CAdES/PAdES, see § 6).
- **One message = one proceeding of one court/StA** (A13; ERV-Leitfaden ch. 5). No sending to multiple courts with a single user action.
- Before every send, the product must re-check that the sender's postbox is still registered in a SAFE directory (A14) — i.e., resolver + sender live together in real products.
- Polling: accesses should not disturb operations; ≥ 15-minute intervals recommended (A2).

### 5.3 Receipts and proofs

- **Eingangsbestätigung** (mandatory, A22): `MessageId` + intermediary intake timestamp (`Creation`) taken from the OSCI-Laufzettel, signed by the OSCI-Manager. Legally, intake at the intermediary = filing (§ 130a Abs. 5 ZPO).
- **Abholbestätigung** (recommended, A23): adds the fetch timestamp (`reception`).
- **Prüfvermerk / Prüfprotokoll** (A24): the receiver-side verification report (who/what/when/how/to whom; VHN check results, qeS checks per attachment, hash values, transfer note); provided as structured "Sendungsdaten" XML *and* PDF. Both are the evidence for the file.
- **Eilige Nachrichten:** XJustiz Nachrichtenkopf `Sendungspriorität` (value `001` "Eilt"; special values for Bereitschaftsdienste).

### 5.4 The VHN (Vertrauenswürdiger Herkunftsnachweis)

Spec: *„Vertrauenswürdiger Herkunftsnachweis (VHN) 2 — Spezifikation, Version 2.2, 09.12.2021"* (local copy `docs/specs/VHN_2_2_Spezifikation.zip` incl. `vhn.xsd` + example `vhn.xml`).

- Purpose: machine-verifiable proof that a message originated from an *identified* postbox over a secure path; also anti-DoS (messages without VHN 2 can be auto-rejected).
- `vhn.xml` = **Fachlich** (Absender-Visitenkarte: `Nutzer_ID` (the SAFE-ID!), title/name/address/org/Berufstraegereigenschaft/`Externe_ID`; `EGVP_Rollenwerte` (1..n); `Sicherer_Uebermittlungsweg` ja/nein — "ja" only if identification+authentication met the legal bar; `Dokument` list with base64 **hash values**, algorithm SHA256/384/512) + **Technisch** (`HerstellerInformation`: product+version, vendor, `Registrierungs_ID`).
- `vhn.xml.p7s` = **advanced electronic signature (CMS/PKCS#7)** over the vhn.xml, created with a VHN certificate from an approved CA.
- **VHN PKI is operated by the BNotK** ("SAFE Root CA 2017", RSA-4096/SHA-512-RSAPSS), with sub-CAs per postbox type: beBPo, beA, beN, Justiz, eBO (2021), OZG-Nutzerkonto (2021), EGVP (2021), beSt (2021), De-Mail (2017, internal), and **"Test VHN CA 2021"**. Participant certs: RSA-2048, SHA-512 RSAPSS, `serialNumber` = SAFE-ID. Root certs: <https://onlinehilfe.bnotk.de/display/syshilfe/Root-Zertifikate+der+Bundesnotarkammer>
- Migration: VHN 1 (legacy "Visitenkarte" attachment) and VHN 2 ran in parallel; every message must carry VHN 2 once migration completes (A19/A20).

### 5.5 Certificate lifecycle: renewal, changeover, revocation

Certificates are **directory data, not protocol state**. OSCI-Transport itself has no user management and no in-protocol certificate announcement ("OSCI-Transport verfügt über keine eigene Benutzerverwaltung … die einzige Voraussetzung … ist der Besitz eines Chiffrierzertifikats", spec § 3.1; X.509v3 per ISIS-MTT Part 1 profile, § 4.4). Distribution and changeover run through the SAFE directory:

1. **Obtain a new certificate before expiry.** Software/VHN certificates are self-service at `zertifikate.safe-justiz.de`: the keypair is generated **locally in the browser** (the CA never sees the private key), delivered as PKCS#12; login with Nutzer-ID (= SAFE-ID) + password obtained via the SAFE registration client (Leitfaden "Web-Anwendung für den Download von Zertifikaten", v1.2, Dec 2021). beBPo Postfach-Zertifikate (encryption) may be self-generated by the client; beA cards/software certificates are annual subscriptions, i.e. rotation is routine.
2. **Publish with overlap.** SAFE identity administrators add the new certificate to the user's directory entry — the identity-admin UI supports **up to ten concurrent certificates** (CER/PEM/CRT/DER) with issuer and validity displayed, plus deletion of old ones (BNotK guide § 4.3.5). Overlapping validity of old and new certificate is thus explicitly supported; keeping the old private key during the window is what keeps not-yet-fetched intermediary messages decryptable (practical consequence — messages on the intermediary are encrypted to the cert that was current at send time, and OSCI has no re-encryption).
   - **How the new cert reaches the directory:** often *without* any admin notification — VHN/software certificates are participant self-service at `zertifikate.safe-justiz.de` (browser-side keygen, PKCS#12 download; the beBPo-Prüfstelle's one-time authentication of the postbox "wirkt ... für die Beantragung ... fort", cert free of charge — "Information VHN für beBPos"; eBO certs likewise via postbox credentials; beA/beN/beSt via their chambers' platforms, which also feed the directory). For the OSCI postbox certificates in the Justiz/beBPo domain the identity administrator is in the loop, and the participant's "notification" is **out-of-band** (form/e-mail/phone to the Land's SAFE-Nutzerverwaltung/beBPo-Prüfstelle; e.g. Lower Saxony publishes a "SAFE-Nutzerregistrierung" application covering new registration, data change and deletion). In-system artifacts are only the pending states (admin UI: "Unbestätigte Rollen", status *beantragt/freigeschaltet/abgelehnt*) and the SAFE registration client's self-service request functions ("Zugang für EGVP-Nutzer anfordern", "Neues Kennwort anfordern", certificate upload at registration). Admins additionally coordinate via the BLK BSCW workspace ("Rollen in Safe" mandatory-field lists — Brandenburg guide § 4.3.2).
   - **The specified switchover state — role value `zertifikatswechsel`:** during the changeover the identity administrator assigns *exclusively* the role value `zertifikatswechsel` (all other roles must be **deleted**; merely setting them to *beantragt/abgelehnt* is insufficient). The owner can still open the postbox in the EGVP client, but the postbox **cannot be addressed** — "Auf diese Weise wird sichergestellt, dass während des Zeitraums des Zertifikatswechsels keine Nachrichten an das Postfach gesendet werden, da diese verloren gehen würden" (Brandenburg guide § 4.3.1.2; identical text in the BNotK guide § 4.3.1). After the new certificate is registered, the regular role values are restored. Note: `zertifikatswechsel` does not appear in the role list of the 2022 Drittprodukte requirements paper — it is administrative practice documented in the SAFE ident-admin guides.
3. **Senders pick it up per send.** Requirement A14: immediately before every send the product must re-check SAFE registration — in practice re-resolving the recipient and encrypting to the certificates *currently* returned (Empfänger-/Leser-Verschlüsselungszertifikat). Senders must run the offline checks (validity window, locally known revocation) on recipient/reader certs before encrypting and must not use a failing cert (OSCI § 4.4). Cert caches must therefore never outlive a send cycle.
4. **Expiry hard-deadline.** SAFE directories must **not** return postbox holders with expired encryption certificates in `search` *or* `lookup`, without any hint to the searcher (search standard A9) — a lapsed certificate silently makes the postbox unaddressable/invisible.
5. **Protocol safeguards (OSCI 1.2).** Within an explicit dialog the intermediary encrypts every response to the exact Chiffrierzertifikat presented at dialog initialization; challenge/response + ConversationId + SequenceNumber bind the dialog, so a client **cannot switch certificates mid-dialog** (§ 4.5/4.6). The intermediary must mathematically verify, offline-validate (validity window) and **online revocation-check** every job-level certificate and chain, recording results in the Prüfprotokoll incl. the CRL date (`CRL` element). Dedicated return codes distinguish *expired* ("zeitlich ungültig", 37xx-series) from *revoked* ("widerrufen", 97xx-series, plus 92xx on message level) certificates per role (client, author, recipient, reader); jobs referencing revoked reader/intermediary-actor certs are rejected, and a client whose own cert is revoked receives an unencrypted rejection notice.
6. **Algorithm evolution** is handled by spec corrigenda, not negotiation: KOR10 (2026-02-13) adds SHA3-256/384/512 to signatures/digests — endpoints roll onto new algorithms as certificates and implementations are renewed.

---

## 6. Attachments and document formats (ERVB 2025)

Hard limits and formats from **ERVB 2025** (local copy `docs/specs/ervb2025.pdf`):

- **Max 1,000 files and max 200 MB (sum of attachment sizes) per message.** (Historic note: earlier bulletins were stricter; Behördenakten per BehAktÜbV: *soll* 200 MB / 1,000 files, but oversized transfers still count as validly filed if technically possible.)
- **Formats:** PDF (incl. PDF 2.0, PDF/A-1, PDF/A-2, PDF/UA; no embedded objects, no JavaScript; inline signatures and Transfervermerke allowed; hyperlinks allowed) and **TIFF 6**. Documents must be printable.
- **File names:** ≤ 90 chars incl. extension; only German-alphabet letters (incl. ä ö ü ß), digits, `_`, `-`; points only as name/extension separator (exception: concatenated extensions like `dokument1.pdf.pkcs7`); logical numbering when sending many files; **no duplicate names within one message**; recommendation `Dokumentname_UUID.ext` (UUID per ISO/IEC 9834-8); a detached signature file must share the base name (`Klage_UUID.pdf` + `Klage_UUID.pdf.pkcs7`).
- **Qualified signatures (where used):** CAdES detached (ETSI EN 319 122-1 / TS 103 173) or PAdES inline (ETSI EN 319 142-1 / TS 103 172), or formats per Commission Implementing Decision (EU) 2015/1506.
- **XJustiz attachment:** every message carries exactly one `xjustiz_nachricht.xml`; the generic "Schriftgut" message `nachricht.gds.uebermittlungSchriftgutobjekte.0005005` must be used when further attachments exist; `nachricht.gds.basisnachricht.0005006` only without attachments; forwarded/older XJustiz payloads get a UUID in the name (`xjustiz_nachricht_<UUID>.xml`). Older XJustiz versions must not be rejected at receipt; version validation on receipt is discouraged.
- If limits are exceeded: **Ersatzeinreichung** on physical media (DVD, CD, USB exFAT/NTFS ≥ USB 2.0).
- Verschlusssachen (classified): EGVP cannot be used for them (ERV-Leitfaden 4.7).

---

## 7. XJustiz (the payload standard)

- Maintained by the **BLK-AG IT-Standards**, portal <https://xjustiz.justiz.de/> (also www.xjustiz.de); binding via ERVB/eAeDB bulletins.
- **Versions (Oct 2026):** valid **3.6.2** (30 Apr 2026 – 30 Apr 2027, with Nachlieferungen e.g. ZVSTR, DABAG); **4.0.0** published 12 May 2026 (formerly RC 3.7.0), **valid from 30 Apr 2027**; annual cycle: RC on 31 Jan, publication by 30 Apr, validity switch on 30 Apr next year (≥12 months lead). 4.0.0 switches XSD versioning to a pattern-based hybrid model (`4\.(0|[1-9]\d*)\.(0|[1-9]\d*)` for `xjustizVersion`).
- **Structure:** Grunddatensatz (Nachrichtenkopf: Absender/Empfänger/Aktenzeichen absender+empfänger, Code.GDS.Gericht; Verfahrensdaten: Instanzdaten w/ Behörde, Aktenzeichen, Sachgebiet, Verfahrensgegenstand, Beteiligte; Schriftgutobjekte: Dokument/Akte types with `nummerImUebergeordnetenContainer` ordering) + 27 Fachmodule / 144 Nachrichtentypen / 43 Codelisten (six Verfahrensbereiche: Zivil&Familie 9, Register 6, Vollstreckung 5, Verwaltung 4, Übergreifend 2, Strafsachen 1).
- **Codelisten** XÖV-conform: Typ 1 (inside XSD), **Typ 3 (dynamic, in XRepository — incl. the court Dienststellen-IDs used for SAFE lookup)**, Typ 4 (bilateral placeholders). XRepository subscription for change notifications.
- **Specialty messages:** elektronisches Empfangsbekenntnis (eEB), eNoVA (separate Anwendungsfall + editor), Schutzschriftenregister, Mahnverfahren, Bußgeld, Registersachen (XJustiz used heavily in Fachverfahren integration).
- **Free downloads** (no registration): specification PDFs, XSD zips, Schematron zips at <https://xjustiz.justiz.de/downloads/index.php> (e.g. `Spezifikation_XJustiz_3_6_2.pdf`, `XJustiz-4_0_0-XSD.zip`, `XJustiz-4_0_0-Schematron.zip`, `XJustiz_3_6_2_SCH.zip`).
- **XJustiz-Werkzeuge** (<https://xjustiz.justiz.de/XJustiz-Werkzeuge/index.php>): official Java toolkit — versions migration (incl. xdomea→XJustiz), PDF visualization, message generator (JSON→XML), validator (XSD + Schematron). Integratable **as Java library or via REST backend** ("Zugriff anfordern" — access on request). Browser tools: eEB generator, "Strukturdaten".
- ERV profiling annex: `uebermittlung_Schriftgutobjekte_und_eEB_XJustiz.xlsx` (justiz.de).

---

## 8. Existing projects, providers, and test infrastructure

### 8.1 Open source (verified on GitHub, Oct 2026)

| Project | Language | What it does | Status |
|---|---|---|---|
| `it-at-m/xjustiz` | Java | XJustiz library by the City of Munich IT dept (it@M) | pushed 2026-06 |
| `it-at-m/eNoVa-Editor` | Java | opens/edits `XJustiz.enova.2900003` files submitted via beBPo | active 2026-10 |
| `digitalservicebund/a2j-xjustiz-bridge` | TypeScript | "Assisted composition of XJustiz messages that are ensured to be valid" (DigitalService Bund) | active 2026-10 |
| `digidigital/openXJV` | Python | viewer for XJustiz/XJV transfer files | pushed 2026-06 |
| `digidigital/XJustiz2PDF` | Python | renders xJustiz messages + electronic court files (eAkte) to PDF | pushed 2026-09 |
| `digidigital/XJV-Viewer-for-XJustiz` | HTML | browser viewer | 2022 |
| `westernacher-solutions/xjustiz-schema` | XSD | schema mirror (2017) | stale |
| `budiq-app/xjustiz` | Java | Handelsregister XML lib | 2023 |
| `psysm/mjp-batch-export` | JavaScript | bulk export of MJP messages incl. metadata | 2025-12 |
| `toweosp/paperlessngx-mjp-parser` | Python | parse MJP ZIPs for Paperless-ngx | 2026-08 |

**OSCI implementations (correction of an earlier finding):** the OSCI-Transport-1.2 **reference library by Governikus is publicly available and open source** — Maven Central group `de.osci` (artifacts `osci-bibliothek`, `osci-bibliothek-bom/-lib/-sample`, `osci-client-bibliothek`, `osci-schema`, `extension-message-meta-data`, …), latest **2.6.1** (2026-08-20), dual-licensed **EUPL-1.2/MIT**, canonical repo [gitlab.opencode.de/governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java). (An earlier Maven *search API* query failed silently and led to a wrong "not published" conclusion — direct repo1.maven.org verification shows it.) On top of it: **`hauksch/rosci`** (MIT, Rust) — a Rust CLI (`rosci`) + REST daemon (`roscid`) wrapping the Java library via a stdio-JSON sidecar bridge, with recipient resolution by direct certificate (`--to cert:…`) or local DVDV extract (`--to dvdv:<org-key>`), an XTA-passthrough send path, fetch/status, a mock intermediary for offline tests, and an opt-in live interop suite against `gov.test.osci.de`. Not published on crates.io.

**Notably absent:** any *Rust-native* OSCI implementation; bos has no public GitHub org with protocol code; Governikus's COM Vibilia (the EGVP client product) is not open source. **crates.io:** zero relevant Rust crates (`osci`, `xjustiz`, `egvp`, `bea`, `justiz`, `erva` all return unrelated results). Generic building blocks that *do* exist: `xsd-parser` (Rust XSD→Rust codegen), plus the usual XML/crypto crates.

### 8.2 Commercial / institutional products (registered Drittprodukte)

From <https://egvp.justiz.de/Drittprodukte/index.php/index.php>:

| Product | Vendor | Notes |
|---|---|---|
| FP Justiz Connect (ehem. Mentana-Gateway) | FP Digital Business Solutions GmbH | beBPo/eBO gateway (same company that ran the last De-Mail) |
| ProDESK Framework 3.0 | procilon GmbH (protectr.com) | incl. eBO ("Procilon eBO") |
| Governikus COM Vibilia (+ eBO/beSt Editions), Multimessenger | Governikus GmbH & Co. KG | the historic EGVP client lineage (EGVP software was based on Governikus Communicator); also builds MJP |
| eBOnaut | Copper & Grey Solutions GmbH | eBO product |
| Juppi eBO Edition | UN Connect Group OU | eBO product |
| eBO.connect | LOGO Datensysteme GmbH | eBO product |
| beA-Webanwendung | BRAK | browser access to beA |
| beSt-API | BStBK | **documented interface for Fachsoftware** to integrate beSt |
| Mein Justizpostfach | Governikus for BMI | free citizen postbox (§ 13 ERVV) |
| **EGVP-Enterprise** | justice community | **free server component for integrating Fachsoftware** with the EGVP infrastructure (not suitable for eBO; not a desktop app); application form on the Drittprodukte page |

### 8.3 Becoming a participant (the official route for a software product)

1. Read *„Teilnahme von Drittanwendungen am OSCI-gestützten elektronischen Rechtsverkehr — Anforderungen, v1.8 (20.04.2022)"* (local copy `docs/specs/EGVP_Infrastruktur_Anforderungen_Teilnahme_von_Drittanwendungen.pdf`) — 25 requirements (A1–A25) incl. OSCI 1.2, message structure, VHN, XJustiz attachment, receipts, SAFE checks.
2. Submit the **Antragsformular** (registration procedure) to the **Projektbüro der BLK-AG IT-Standards** — `it-standards@justiz.de` (also the XJustiz contact).
3. Alternatively apply for **EGVP-Enterprise** (separate form) and integrate it as the transport component.
4. The registration yields the `Registrierungs_ID` that your product must embed in every VHN 2 (`Technisch/HerstellerInformation`).

### 8.4 Test & integration infrastructure

| What | Where / how |
|---|---|
| SAFE test system | `https://safetest.safe-justiz.de/safe-registration-client/` (+ `/safe-identity-admin/`) |
| Test postboxes in production | role **`egvp_test`** — visible only among themselves, so legally relevant Zustellungen can't happen (requirements § 5.3); the paper explicitly contemplates "Tests im Echtsystem" |
| VHN test certificates | **Test VHN CA 2021** (BNotK PKI); software certificates via `zertifikate.safe-justiz.de` |
| XJustiz offline testing | free XSD/Schematron/spec downloads; Release Candidates published 12 months ahead; **XJustiz-Werkzeuge** validator/generator (REST/Java) |
| OSCI-Transport 1.2 spec | **free download** (ITZBund OSCI/XÖV-Bezugsstelle, incl. Korrigenda up to 2026) — the full protocol is implementable from public documents |
| EGVP/Drittprodukt testing | through the registration procedure / EGVP-Enterprise; the project office coordinates test postboxes & intermediary access (no self-service) |
| **Public OSCI 1.2 test intermediary** | `gov.test.osci.de` — registration-free Governikus OSCI-Manager instance (production intermediary software), documented in the osci-bib-java README and linked from xoev.de's intermediaries page; functional tests only (no load tests), no availability guarantee, max 500 MB/message, plain HTTP *by design* (security lives in the OSCI message envelope); **not** an EGVP/justice intermediary — it tests general OSCI 1.2, not the EGVP transport profile |
| MJP | no test instance (production pilot; JS app) |
| De-Mail | dead — do not target |

**Gap to be aware of:** there is no publicly reachable OSCI test intermediary or VAS sandbox; all realistic integration testing runs through the BLK-AG project office and the `egvp_test` mechanism.

---

## 9. Implications for a Rust library ("safedir")

Recommended layering, bottom-up:

1. **`safe-id` crate (pure, no I/O):** `SafeId` enum (legacy vs. modern format), domain enum (`BRAK`, `BEN_PROD`, `BNotK_Produktiv`, `Justiz`, `Other(String)`), UUID handling, **SHA-256 check-digit verification** (first two bytes of SHA-256 over lowercased ID prefix, hex), `FromStr`/`Display`/serde. Fully specified by the Abbildungsvorschrift; unit-testable offline.
2. **`xjustiz` crate:** schema-derived types (generate from the official XSDs with `xsd-parser` or hand-write the Grunddatensatz subset: Nachrichtenkopf, Verfahrensdaten, Schriftgutobjekte), Schematron validation hook, `uebermittlungSchriftgutobjekte` builder, Dienststellen-ID **Werteliste Typ 3** (XRepository) as a bundled data table + refresh mechanism, DIN SPEC 91379 string normalization/validation. Test vectors: the spec's example instances + XJustiz-Werkzeuge as reference oracle.
3. **`vhn` crate:** parse/validate `vhn.xml` (XSD in `docs/specs/VHN_2_2_Spezifikation.zip`), verify the CMS `p7s` (advanced signature) against the BNotK VHN CA hierarchy (root certificates from the BNotK online help), map `Sicherer_Uebermittlungsweg`, hash-check the Dokument list.
4. **`safe-search` (SPML/VAS client):** typed model of the attribute table + role values + error codes from the v1.5 standard; SOAP/SPML 2.0 request construction; `search(criteria) -> Vec<SafeEntry>`, `lookup(SafeId | DienstellenId) -> SafeEntry`; feature-gated live transport. **Blocked on:** endpoint + credentials, obtainable only via Drittprodukt registration or EGVP-Enterprise embedding — plan an in-memory/mock directory for development (the standard's exact message shapes are in the spec's example).
5. **`erv-message` (container layer):** build/parse the `project_coco`/`vhn_coco` structure, filename rules (90 chars, charset, signature pairing), the 1,000-file/200 MB checks, XJustiz attachment invariant. This is implementable and testable without ever touching OSCI.
6. **OSCI-Transport client (the big lift, optional/later):** SOAP + XML-DSig/Enc, intermediary handshakes, Laufzettel parsing for Eingangs-/Abholbestätigung. **The specification is public and free** (ITZBund Bezugsstelle, local copies in `docs/specs/`, implementers explicitly granted a free simple usage right), and actively maintained (Korrigendum 10, Feb 2026). What does *not* exist publicly: a reference implementation to diff against, WSDLs of a test intermediary, and VAS endpoint access — so interop testing still realistically requires the Projektbüro/registration path or wrapping EGVP-Enterprise.

**Practical recommendation:** talk to the Projektbüro der BLK-AG IT-Standards (`it-standards@justiz.de`) early — both for VAS access and to clarify licensing of the OSCI-Transport specification for an independent (Rust) implementation. XJustiz and SAFE-ID work can start immediately with zero dependencies.

### 9.1 Consumer integration: rosci (`github.com/hauksch/rosci`)

rosci is an MIT-licensed Rust CLI/REST wrapper around the open-source Governikus OSCI-1.2 Java library (see § 8.1), with recipient resolution currently via direct certificate (`--to cert:<file>` + `--intermediary` + `--intermediary-cert`) or a **local DVDV JSON extract** (`--to dvdv:<org-key>`; the `DvdvDirectory` trait is explicitly the seam for online clients). safedir as its resolution provider is architecturally sound because it mirrors the real-world split — **DVDV is the directory of the general OSCI world, SAFE/VAS is the directory of the justice ERV world**; the OSCI transport layer is deliberately directory-agnostic. The data contract maps 1:1:

| SAFE attribute (XPath, § 3.4) | rosci input |
|---|---|
| `OsciMsgParameter/IntermedAddress` | `--intermediary <url>` |
| `OsciMsgParameter/IntermedEncryptKey` | `--intermediary-cert <file>` |
| `OsciMsgParameter/RecipientEncryptKey` / `ReaderEncryptKey` | `--to cert:…` / `--decrypter-cert` |

Recommended shape: safedir exposes `resolve(SafeId | DienststellenId) -> ResolvedRecipient{intermediary_url, intermediary_cipher_cert, recipient_cipher_cert, reader_cipher_cert, display, roles, state}` plus (a) a **live SPML/VAS client** for registered participants and (b) an **offline extract format** philosophically identical to rosci's `dvdv.json` (a `safe.json` produced by a registered party) — giving rosci a `--to safe:<SAFE-ID>` scheme with zero gated dependencies on day one. safedir additionally owns what a raw directory lacks: addressability rules (visibility matrix, eBO-plus, `zertifikatswechsel`/inactive states, silent expiry exclusion), A14 freshness semantics (re-resolve per send), and multi-certificate sets.

**Open items on the rosci side for actual justice delivery:** plain OSCI 1.2 ≠ EGVP transport profile — messages into justice postboxes need the `project_coco`/`vhn_coco` containers, a VHN 2 signed with a BNotK-CA certificate (only issued to identified postboxes), the mandatory `xjustiz_nachricht.xml`, filename rules and one-recipient-court-per-message. Natural split: safedir's `erv-message` layer assembles the profiled container, rosci stays payload-opaque. And `gov.test.osci.de` proves general OSCI 1.2 interop only — justice interop still runs through `egvp_test` + Projektbüro.

---

## 10. Open questions / risks

- VAS **endpoint URL and authentication mechanism** are not published; the standard only defines message semantics. (Unverified expectation from the SOAP example: TLS client certificates + XML signatures.)
- Whether the **BStBK directory** is fully live in the federation in all respects (the ERV-Leitfaden v1.6 still says "künftig der Steuerberaterkammer" in one footnote while the 2026 search standard counts four directories) — treat as "live per the 2026 standard".
- **MJP production status** (started as pilot 12 Oct 2023; several portal domains exist: mjp.justiz.de, mjpserviceportal.de, mein-justizpostfach.bund.de) — verify current phase before relying on it.
- ~~OSCI-Transport spec availability/licensing~~ **resolved (2026-10-10):** OSCI-Transport 1.2 is freely downloadable from the ITZBund Bezugsstelle and implementers get an explicit free simple usage right (see § 5.1). Open remainder: **OSCI-Transport 2.0** is not on the ITZBund download list; availability for that version is unverified (not needed for EGVP).
- The pre-2022 "old transport profile" and VHN 1 coexistence: new implementations should target the 2022 profile only, but must parse legacy receipts on receipt paths.
- XJustiz 4.0.0 breaking changes (hybrid versioning, `xjustizVersion` value change) land 30 Apr 2027 — design the crate versioned from day one.

---

## 11. Source index

**Primary specifications (local copies in `docs/specs/`):**
- OSCI-Transport 1.2 Spezifikation (Fassung 2002-06-06), Korrigendum 10 (2026-02-13), Ergänzung "Effiziente Übertragung großer Datenmengen" (2017-10-25) — free download: <https://www.itzbund.de/DE/itloesungen/standardloesungen/xoev/oscixoevbezugsstelle/oscixoevbezugsstelle.html>
- Standard für die Suche in den SAFE-Verzeichnissen der ERV-Kommunikationsinfrastruktur, v1.5 (21.05.2026) — <https://egvp.justiz.de/Drittprodukte/Standard_SAFE_Verzeichnisdienst.pdf>
- SAFE-ID Abbildungsvorschrift V2 (Juli 2017) — <https://egvp.justiz.de/Drittprodukte/SAFE_Abbildungsvorschrift_SAFE_ID_V2.pdf>
- Vertrauenswürdiger Herkunftsnachweis (VHN) 2, Spezifikation v2.2 (09.12.2021) — <https://egvp.justiz.de/Drittprodukte/VHN_2_2_Spezifikation.zip>
- Teilnahme von Drittanwendungen am OSCI-gestützten elektronischen Rechtsverkehr — Anforderungen v1.8 (20.04.2022) — <https://egvp.justiz.de/Drittprodukte/EGVP_Infrastruktur_Anforderungen_Teilnahme_von_Drittanwendungen.pdf>
- ERVB 2025 (16.07.2025, BAnz AT 29.07.2025 B2) — <https://justiz.de/laender-bund-europa/elektronische_kommunikation/bundesanzeiger_29_07_2025.pdf>
- Leitfaden Elektronischer Rechtsverkehr mit der Justiz, v1.6 (28.07.2025) — <https://justiz.de/ervvoe/leitfaden_erv_pdf.pdf>
- SAFE Identitätsadministration Leitfaden v1.4 (10.10.2024, BNotK) — <https://cdn.bnotk.de/safe/SAFE_Leitfaden_Anwendung_fuer_Identitaetsadministration.pdf>

**Portals & law texts:**
- <https://egvp.justiz.de/> (incl. /Drittprodukte, /behoerdenpostfach, /buerger_organisationen, /Ansprechpartner)
- <https://xjustiz.justiz.de/> (downloads, Werkzeuge, Versionen)
- <https://www.gesetze-im-internet.de/ervv/> · <https://www.gesetze-im-internet.de/zpo/__130a.html>
- <https://safe.safe-justiz.de/safe-registration-client/> · <https://zertifikate.safe-justiz.de/UserCertificateManagementUI/> · <https://safetest.safe-justiz.de/safe-registration-client/>
- <https://mjp.justiz.de/> · <https://steuerberaterplattform-bstbk.de/best> · <https://www.osci.de/> (KoSIT) · <https://onlinehilfe.bnotk.de/display/syshilfe/Root-Zertifikate+der+Bundesnotarkammer>

**Open-source projects:** github.com/it-at-m/xjustiz · github.com/it-at-m/eNoVa-Editor · github.com/digitalservicebund/a2j-xjustiz-bridge · github.com/digidigital/openXJV · github.com/digidigital/XJustiz2PDF · github.com/psysm/mjp-batch-export · **github.com/hauksch/rosci** (Rust OSCI CLI/REST wrapper; consumer of this research's target library)

**OSCI library & test intermediary:** repo1.maven.org/maven2/de/osci/ (`osci-bibliothek` 2.6.1, EUPL-1.2/MIT) · gitlab.opencode.de/governikus/osci/osci-bib-java · gov.test.osci.de (registration-free OSCI-Manager test instance) · xoev.de/osci-xta/…/osci-transport-1-2-intermediaere-23213 (intermediaries overview)

**Wikipedia (overview/history):** OSCI · Online Services Computer Interface · EGVP · beA · beBPo · eBO · MJP · XJustiz · De-Mail
