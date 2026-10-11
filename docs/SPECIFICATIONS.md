# Specification sources

This crate implements publicly documented German justice / e-government
standards. The specification documents are **not vendored** in this
repository: they are copyrighted by their publishers (redistribution terms
vary per document), so only canonical download locations are listed here.
All facts implemented in this crate were verified against these documents.

| Specification | Publisher / point of distribution | Status |
|---|---|---|
| **Standard für die Suche in den SAFE-Verzeichnissen der ERV-Kommunikationsinfrastruktur**, v1.5 (21.05.2026) — SPML search/lookup, attribute table, ERR codes | BLK-AG IT-Standards via [egvp.justiz.de/Drittprodukte](https://egvp.justiz.de/Drittprodukte/index.php/index.php) → „Spezifikation des SAFE-Standards für die Suche“ | freely downloadable |
| **SAFE-ID — Abbildungsvorschrift V2** (Juli 2017) — ID formats and SHA-256 check digits | same page → „SAFE_Abbildungsvorschrift_SAFE_ID_V2.pdf“ | freely downloadable |
| **Teilnahme von Drittanwendungen am OSCI-gestützten elektronischen Rechtsverkehr — Anforderungen**, v1.8 (20.04.2022) — SAFE role model / visibility matrix (§ 5.3) | same page → „Anforderungen für die Teilnahme von Drittanwendungen“ | freely downloadable |
| **Vertrauenswürdiger Herkunftsnachweis (VHN) 2 — Spezifikation**, v2.2 (09.12.2021) | same page → „Spezifikation des VHN 2-Standards“ (incl. `vhn.xsd`) | freely downloadable |
| **OSCI-Transport 1.2 Spezifikation** (Fassung 2002-06-06) + Korrigenda 1–10 (latest 2026-02-13) + Ergänzung „Effiziente Übertragung großer Datenmengen“ | [ITZBund OSCI/XÖV-Bezugsstelle](https://www.itzbund.de/DE/itloesungen/standardloesungen/xoev/oscixoevbezugsstelle/oscixoevbezugsstelle.html) — free download; implementers are granted a free, simple usage right (spec p. 2) | freely downloadable |
| **ERVB 2025** (BAnz AT 29.07.2025 B2) — file formats, size limits, signature formats | [justiz.de Elektronische Kommunikation](https://justiz.de/laender-bund-europa/elektronische_kommunikation/index.php) | freely downloadable (Bundesanzeiger) |
| **Leitfaden Elektronischer Rechtsverkehr mit der Justiz**, v1.6 (28.07.2025) | same page / [justiz.de/ervvoe/leitfaden_erv_pdf.pdf](https://justiz.de/ervvoe/leitfaden_erv_pdf.pdf) | freely downloadable |
| **XJustiz** schemata, Schematron, specifications (3.6.2 valid, 4.0.0 from 2027-04-30) | [xjustiz.justiz.de/downloads](https://xjustiz.justiz.de/downloads/index.php) | freely downloadable |
| **de.osci:osci-bibliothek** (OSCI 1.2 reference library, EUPL-1.2/MIT) | [Maven Central `de.osci`](https://repo1.maven.org/maven2/de/osci/) · canonical repo [gitlab.opencode.de/governikus/osci/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java) | open source |

Notes:

- The OSCI-Transport 1.2 specification is copyright-protected but grants
  implementers an *unentgeltliches einfaches Nutzungsrecht* (free, simple
  usage right) for building client/intermediary/service-provider systems;
  unmodified redistribution within that purpose is permitted.
- The BLK-AG documents above are freely downloadable but carry no explicit
  redistribution license — hence links, not copies.
- The full research background, including a per-spec summary, lives in
  [SAFE-register-research.md](SAFE-register-research.md).
