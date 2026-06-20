# Lean/RFC 9868 Validation

Stand: 2026-06-12; Status-Update nach Step 3: 2026-06-20

## Kurzurteil

Lean kann fuer dieses Projekt sinnvoll eingesetzt werden, aber nicht als sofortige
End-to-End-Verifikation des kompletten aktuellen Rust-Codes gegen den RFC-Text.

Der belastbare Pfad ist gestuft:

1. Eine kleine, manuell geschriebene Lean-Spezifikation der RFC-9868-Wire-Regeln.
2. Beweise ueber diese Spezifikation und ueber einfache, reine Rust-Module.
3. Danach ein Pilot mit Charon/Aeneas, um ausgewaehlte Safe-Rust-Funktionen nach
   Lean zu extrahieren und gegen die Spezifikation zu beweisen.

Nicht belastbar waere die Aussage "Lean verifiziert jetzt den geschriebenen Code
vollstaendig gegen RFC 9868". Das bleibt in diesem Checkout falsch, weil:

- der aktive Branch `step-03-option-kind` nach Step 3 nur den reinen Wire-/Kind-Kern
  implementiert; Step 4 und spaetere Module sind weiterhin Stubs oder geplant;
- das Repo jetzt ein manuelles Lean/Lake-Projekt fuer Steps 1-3 enthaelt, aber keine
  Rust-zu-Lean-Extraktion;
- Charon/Aeneas lokal nicht installiert sind;
- die Lean-Schiene ueber die repo-gepinnte Toolchain und `scripts/lean-gate.sh`
  laeuft;
- RFC-9868-Konformitaet teilweise von Linux-Raw-Socket- und Middlebox-Verhalten
  abhaengt, das Lean nicht beweisen kann.

## Kontext, der validiert wurde

Checkout:

- `cwd`: `/Users/ab/Developer/me/udp-transport-options`
- Branch: `step-03-option-kind`
- `HEAD`: `f14b785 refactor: remove IPv6 from project scope` (die Erstfassung
  dieser Datei validierte gegen den Vorgaenger `b0d5afc`; siehe
  "Review-Korrekturen und Empfehlungen" unten)
- `origin/main`: `ac7eb17 feat: add wire model (IpRepr, UDP header, surplus) (#12)`
- Arbeitsbaum vor dieser Datei: sauber

Implementierungsstand:

- Fertig laut Roadmap nach dem Status-Update: Step 0, 0.5, 1, 2, 3.
- Offen laut Roadmap: Step 4-15 und 17 (Step 16 entfernt, Step 9 in Step 8
  gemerged).
- Reiner Ist-Code mit Substanz:
  - `src/model.rs`
  - `src/wire/checksum.rs`
  - `src/wire/ip.rs`
  - `src/wire/udp.rs`
  - `src/wire/surplus.rs`
  - `src/options/kind.rs`
  - `tests/properties_wire.rs`
  - `tests/common/mod.rs`
- Stub- oder Planmodule:
  - `src/options/parse.rs` enthaelt nur `OptionRef`.
  - `src/options/serialize.rs`, `src/options/ocs.rs`, `src/frag/split.rs`,
    `src/socket/send.rs`, `src/socket/recv.rs`, `src/api/mod.rs` sind Stubs.

Rust-Baseline:

- `cargo fmt --check`: erfolgreich.
- `cargo test`: erfolgreich.
  - 24 Unit-Tests
  - 3 Fuzz-Regression-Tests
  - 7 Property-Tests
  - (Stand `f14b785`; die Erstfassung zaehlte 29/3/8 am Vorgaenger `b0d5afc`,
    der IPv6-Scope-Cut entfernte die Differenz)
- `cargo clippy --all-targets -- -D warnings`: erfolgreich.

Lean-/Toolchain-Baseline:

- `lean`, `lake`, `elan` existieren unter `~/.elan/bin`.
- `lean --version` ohne explizite Toolchain schlaegt fehl: kein aktives
  Lean-Default-Toolchain.
- Installierte Lean-Toolchain: `leanprover/lean4:v4.15.0`.
- Expliziter Smoke-Test erfolgreich:
  - `elan run leanprover/lean4:v4.15.0 lean --version`
  - einfacher Lean-Beweis ueber `lean --stdin`
  - `elan run leanprover/lean4:v4.15.0 lake --version`
- Kein Charon/Aeneas lokal:
  - kein `charon`
  - kein `aeneas`
  - kein `opam`, `ocaml`, `dune`, `nix`

## Normative Quellenbasis

Lokale RFC-Quelle:

- `../mcs-thesis-docs/literature/rfc9868.txt`

Gelesene RFC-Bereiche:

- Section 7: UDP Option Area, IP transport payload, Surplus Area.
- Section 8: OCS-Platzierung, 2-Byte-Alignment, Null-Pad.
- Section 9: OCS als Internet-Checksumme ueber Surplus Area plus
  Surplus-Laenge.
- Section 10: TLV-Format, Extended Length, SAFE/UNSAFE, Must-Support,
  invalid length handling.
- Sections 11.1-11.7: EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES.
- Section 14: Receive-Disposition und Reihenfolge.
- Section 15: API-Erwartungen.

Zusaetzlicher Errata-Check:

- RFC Editor Errata fuer RFC 9868 hat zwei Eintraege.
- Erratum 8834 ist verifiziert und technisch relevant: die Section-14-Aussage zu
  Optionen, deren Laenge ueber den UDP-Packet-Bereich hinausgeht, wird durch
  einen Verweis auf Section 10 ersetzt. Fuer ein Lean-Modell bedeutet das:
  Section 10 regiert invalid length handling; ein ueberlaufender Length-Wert ist
  malformed surplus area und fuehrt zum stillen Verwerfen aller Optionen.
- Erratum 8708 ist editorial: Figure 11 ist Terminal-FRAG, nicht
  Non-Terminal-FRAG.

Externe Primaerquellen:

- Lean Language Reference: https://lean-lang.org/doc/reference/latest/
- Lean/Aeneas Use Case: https://lean-lang.org/use-cases/aeneas/
- Aeneas README: https://github.com/AeneasVerif/aeneas
- Charon README: https://github.com/AeneasVerif/charon
- Aeneas Lean backend toolchain auf `main`:
  `leanprover/lean4:v4.30.0-rc2` (Stand 2026-06-12; der Pin wandert schnell)
- Charon `main` Rust toolchain:
  `nightly-2026-02-07` mit `rustc-dev`, `llvm-tools-preview`, `rust-src`,
  `miri`

## Was Lean beweisen kann

Lean kann nur Aussagen ueber eine formale Spezifikation beweisen. Der RFC ist
natuerliche Sprache. Daher gibt es immer eine menschlich zu pruefende Grenze:

1. Der RFC-Text und Errata muessen in Lean als mathematisches Modell uebersetzt
   werden.
2. Lean kann dann beweisen, dass Funktionen dieses Modell erfuellen.
3. Lean beweist nicht, dass die Modellierung jeden Satz des RFC korrekt erfasst,
   und Lean beweist nicht, wie Linux oder Middleboxes in der realen Welt handeln.

Damit ist der sinnvolle Claim:

> Der reine Wire-/Options-Kern erfuellt ein in Lean formalisiertes RFC-9868-Modell.

Nicht der sinnvolle Claim:

> Die gesamte Userspace-Implementation ist durch Lean vollstaendig RFC-9868-konform.

## Bewertete Ansaetze

### Ansatz A: Manuelle Lean-Spezifikation

Das ist sofort machbar und am wenigsten riskant.

Vorgehen:

- In einem separaten `formal/`- oder `lean/`-Verzeichnis ein Lake-Projekt anlegen.
- Ein repo-lokales `lean-toolchain` pinnen, statt globale `elan default`-Zustaende
  zu veraendern.
- RFC-Grundtypen modellieren:
  - `Byte`, `U16`, `U32` oder geeignete `UInt8`/`UInt16`-Wrapper.
  - Big-endian Decode/Encode.
  - `IpRepr`, `UdpHeader`, `SurplusLayout`, `OptionKind`.
  - One's-complement Addition und Checksumme.
  - TLV-Stream und Parse-Ergebnis.
- Erst Beweise fuer kleine, harte Invarianten schreiben.

Vorteile:

- Kein Abhaengigkeitsproblem mit `socket2`, `libc`, `thiserror`, `proptest` oder
  `std::net`.
- Sehr gut fuer RFC-9868-Wire-Regeln geeignet.
- Gute Basis fuer Testvektoren und Property-Test-Oracles.

Grenze:

- Beweist zunaechst eine Spezifikation, nicht automatisch den vorhandenen
  Rust-Code.

### Ansatz B: Charon/Aeneas Rust -> Lean

Das ist der direkte Weg, wenn "geschriebener Rust-Code" tatsaechlich in Lean
modelliert werden soll.

Dokumentierter Workflow:

1. Charon im Rust-Crate-Kontext ausfuehren, z.B. `charon cargo --preset=aeneas`.
2. Aeneas auf die erzeugte `.llbc`-Datei anwenden, z.B.
   `aeneas -backend lean`.
3. Die generierten Lean-Dateien in ein Lake-Projekt mit Aeneas-Backend einbinden.
4. Beweise gegen eine manuelle RFC-Spezifikation schreiben.

Befund:

- Der Ansatz existiert und ist fuer Safe, sequential Rust grundsaetzlich passend.
- Aeneas/Charon sind aber nicht lokal installiert.
- Die lokale Build-Basis fuer Aeneas fehlt (`opam`, `ocaml`, `dune` oder `nix`).
- Aeneas `main` pinnt aktuell ein anderes Lean als lokal verfuegbar
  (`v4.30.0-rc2` vs lokal `v4.15.0`); bei Aktivierung des Pfads frisch
  pruefen und per Commit-Hash einfrieren.
- Charon ist laut README Alpha-Software und hat bekannte Edge-Case-/API-Drift.
- Der Repo-Code nutzt Rust `1.96` und Edition 2024; Charon/Aeneas muessten mit
  einem kompatiblen, gepinnten Toolchain-Stand getestet werden.

Code-Fit im aktuellen Projekt:

- Gut geeignet:
  - `src/model.rs`
  - `src/wire/surplus.rs`
  - Teile von `src/wire/checksum.rs`
  - spaeter `src/options/kind.rs`
- Mit Adaptern oder Proof-Facade geeignet:
  - `src/wire/ip.rs`
  - `src/wire/udp.rs`
  - spaeter TLV Parser/Serializer/OCS
- Nicht direkt geeignet:
  - `src/socket/*` wegen FFI/Raw-Socket-I/O.
  - `examples/spike_*` wegen `unsafe`, Threads, Timing, Linux-Umgebung.
  - Tests/Fuzzer selbst; sie sind Oracles und Regressionen, keine
    Verifikationsziele.

Pragmatische Anpassung:

- Nicht den ganzen Crate auf einmal extrahieren.
- Einen kleinen `formal-core`-Ausschnitt oder Feature-gated Proof-Facade
  definieren, der nur reine, dependency-arme Funktionen enthaelt.
- Externe Modelle fuer `std::net::Ipv4Addr`, `Vec`, Slices,
  `Range`, `Option`, `Result` und einzelne Iteratoren nur dort zulassen, wo sie
  wirklich benoetigt werden.

### Ansatz C: Nur Lean-Reimplementation

Das ist als RFC-Modell nuetzlich, aber als Code-Verifikation zu schwach.

Es kann:

- RFC-9868-Invarianten maschinengeprueft ausdruecken.
- Golden vectors generieren.
- Rust-Property-Tests verbessern.

Es kann nicht:

- beweisen, dass die existierenden Rust-Funktionen dieselbe Semantik haben.

### Ansatz D: Andere Rust-Verifikationstools

Kani, Prusti, Creusot, Verus oder hax koennen das Projekt spaeter ergaenzen.
Sie ersetzen aber nicht den Lean-Claim. In diesem Checkout ist keines dieser
Tools installiert. Fuer die konkrete Frage ist Aeneas/Charon der naechstliegende
Rust-zu-Lean-Pfad.

## Modul-fuer-Modul-Ergebnis

### `src/model.rs`

Lean-Eignung: sehr hoch.

Beweisziele:

- Must-support Kinds sind genau `0..=7`.
- SAFE ist genau `0..=191`.
- UNSAFE ist genau `192..=255`.
- Feste Laengen stimmen mit RFC Table 1 und Sections 11.3-11.7.
- MRDS Default: IPv4 `2926`, Segmente `2` (kein IPv6-Default mehr; IPv6 ist
  seit `f14b785` out of scope).
- Reassembly-Timeout: der RFC fordert nur einen Default von hoechstens
  2 Minuten als SHOULD (Section 11.4), kein hartes MUST.
  `REASSEMBLY_TIMEOUT_MAX` ist als Default-Obergrenze zu modellieren, nicht
  als absolute Invariante.

Status:

- Als manuelle Lean-Spezifikation sofort beweisbar.
- Per Aeneas wahrscheinlich einfach, sofern Konstantenextraktion funktioniert.

### `src/wire/checksum.rs`

Lean-Eignung: hoch, aber nicht trivial.

Beweisziele:

- 16-bit one's-complement Addition mit End-Around-Carry.
- Odd trailing byte wird als High-Byte eines finalen Wortes behandelt.
- `finish` ist das Einerkomplement des gefalteten Sums.
- Daten plus gespeicherter Checksumme falten zu `0xffff`.
- UDP-spezifische Normalisierung `0x0000 -> 0xffff` bleibt ausserhalb des
  generischen Checksum-Kerns.

Risiken:

- Die Rust-Implementation nutzt `chunks_exact` und mutable Akkumulation. Aeneas
  kann Mutation grundsaetzlich funktionalisieren, aber Iterator-/Slice-Modelle
  koennen Handarbeit erzwingen.

Empfehlung:

- Erst manuelle Lean-Spec fuer `onesComplementSum`.
- Danach einen kleinen Rust-Proof-Facade-Wrapper ohne komplexe Iteratoren fuer
  Aeneas-Pilot pruefen.

### `src/wire/ip.rs`

Lean-Eignung: mittel bis hoch (seit dem IPv6-Scope-Cut deutlich einfacher).

Beweisziele:

- IPv4: `transport_payload_len = total_len - ihl * 4`.
- `header_len = ihl * 4`.
- UDP pseudo-header seed benutzt nur UDP Length, nicht Surplus Area.
- Parse gibt keine Out-of-Bounds-Slices frei; IPv6 wird als
  `UnsupportedVersion(6)` abgelehnt.

Risiken:

- `std::net::Ipv4Addr` braucht ein Modell oder einen Wrapper.
- Das `expect("4-byte slice")` beim Adress-Slicing ist im Code trivially
  bounded, muss fuer Proofs aber als Lemma formuliert werden.

Empfehlung:

- Zuerst `IpRepr` als eigene Lean-Struktur modellieren.
- Danach nur `header_len`, `transport_payload_len`, `pseudo_header_sum` und
  ausgewahlte Parser-Invarianten beweisen.

### `src/wire/udp.rs`

Lean-Eignung: hoch fuer Header- und Checksum-Postconditions.

Beweisziele:

- Parse akzeptiert nur mindestens 8 Bytes.
- UDP Length unter 8 wird abgelehnt.
- Write/parse round trip.
- `compute_checksum` deckt Pseudo-Header, UDP header mit Checksum-Feld null und
  UDP user data ab, nie die Surplus Area.
- Computed zero wird als `0xffff` gesendet.

Risiken:

- `compute_checksum` hat eine `assert_eq!`-Precondition:
  `self.length == 8 + data.len()`. Lean/Aeneas muss diese Precondition sehen,
  sonst ist die Funktion partiell.

### `src/wire/surplus.rs`

Lean-Eignung: sehr hoch und bester erster Zielkandidat.

Beweisziele:

- Wenn `locate_surplus` `Some(layout)` liefert:
  - `layout.starts_at = ip.header_len + udp.length`
  - `layout.needs_pad` genau dann, wenn `starts_at` ungerade ist
  - `layout.ocs_at = starts_at + needs_pad`
  - `layout.ocs_at` ist gerade
  - `layout.range` endet am IP-Datagrammende
  - `layout.len` ist die raw surplus length
  - `layout.len >= pad + 2`
- Wenn `udp.length > transport_payload_len`, muss `None` kommen.
- Wenn kein Surplus oder zu wenig Platz fuer aligned OCS existiert, muss `None`
  kommen.

Status:

- Diese Eigenschaften sind bereits als Rust-Property-Test-Oracles in
  `tests/common/mod.rs` angelegt.
- Sie lassen sich sehr sauber in Lean formalisieren.

### `src/options/kind.rs`

Lean-Eignung: sehr hoch, aber aktueller Code ist unvollstaendig.

Ist-Zustand:

- Step 3 ist umgesetzt.
- `from_byte`, `to_byte`, SAFE/UNSAFE, must-support und length/framing helpers sind
  implementiert und exhaustiv ueber alle 256 Kind-byte-Werte getestet.
- Die manuelle Lean-Spec `Rfc9868/Kind.lean` beweist die Kind-Tabelle und die
  Grenzpraedikate.

Beweisziele nach Step 3:

- Exhaustive 256-Kind-Theoreme.
- `to_byte(from_byte(b)) == b`.
- `is_safe` iff `to_byte(kind) < 192`.
- `is_unsafe` iff `to_byte(kind) >= 192`.
- `is_must_support` iff raw Kind in `0..=7`.
- EOL/NOP sind Single-Byte; andere Kinds sind TLV/extended-capable.

### `src/options/parse.rs`

Lean-Eignung: hoch, sobald implementiert.

Ist-Zustand:

- Nur `OptionRef` existiert; kein Iterator.

Spaetere Beweisziele:

- Totalitaet: beliebige Bytes fuehren zu Ergebnis oder Fehler, nie Panic.
- Optionen werden in Reihenfolge geliefert.
- EOL beendet Verarbeitung.
- NOP/EOL haben keine Length-Felder.
- Extended Length wird korrekt interpretiert.
- Invalid underrun/overrun fuehrt gemaess RFC 9868 Section 10 und Erratum 8834
  zum Verwerfen aller Optionen.

### `src/options/serialize.rs`

Lean-Eignung: mittel bis hoch, sobald implementiert.

Spaetere Beweisziele:

- Must-support-before-other-SAFE auf Sendeseite.
- NOP nur fuer Alignment.
- EOL plus Zero-Fill.
- Kleinste Length-Form fuer `<=254`, Extended fuer `>254`.
- Serialize/parse round trip fuer wohlgeformte Optionen.

### `src/options/ocs.rs`

Lean-Eignung: hoch, sobald implementiert.

Spaetere Beweisziele:

- OCS-Feld wird fuer Berechnung als null behandelt.
- Surplus-Laenge wird als 16-bit Addend eingeschlossen.
- Validierung ueber Surplus Area plus gespeicherter OCS faltet zu `0xffff`.
- Berechneter Wert `0x0000` wird als `0xffff` gesendet. Achtung: diese Regel
  ist im RFC-9868-Text nicht woertlich zitierbar; sie folgt aus der
  Internet-Checksum-Konvention plus der Non-zero-OCS-Anforderung (Section 9).
  Vor der Formalisierung die exakte Belegstelle fixieren, statt sie still als
  Axiom anzunehmen.
- `OCS == 0` ist nur mit UDP checksum zero erlaubt bzw. in der Receive-Matrix
  als Legacy-Ignore-Fall behandelt.

### `src/options/typed.rs`

Lean-Eignung: hoch fuer feste Laengen, mittel fuer APC.

Ist-Zustand:

- Structs und Trait-Signatur existieren; keine Encode/Decode-Implementierung.

Spaetere Beweisziele:

- APC/MDS/MRDS/REQ/RES/FRAG Decode akzeptiert genau die RFC-Laengen.
- FRAG Len `10` ist non-terminal, Len `12` terminal.
- Big-endian Round Trip.
- APC CRC32C braucht entweder ein Lean-Modell von CRC32C oder eine bewusst
  abgegrenzte Trusted-Primitive mit externen Testvektoren.

### `src/recv/pipeline.rs`

Lean-Eignung: mittel, sobald implementiert.

Spaetere Beweisziele:

- Receive order: UDP checksum -> surplus layout/pad -> OCS -> TLV parse ->
  option processing -> FRAG/reassembly oder delivery.
- Section-14-Disposition-Matrix.
- SAFE default-deliver.
- UNSAFE unsupported drop semantics inklusive zero-length delivery caveat.
- FRAG/NOP/EOL werden nicht an User weitergegeben.

Risiko:

- Die Pipeline wird viele Konfigurations- und Fehlerpfade haben. Hier sind
  zuerst table-driven Rust-Tests und danach Lean-Theoreme sinnvoll.

### `src/frag/*`

Lean-Eignung: mittel bis hoch, sobald implementiert.

Spaetere Beweisziele:

- Split-Chunks respektieren MDS/MRDS.
- Non-terminal/terminal FRAG-Laengen.
- Reassembly-Key ist (Quell-IP, Quell-Port, Ziel-IP, Ziel-Port) plus
  Identification. Nicht "5-Tuple plus Identification": das Protokoll ist fix
  UDP und kein Key-Bestandteil.
- Overlap abortet.
- Complete erst bei lueckenloser Abdeckung.
- Timeout/GC/DoS-Caps sind als reine State-Transitionen modellierbar.

Grenze:

- `Instant`/wall-clock selbst nicht beweisen; nur uebergebenes `now` und
  Timeout-Relation.

### `src/socket/*` und Examples

Lean-Eignung: niedrig fuer direkte Verifikation.

Grund:

- Raw sockets, Linux-Kernel, `CAP_NET_RAW`, `IP_HDRINCL`, `SOCK_RAW`, `libc`,
  `socket2`, `unsafe`, Timing und netns/veth-Verhalten sind Systemeffekte.

Machbarer Lean-Claim:

- Pure Buffer-Building-Funktionen erfuellen Wire-Postconditions.

Nicht machbarer Lean-Claim:

- Der Linux-Kernel oder ein Middlebox-Pfad erhaelt den Surplus Area garantiert.
  Das bleibt Spike-/Integration-/FF2-Empirie.

## Empfohlener Validierungspfad

### Phase 0: Lean-Projekt vorbereiten

Success Criteria:

- Repo-lokales Lean-Toolchain-Pinning vorhanden.
- `lake build` laeuft ohne globale `elan default`-Annahme.
- Keine `sorry` in produktiven Proof-Dateien.
- Externe Axiome nur in einer kleinen, dokumentierten Trusted Base.

Empfehlung:

- Ein separates Verzeichnis verwenden, z.B. `formal/lean-rfc9868/`.
- Keine generierten Aeneas-Dateien per Hand editieren.
- Aeneas/Charon-Versionen mit Commit-Hash pinnen, falls der Extraktionspfad
  aktiviert wird.

### Phase 1: RFC-Kern manuell formalisieren

Startumfang:

- `OptionKind` und Konstanten.
- One's-complement Sum.
- UDP Header-Laenge und Checksum-Scope.
- `SurplusLayout` und `locate_surplus`-Spezifikation.

Success Criteria:

- Theoreme fuer SAFE/UNSAFE/Must-Support sind exhaustive ueber 256 Werte.
- Theoreme fuer `locate_surplus` decken alle `Some`/`None`-Faelle ab.
- OCS-/UDP-Checksum-Basislemmata sind vorhanden.

### Phase 2: Rust-Extraktionspilot

Startumfang:

1. `src/model.rs`
2. ein kleiner Proof-Facade fuer `src/wire/surplus.rs`
3. danach `src/wire/checksum.rs`

Success Criteria:

- Charon erzeugt `.llbc` fuer den ausgewaehlten Ausschnitt.
- Aeneas erzeugt Lean.
- `lake build` prueft die generierten Dateien.
- Mindestens ein Theorem verbindet eine extrahierte Rust-Funktion mit der
  manuellen RFC-Spezifikation.

Nicht als Erfolg zaehlen:

- Nur generierten Lean-Code erzeugen.
- Proofs mit `sorry`.
- Axiome, die genau die zu beweisende RFC-Eigenschaft voraussetzen.

### Phase 3: Ausbau mit Projektfortschritt

Reihenfolge:

1. Step 3: `OptionKind`.
2. Step 4: TLV parser totality.
3. Step 5: Serializer canonicalization.
4. Step 6: OCS.
5. Step 7: typed options.
6. Step 10: receive disposition.
7. Step 11-12: FRAG split/reassembly.

Socket-I/O bleibt ausserhalb des Lean-Kerns und wird mit Linux-/achim-Tests
validiert.

## Ergebnis

Ja, wir koennen Lean in diesem Projekt verwenden.

Aber das belastbare Ergebnis ist begrenzt:

- Jetzt sofort sinnvoll: Lean als formale RFC-9868-Wire-Spezifikation und fuer
  kleine Beweise zu Konstanten, Checksum-Arithmetik und Surplus-Layout.
- Nach Setup sinnvoll: Charon/Aeneas-Pilot fuer ausgewaehlte reine
  Safe-Rust-Module.
- Nicht jetzt moeglich: vollstaendige Verifikation des gesamten geschriebenen
  Rust-Codes gegen RFC 9868.
- Grundsaetzlich nicht durch Lean allein moeglich: Nachweis von Linux-Raw-Socket-
  und Middlebox-Verhalten.

Diese Punkte sind seit Step 3 erledigt:

1. Step 3 implementieren.
2. `formal/lean-rfc9868/` anlegen.
3. `OptionKind` und `locate_surplus` als erste Lean-Beweise formalisieren.

Die naechste technisch saubere Arbeitseinheit ist Step 4: der zero-copy TLV-Parser. Danach bleibt
die Entscheidung offen, ob Charon/Aeneas fuer diesen Crate stabil genug ist oder ob der Wert
primaer in einer manuellen Spezifikation plus Rust-Testvektoren liegt.

## Review-Korrekturen und Empfehlungen (2026-06-12)

Diese Datei wurde nach der Erstfassung adversarial gegengeprueft (eigene
Pruefung plus drei unabhaengige Codex-Verifizierer gegen RFC-Text, Repo-Stand
und Toolchain). Kernurteil und Phasenplan halten; die folgenden Punkte der
Erstfassung waren falsch oder zu stark formuliert und sind oben korrigiert.

Korrekturen:

- HEAD ist `f14b785` (IPv6-Scope-Cut), nicht `b0d5afc`. Alle IPv6-Beweisziele
  (ip.rs Extension-Header, `Ipv6Addr`-Modelle, MRDS-IPv6-Default 2886) waren
  gegen entfernten Code geschrieben und sind gestrichen.
- Testzahlen am echten HEAD: 24 Unit / 3 Fuzz-Regression / 7 Property,
  nicht 29/3/8.
- `src/wire/ip.rs` enthaelt kein `expect("bounded...")`, nur
  `expect("4-byte slice")`; `IpRepr` ist IPv4-only.
- Der Aeneas-Lean-Pin auf `main` ist `v4.30.0-rc2`, nicht `v4.28.0-rc1`.
- FRAG-Reassembly-Key: (Quell-IP, Quell-Port, Ziel-IP, Ziel-Port) plus
  Identification, nicht "5-Tuple plus Identification".
- Der Reassembly-Timeout "hoechstens 2 Minuten" ist im RFC nur ein
  Default-SHOULD (Section 11.4), kein hartes MUST; als Default modellieren.
- Die Regel "berechnetes OCS 0x0000 wird als 0xFFFF gesendet" ist im
  RFC-9868-Text nicht woertlich belegbar; Belegstelle vor der Formalisierung
  fixieren (siehe den ocs.rs-Abschnitt).

Empfehlungen (verbindlich fuer den weiteren Pfad):

1. Phase 1 (manuelle Lean-Spec plus Theoreme fuer `OptionKind`,
   `locate_surplus`, Checksum-Basics, OCS-Framing) ist das einzige
   verbindliche Thesis-Artefakt der Lean-Schiene.
2. Der Charon/Aeneas-Pilot (Phase 2) ist ein optionaler, zeitgeboxter Spike
   mit hartem Erfolgskriterium: genau eine extrahierte Rust-Funktion wird
   aequivalent zur Spec bewiesen. Kein Erfolg = kein Thesis-Claim, sondern
   nur eine dokumentierte Machbarkeitsaussage.
3. Proof-Maintenance ist ein wiederkehrender Posten pro Roadmap-Step, keine
   einmalige Phase: jeder Step erweitert zuerst die Spec, implementiert dann
   und beweist danach; `lake build` ohne `sorry` gehoert zum Step-Commit.
   Dieser Spec-first-Workflow ist in jedem `docs/plan/steps/NN-*.md` als
   Abschnitt "Lean verification" verankert.
4. CI-Kosten explizit einplanen: repo-lokales Toolchain-Pinning, Build-Cache,
   `sorry`-Gate; der Aeneas-Pfad laeuft, falls aktiviert, als separate,
   nicht-blockierende Lane.
5. Kani als pragmatische Ergaenzung fuer bounded-Eigenschaften (Panics,
   Overflow am TLV-Parser/Serializer) pruefen; es ersetzt den Lean-Claim
   nicht, flankiert ihn aber deutlich billiger als der Extraktionspfad.

Umsetzungsstand (gleicher Tag): `formal/lean-rfc9868/` existiert mit den
bewiesenen Step-1/2-Specs (45 Theoreme, Toolchain-Pin `v4.15.0`);
`scripts/lean-gate.sh` (Build + Kernel-Axiom-Audit) laeuft als Lane in
`scripts/pre-pr.sh` und als `lean`-Job zwischen `rust` und `agent-reviews`
in der PR-CI. Damit sind die Empfehlungen 3 und 4 umgesetzt und Phase 0/1
fuer die Steps 1-2 abgeschlossen; die Kurzurteil-Punkte "kein Lake-Projekt"
und "nur via explizitem elan run" sind damit ueberholt.

## Nicht zu verwechseln mit PR-Gruen

Die aktuellen Rust-Checks sind gruen, aber das ist keine formale Verifikation.
Sie zeigen, dass die aktuelle Implementierung kompiliert, formatiert ist, clippy
sauber ist und die vorhandenen Unit-/Property-/Regression-Tests bestehen.

Lean wuerde erst dann einen neuen Assurance-Level liefern, wenn:

- der RFC-Kern formal modelliert ist;
- die relevanten Rust-Funktionen extrahiert oder anderweitig nachweislich an die
  Spezifikation gekoppelt sind;
- die Proofs in CI ohne `sorry` laufen;
- der Scope klar trennt zwischen beweisbarem Pure-Core und empirischem
  Linux-/Netzwerkverhalten.
