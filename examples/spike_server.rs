//! Step 0.5 spike -- server. Runs in netns `spk` (address 10.0.0.2) via `ip netns exec spk`, opens a
//! raw `IPPROTO_UDP` socket (the kernel hands it full, already-reassembled IP datagrams), and for
//! each wire case reports how much of the appended surplus survived the staged 1500-MTU link.
//! Throwaway; see `scripts/spike.sh` and `docs/plan/steps/00b-spike.md`.
//!
//! Gates the delivery side (the client gates the send-limit case). Note: a surplus surviving the
//! local kernel is NOT evidence a real middlebox preserves it -- that is the Step 17 / real-path
//! question.

#[path = "support/common.rs"]
mod common;

use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::process;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use common::{CaseParts, Check, IP_HDR_LEN, MARKER_BASE, SpikeError, UDP_HDR_LEN, case_parts, marker_port, pattern};

/// Touched once the recv socket is live, so `scripts/spike.sh` only starts the client when we listen.
const READY_FILE: &str = "/tmp/spike-server-ready";
const RECV_TIMEOUT: Duration = Duration::from_secs(2);
/// Overall budget to collect all wire cases before giving up on the stragglers.
const DEADLINE: Duration = Duration::from_secs(30);

struct Observation {
    total_len: usize,
    udp_len_field: usize,
    /// `None` when the delivered UDP Length field was inconsistent (anomaly cases).
    surplus: Option<Vec<u8>>,
}

struct Case {
    label: String,
    surplus_len: usize,
    written_ip_total_len: usize,
    check: Check,
    physical_len: usize,
}

fn cases() -> Vec<Case> {
    case_parts()
        .into_iter()
        .map(
            |CaseParts {
                 label,
                 udp_data_len,
                 surplus_len,
                 written_ip_total_len,
                 udp_len_override: _udp_len_override,
                 cksum: _cksum,
                 check,
             }| Case {
                label,
                surplus_len,
                written_ip_total_len,
                check,
                physical_len: IP_HDR_LEN + UDP_HDR_LEN + udp_data_len + surplus_len,
            },
        )
        .collect()
}

/// A matched marker datagram as the server observed it (after any kernel reassembly).
struct Marker<'a> {
    dst_port: u16,
    /// IP Total Length as delivered -- the kernel sets this to the buffer length (Finding A).
    total_len: usize,
    /// The UDP Length *field* as delivered (the anomaly cases write a lying value).
    udp_len_field: usize,
    /// Surplus = bytes from the end of the UDP datagram up to the observed IP Total Length.
    /// `None` when the UDP Length field is inconsistent (under 8 or past the IP Total Length),
    /// because then no well-defined surplus exists.
    surplus: Option<&'a [u8]>,
}

/// If `data` is one of our marker datagrams (matched by destination port out of `n_cases` marker
/// ports), return what the receiver sees bounded by IP Total Length. A lying UDP Length field
/// does not disqualify the match -- the anomaly cases need to be observed, not filtered out.
/// Total over the wire; never panics on malformed input.
fn match_marker(data: &[u8], n_cases: usize) -> Option<Marker<'_>> {
    if data.len() < IP_HDR_LEN {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < IP_HDR_LEN || data.len() < ihl || data[9] != libc::IPPROTO_UDP as u8 {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len > data.len() || total_len < ihl + UDP_HDR_LEN {
        return None;
    }
    let udp = &data[ihl..];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if !(MARKER_BASE..MARKER_BASE + n_cases as u16).contains(&dst_port) {
        return None;
    }
    let surplus = if udp_len >= UDP_HDR_LEN && ihl + udp_len <= total_len {
        Some(&data[ihl + udp_len..total_len])
    } else {
        None
    };
    Some(Marker {
        dst_port,
        total_len,
        udp_len_field: udp_len,
        surplus,
    })
}

/// Space-separated hex of up to `max` bytes, with an ellipsis marker when truncated.
fn hex(bytes: &[u8], max: usize) -> String {
    let mut s = String::new();
    for b in bytes.iter().take(max) {
        s.push_str(&format!("{b:02x} "));
    }
    if bytes.len() > max {
        s.push_str("...");
    }
    s.trim_end().to_string()
}

fn main() {
    match run() {
        Ok(true) => process::exit(0),
        Ok(false) => process::exit(1),
        Err(SpikeError::Permission) => {
            eprintln!("spike_server FAIL: raw recv socket needs CAP_NET_RAW (run via scripts/spike.sh under sudo)");
            process::exit(2);
        }
        Err(SpikeError::Io(e)) => {
            eprintln!("spike_server FAIL: {e}");
            process::exit(1);
        }
    }
}

fn run() -> Result<bool, SpikeError> {
    let sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::from(libc::IPPROTO_UDP)),
    )?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))?;
    let _ = fs::write(READY_FILE, b"ready");

    // We expect every wire and anomaly case; the send-limit cases never reach us.
    let all = cases();
    let mut seen: Vec<Option<Observation>> = (0..all.len()).map(|_| None).collect();
    let expected = |i: usize| all[i].check != Check::SendFails;
    let all_wire_seen =
        |seen: &[Option<Observation>]| seen.iter().enumerate().all(|(i, o)| !expected(i) || o.is_some());

    let mut buf = [MaybeUninit::<u8>::uninit(); 8192];
    let deadline = Instant::now() + DEADLINE;
    while !all_wire_seen(&seen) && Instant::now() < deadline {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(SpikeError::from(e)),
        };
        // SAFETY: the kernel initialized the first `n` bytes of `buf`.
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if let Some(m) = match_marker(data, all.len()) {
            let idx = (m.dst_port - MARKER_BASE) as usize;
            if idx < seen.len() && seen[idx].is_none() {
                seen[idx] = Some(Observation {
                    total_len: m.total_len,
                    udp_len_field: m.udp_len_field,
                    surplus: m.surplus.map(<[u8]>::to_vec),
                });
            }
        }
    }

    Ok(report(&all, &seen))
}

/// Print the per-case report and return whether every gating (wire/anomaly) case passed.
fn report(all: &[Case], seen: &[Option<Observation>]) -> bool {
    println!("spike_server: results");
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;
    let mut rewritten = 0usize;

    for (i, case) in all.iter().enumerate() {
        let port = marker_port(i);
        let label = &case.label;

        if case.check == Check::SendFails {
            skip += 1;
            continue;
        }

        let Some(obs) = &seen[i] else {
            println!(
                "  {label:<18} port {port}  MISS  no datagram within {}s",
                DEADLINE.as_secs()
            );
            fail += 1;
            continue;
        };

        // The kernel delivers IP Total Length == buffer regardless of what was written (Finding A).
        let note = if case.written_ip_total_len != obs.total_len {
            rewritten += 1;
            format!(" (wrote {}; kernel rewrote -- Finding A)", case.written_ip_total_len)
        } else {
            String::new()
        };

        match case.check {
            Check::Wire => {
                let want = pattern(case.surplus_len);
                let got = obs.surplus.as_deref().unwrap_or(&[]);
                let ok = got == want.as_slice() && obs.total_len == case.physical_len;
                let tag = if ok { "PASS" } else { "FAIL" };
                println!(
                    "  {label:<18} port {port}  {tag}  surplus={}B [{}] (expected {}B) total={}{note}",
                    got.len(),
                    hex(got, 8),
                    case.surplus_len,
                    obs.total_len,
                );
                if ok {
                    pass += 1
                } else {
                    fail += 1
                };
            }
            Check::WireRaw => {
                // Anomaly case: arriving at all is the result; the shape is logged, not judged.
                let surplus_desc = match &obs.surplus {
                    Some(s) => format!("surplus={}B [{}]", s.len(), hex(s, 8)),
                    None => "surplus=<no well-defined surplus: UDP Length field inconsistent>".to_string(),
                };
                println!(
                    "  {label:<18} port {port}  PASS  delivered despite anomaly: total={} udp-len-field={} {surplus_desc}",
                    obs.total_len, obs.udp_len_field,
                );
                pass += 1;
            }
            Check::SendFails => unreachable!("skipped above"),
        }
    }

    let all_pass = fail == 0;
    println!(
        "spike_server: {} ({pass} delivered+passed, {skip} skipped send-limit cases, {fail} failed; \
         Finding A confirmed on {rewritten} lying-Total-Length cases)",
        if all_pass {
            "PASS (all deliverable cases)"
        } else {
            "FAIL (a deliverable case did not match)"
        }
    );
    all_pass
}
