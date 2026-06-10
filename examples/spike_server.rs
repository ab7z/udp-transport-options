//! Step 0.5 spike -- server. Runs in netns `spk` (address 10.0.0.2) via `ip netns exec spk`, opens a
//! raw `IPPROTO_UDP` socket (the kernel hands it full, already-reassembled IP datagrams), and for
//! each wire case reports how much of the appended surplus survived the staged 1500-MTU link.
//! Throwaway; see `scripts/spike.sh` and `docs/plan/steps/00b-spike.md`.
//!
//! Gates the delivery side (the client gates the send-limit case). Note: a surplus surviving the
//! local kernel is NOT evidence a real middlebox preserves it -- that is the Step 17 / real-path
//! question.

mod common;

use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::process;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use common::{Case, Check, MARKER_BASE, SpikeError, cases, hex, marker_port, match_marker, pattern};

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
                let ok = got == want.as_slice() && obs.total_len == case.physical_len();
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
