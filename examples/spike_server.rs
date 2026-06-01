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

use common::{CASES, Check, MARKER_BASE, SpikeError, hex, marker_port, match_marker, pattern};

/// Touched once the recv socket is live, so `scripts/spike.sh` only starts the client when we listen.
const READY_FILE: &str = "/tmp/spike-server-ready";
const RECV_TIMEOUT: Duration = Duration::from_secs(2);
/// Overall budget to collect all wire cases before giving up on the stragglers.
const DEADLINE: Duration = Duration::from_secs(8);

struct Observation {
    total_len: usize,
    surplus: Vec<u8>,
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

    // We only expect the wire cases; the send-limit case never reaches us.
    let mut seen: Vec<Option<Observation>> = (0..CASES.len()).map(|_| None).collect();
    let expected = |i: usize| CASES[i].check == Check::Wire;
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
        if let Some(m) = match_marker(data) {
            let idx = (m.dst_port - MARKER_BASE) as usize;
            if idx < seen.len() && seen[idx].is_none() {
                seen[idx] = Some(Observation {
                    total_len: m.total_len,
                    surplus: m.surplus.to_vec(),
                });
            }
        }
    }

    Ok(report(&seen))
}

/// Print the per-case report and return whether every gating (wire) case passed.
fn report(seen: &[Option<Observation>]) -> bool {
    println!("spike_server: results");
    let mut all_pass = true;

    for (i, case) in CASES.iter().enumerate() {
        let port = marker_port(i);
        let label = case.label;

        if case.check == Check::SendFails {
            println!("  {label:<13} port {port}  SKIP  client-side send-limit case (not expected on the wire)");
            continue;
        }

        let Some(obs) = &seen[i] else {
            println!(
                "  {label:<13} port {port}  MISS  no datagram within {}s",
                DEADLINE.as_secs()
            );
            all_pass = false;
            continue;
        };

        let want = pattern(case.surplus_len);
        let got = obs.surplus.as_slice();
        let ok = got == want.as_slice();
        let tag = if ok { "PASS" } else { "FAIL" };
        println!(
            "  {label:<13} port {port}  {tag}  surplus={}B [{}] (expected {}B)",
            got.len(),
            hex(got, 16),
            case.surplus_len,
        );
        if case.written_ip_total_len != obs.total_len {
            println!(
                "                 Finding A: wrote IP Total Length={}, kernel delivered {} (= buffer); the appended bytes could not be hidden",
                case.written_ip_total_len, obs.total_len,
            );
        }
        if !ok {
            all_pass = false;
        }
    }

    println!(
        "spike_server: {}",
        if all_pass {
            "PASS (all wire cases)"
        } else {
            "FAIL (a wire case did not match)"
        }
    );
    all_pass
}
