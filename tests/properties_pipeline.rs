//! Property-based tests for the Step 10 pure receive pipeline.

mod common_assemble;
mod common_pipeline;

use std::net::Ipv4Addr;
use std::time::Instant;

use proptest::collection::vec;
use proptest::prelude::*;
use udp_transport_options::frag::reassembly::ReassemblyCache;
use udp_transport_options::model::{kind, length};
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::typed::{Frag, TypedOption};
use udp_transport_options::recv::pipeline::{Delivery, OptionSource, OptionStatus, process_datagram};
use udp_transport_options::socket::send::assemble_datagram;

proptest! {
    #[test]
    fn pipeline_is_total_over_arbitrary_datagrams(bytes in vec(any::<u8>(), 0..=2048)) {
        common_pipeline::check_pipeline_invariants(&bytes);
    }

    #[test]
    fn pipeline_accepts_assembled_datagrams(
        src in any::<[u8; 4]>(),
        dst in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        user in vec(any::<u8>(), 0..=96),
        seed in vec(any::<u8>(), 0..=64),
    ) {
        let options = common_assemble::options_body_from_fuzz_bytes(&seed);
        let datagram = udp_transport_options::socket::send::assemble_datagram(
            Ipv4Addr::from(src),
            Ipv4Addr::from(dst),
            src_port,
            dst_port,
            &user,
            &options,
        );
        common_pipeline::check_pipeline_invariants(&datagram);
    }

    #[test]
    fn unknown_unsafe_terminates_before_later_frag(
        fragment_data in vec(any::<u8>(), 0..=64),
    ) {
        let frag = Frag {
            frag_start: u16::from(length::UDP_HEADER)
                + u16::from(length::OCS)
                + 2
                + u16::from(length::FRAG_NON_TERMINAL),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let mut options_body = vec![0, 0, kind::UNSAFE_MIN, 2];
        frag.encode(&mut options_body);
        options_body.extend_from_slice(&fragment_data);
        let datagram = assemble_datagram(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 2),
            12345,
            54321,
            b"",
            &options_body,
        );
        let mut cache = ReassemblyCache::new();

        let delivery = process_datagram(&datagram, &mut cache, Instant::now())
            .expect("assembled datagram has valid IP, UDP, and OCS checksums");
        let Delivery::Payload {
            data,
            options,
            option_bearing,
            reports,
            ocs_reports,
        } = delivery
        else {
            prop_assert!(false, "a later FRAG must not establish fragment context after UNSAFE");
            return Ok(());
        };
        prop_assert!(data.is_empty());
        prop_assert!(options.is_empty());
        prop_assert!(option_bearing);
        prop_assert_eq!(reports.len(), 1);
        prop_assert_eq!(reports[0].kind, OptionKind::Other(kind::UNSAFE_MIN));
        prop_assert_eq!(reports[0].status, OptionStatus::Failed);
        prop_assert_eq!(reports[0].source, OptionSource::Datagram);
        prop_assert_eq!(ocs_reports.len(), 1);
        prop_assert!(cache.is_empty());
    }
}
