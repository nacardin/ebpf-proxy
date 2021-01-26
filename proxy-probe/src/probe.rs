#![no_std]
#![no_main]

use redbpf_macros::map;

// use cty::*;

// use one of the preludes
// use redbpf_probes::kprobe::prelude::*;
// use redbpf_probes::xdp::prelude::*;
// use redbpf_probes::socket_filter::prelude::*;

use redbpf_probes::socket_filter::prelude::*;

use redbpf_probes::helpers::gen::bpf_sk_redirect_map;
use redbpf_probes::helpers::gen::bpf_ktime_get_ns;

// Use the types you're going to share with userspace, eg:
// use ebpf-proxy::sockmap::SomeEvent;

// use std::os::unix::io::RawFd;

mod sockmap;
use sockmap::SockMap;

#[map(link_section = "maps/sockmap")]
static mut SOCK_MAP: SockMap<u32, i32> = SockMap::with_max_entries(2);

program!(0xFFFFFFFE, "Dual BSD/GPL");

#[no_mangle]
#[map(link_section = "skskb/prog_parser")]
unsafe fn _prog_parser(skb: *mut ::redbpf_probes::bindings::__sk_buff) -> c_uint {
    (*skb).len
}

#[no_mangle]
#[map(link_section = "skskb/prog_verdict")]
unsafe fn _prog_verdict(skb: *mut ::redbpf_probes::bindings::__sk_buff) -> c_int {
    // let skb = ::redbpf_probes::socket_filter::SkBuff { skb };

    let map = &mut SOCK_MAP as *mut _ as *mut core::ffi::c_void;
    let key = 0u32;
    let flags = 0u64;
    // bpf_ktime_get_ns() as i32
    bpf_sk_redirect_map(skb, map, key, flags)
}
