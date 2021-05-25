#![no_std]
#![no_main]

use redbpf_probes::sockmap::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/sockmap")]
static mut SOCK_MAP: SockMap = SockMap::with_max_entries(1);

#[stream_parser]
fn parse_message_boundary(sk_buff_wrapper: SkBuff) -> StreamParserResult {
    let len: u32 = unsafe {
        (*sk_buff_wrapper.skb).len
    };
    Ok(StreamParserAction::MessageLength(len))
}

#[stream_verdict]
fn verdict(sk_buff_wrapper: SkBuff) -> SkAction {

    let index = 0;
    match unsafe { SOCK_MAP.redirect(sk_buff_wrapper.skb as *mut _, index) } {
        Ok(_) => SkAction::Pass,
        Err(_) => SkAction::Drop,
    }
}
