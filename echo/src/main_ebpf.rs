use std::os::unix::io::AsRawFd;
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use glommio::net::{TcpListener};
use glommio::prelude::*;

use redbpf::load::Loader;
use redbpf::SockMap;


fn main() {
   let server_handle = LocalExecutorBuilder::new().spawn(|| async move {

        let loaded = Loader::load(probe_code()).expect("error loading BPF program");

        let bpf_map = loaded.map("sockmap").unwrap();
    
        let mut sockmap = SockMap::new(bpf_map).unwrap();

        loaded
            .stream_parsers()
            .next()
            .unwrap()
            .attach_sockmap(&sockmap)
            .expect("Attaching sockmap failed");

        loaded
            .stream_verdicts()
            .next()
            .unwrap()
            .attach_sockmap(&sockmap)
            .expect("Attaching sockmap failed");

        let listener = TcpListener::bind("127.0.0.1:10000").unwrap();
        println!(
            "Server Listening on {}",
            listener.local_addr().unwrap()
        );

        let mut stream = listener.accept().await.unwrap();
        sockmap.set(0, stream.as_raw_fd()).unwrap();
        println!(
            "Sockmap set fd {}",
            stream.as_raw_fd()
        );

        loop {
            let mut buf = [0u8; 16];
            let b = stream.read(&mut buf).await.unwrap();
            if b == 0 {
                break;
            } else {
                stream.write(&buf).await.unwrap();
                println!("Echoed from userspace: {}", String::from_utf8_lossy(&buf));
            }
        }
    }).unwrap();

    server_handle.join().unwrap();
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        std::env!("OUT_DIR"),
        "/target/bpf/programs/echo/echo.elf"
    ))
}
