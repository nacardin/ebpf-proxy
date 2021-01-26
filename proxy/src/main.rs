use redbpf::load::Loader;
use redbpf::HashMap;

use futures_lite::{AsyncReadExt, AsyncWriteExt};
use glommio::net::{TcpListener, TcpStream};
use glommio::prelude::*;
use glommio::Task;

use std::os::unix::io::AsRawFd;

// mod tbpf;

fn main() {
    

    let server_handle = LocalExecutorBuilder::new().spawn(|| async move {

        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        let map = loaded.map("sockmap").unwrap();
    
        let mut sockmap: HashMap<u32, i32> = HashMap::new(map).unwrap();

        println!("loaded.sk_skbs() len {}", loaded.sk_skbs().count());

        for prog in loaded.sk_skbs() {
            match prog.name().as_ref() {
                "prog_parser" => {
                    println!("asd prog_parser");
                    prog.attach_map(map, bpf_sys::bpf_attach_type_BPF_SK_SKB_STREAM_PARSER).unwrap();
                },
                "prog_verdict" => {
                    println!("asd prog_verdict");
                    prog.attach_map(map, bpf_sys::bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT).unwrap();
                },
                _ => println!("asd bad"),
            }
        }

        // let prog_parser = loaded.program("skskb/prog_parser").unwrap();
        // let prog_verdict = loaded.program("skskb/prog_verdict").unwrap();

        // match prog_parser {
        //     redbpf::Program::SkSkb(prog_parser) => {
        //         
        //     }
        //     _ => ()
        // }
        // match prog_verdict {
        //     redbpf::Program::SkSkb(prog_verdict) => {
        //         prog_verdict.attach_map(map, bpf_sys::bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT).unwrap();
        //     }
        //     _ => ()
        // }


        let listener = TcpListener::bind("127.0.0.1:10000").unwrap();
        println!(
            "Server Listening on {}",
            listener.local_addr().unwrap()
        );
        let mut stream = listener.accept().await.unwrap();
        sockmap.set(0, stream.as_raw_fd());
        println!(
            "Sockmap set fd {}",
            stream.as_raw_fd()
        );
        loop {
            let mut buf = [0u8; 4];
            let b = stream.read(&mut buf).await.unwrap();
            if b == 0 {
                break;
            } else {
                stream.write(&buf).await.unwrap();
                println!(
                    "Echoed {:?}", buf
                );
            }
        }
    }).unwrap();

    server_handle.join().unwrap();
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        std::env!("OUT_DIR"),
        "/target/bpf/programs/sockmap/sockmap.elf"
    ))
}