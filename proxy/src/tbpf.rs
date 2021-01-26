use bpf_sys::*;

use bpf_sys::bpf_attr__bindgen_ty_3 as bpf_attr;

use libc::syscall;
use libc::SYS_bpf;

fn sys_bpf(cmd: bpf_cmd, attr: bpf_attr, size: u32) -> i64{
	syscall(SYS_bpf, cmd, attr, size)
}

fn load_program(prog_type: bpf_prog_type, insns: bpf_insn, insns_cnt: usize,
		      license: &str, kern_version: u32, log_buf: &str,
		      log_buf_sz: usize) -> c_int
{



	let mut attr = bpf_attr {
		prog_type : prog_type,
		insns : insns,
		insn_cnt : insns_cnt,
		license : license as *const _,
		log_buf : std::ptr::null(),
		log_size : 0,
		log_level : 0,
		kern_version : kern_version,
	};

	let fd = sys_bpf(bpf_cmd_BPF_PROG_LOAD, &attr, sizeof(attr));
	if fd >= 0 || !log_buf || !log_buf_sz {
		return fd;
	}



	/* Try again with log */
	attr.log_buf = log as *mut _;
	attr.log_size = log.capacity();
	attr.log_level = 1;
	log_buf[0] = 0;
	return sys_bpf(bpf_cmd_BPF_PROG_LOAD, &attr, sizeof(attr));
}

fn load_parser() {

	let log = String::with_capacity(16 * 1024);

	load_program(bpf_prog_type_BPF_PROG_TYPE_SK_SKB, )
}