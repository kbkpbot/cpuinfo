module main

import cpuinfo as u
import benchmark

fn test_cpuinfo() {
	mut cpu := u.detect_x86() // detect x86 CPU features
	y := cpu.feature_set().join(',') // get all features, and construct into a string
	println(cpu)
	println(y)
	println('level = ${cpu.x86_level()}') // get x86 architecture level
	println('rt_counter=${cpu.rt_counter()}') // get x86 rt counter
	assert cpu.has(.fpu, .sse, .sse2, .sse3, .aes) // `has` at least one of the request features
	assert cpu.all(.fpu, .sse, .sse2) // should have `all` the request features
}

fn main() {
	mut b := benchmark.start()
	test_cpuinfo()
	b.measure('cpuinfo done')
}
