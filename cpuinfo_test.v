import cpuinfo

fn test_cpuinfo_x86() {
	$if i386 || amd64 {
		mut cpu := cpuinfo.detect_x86()
		assert cpu.x86_level() > 1
		assert cpu.x86_level() < 5
		assert cpu.feature_set().len > 1
		assert cpu.feature_set().len < 10000
		assert cpu.all(.fpu, .mmx, .sse)
		assert cpu.has(.fpu, .mmx, .sse, .sse3)
		if cpu.has(.rdtscp) {
			assert cpu.rt_counter() > 1000000
		}
	}
}

fn test_cpuinfo_arm64() {
	$if arm64 {
		mut cpu := cpuinfo.detect_arm()
		assert cpu.feature_set().len > 1
		assert cpu.feature_set().len < 10000
		assert cpu.all(.fp)
		assert cpu.has(.fp, .sha512)
	}
}
