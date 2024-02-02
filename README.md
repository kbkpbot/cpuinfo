## Description:
  cpuinfo is a vlang module of retrieve CPU info. Currently, it support x86 & arm64 processor.
  
## Usage:
  ```sh
	git clone https://github.com/kbkpbot/cpuinfo
  ```
  Then, in your code, import it.
  ```v
  import cpuinfo
  
  fn main() {
	mut cpu := cpuinfo.detect_x86()
	println(cpu)
 	assert cpu.has(.fpu, .sse, .sse2, .sse3, .aes)	// `has` at least one of the request features
	assert cpu.all(.fpu, .sse, .sse2)  // should have `all` the request features
  }
  ```
  Also, you can use the `cpuinfo.CPUInfo_X86` or `cpuinfo.CPUInfo_ARM64` directly.