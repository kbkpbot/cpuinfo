# module cpuinfo
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



## Contents
- [cpuidex](#cpuidex)
- [detect_arm](#detect_arm)
- [detect_x86](#detect_x86)
- [rdtscp](#rdtscp)
- [xgetbv](#xgetbv)
- [FeatureID_ARM64](#FeatureID_ARM64)
- [FeatureID_X86](#FeatureID_X86)
- [Vendor_ARM64](#Vendor_ARM64)
- [Vendor_X86](#Vendor_X86)
- [AArch64Features](#AArch64Features)
- [AMDMemEncryptionSupport](#AMDMemEncryptionSupport)
- [CPUInfo_ARM64](#CPUInfo_ARM64)
  - [has](#has)
  - [all](#all)
  - [feature_set](#feature_set)
- [CPUInfo_X86](#CPUInfo_X86)
  - [has](#has)
  - [all](#all)
  - [x86_level](#x86_level)
  - [feature_set](#feature_set)
  - [rt_counter](#rt_counter)
  - [ia32_tsc_aux](#ia32_tsc_aux)
  - [logical_cpu](#logical_cpu)
  - [frequencies](#frequencies)
  - [vm](#vm)
- [SGXEPCSection](#SGXEPCSection)
- [SGXSupport](#SGXSupport)

## cpuidex
```v
fn cpuidex(op u32, op2 u32) (u32, u32, u32, u32)
```
cpuidex will call `cpuidex` instruction, return eax,ebx,ecx,edx

[[Return to contents]](#Contents)

## detect_arm
```v
fn detect_arm() CPUInfo_ARM64
```
detect_arm will detect current CPU info.

[[Return to contents]](#Contents)

## detect_x86
```v
fn detect_x86() CPUInfo_X86
```
detect_x86 will detect current CPU info.

[[Return to contents]](#Contents)

## rdtscp
```v
fn rdtscp() (u32, u32, u32, u32)
```
rdtscp will call `rdtscp` instruction, return eax,ebx,ecx,edx

[[Return to contents]](#Contents)

## xgetbv
```v
fn xgetbv(index u32) (u32, u32)
```
xgetbv will call `xgetbv` instruction, return eax,edx

[[Return to contents]](#Contents)

## FeatureID_ARM64
```v
enum FeatureID_ARM64 {
	unknown          = -1
	// ID_AA64PFR0_EL1, AArch64 Processor Feature Register 0
	fp // Floating-point
	fphp // Half-precision floating point support
	asimd // Advanced SIMD
	asimdhp // Advanced SIMD half-precision support
	// gic3_gic4 // GIC CPU interface system registers 3.0 and 4.0
	// gic_4p1   // GIC CPU interface system registers 4.1
	ras // RAS Extension 1.0 implemented
	ras_1p1 // RAS Extension 1.1 implemented
	sve // Scalable Vector Extension
	sel2 // Secure EL2 is implemented
	mpam_0p1 // MPAM extension is 0.1
	mpam_1p0 // MPAM extension is 1.0
	mpam_1p1 // MPAM extension is 1.1
	amu_v1 // Activity Monitors Extension v1 is implemented
	amu_v1p1 // Activity Monitors Extension v1.1 is implemented
	dit // Data independent timing
	csv2 // Speculative use of out of context branch targets csv2
	csv2_2 // Speculative use of out of context branch targets csv2_2
	csv2_1p1 // Speculative use of out of context branch targets csv2_1p1
	csv2_1p2 // Speculative use of out of context branch targets csv2_1p2
	csv3 // Speculative use of faulting data
	// ID_AA64PFR1_EL1, AArch64 Processor Feature Register 1
	bti // The Branch Target Identification mechanism is implemented
	ssbs // Speculative Store Bypass Safe PSTATE bit
	ssbs2 // Speculative Store Bypassing controls, adds the MSR and MRS instructions
	mte // Instruction-only Memory Tagging Extension is implemented
	mte2 // Full Memory Tagging Extension is implemented
	mte3 // Memory Tagging Extension is implemented with support for asymmetric Tag Check Fault handling
	ras_frac // RAS Extension fractional field
	mpam_frac // The minor version number of the MPAM extension is 0/1
	rndr_trap // Trapping of RNDR and RNDRRS to EL3 is supported
	csv2_frac // CSV2 fractional field
	nmi // Non-maskable Interrupt
	// ID_AA64ISAR0_EL1, AArch64 Instruction Set Attribute Register 0
	aes // Hardware-accelerated Advanced Encryption Standard
	pmull // Polynomial multiply long (PMULL/PMULL2)
	sha1 // Hardware-accelerated SHA1 (SHA1C, etc)
	sha256 // Hardware-accelerated SHA2-256 (SHA256H, etc)
	sha512 // Hardware-accelerated SHA512
	crc32 // Hardware-accelerated CRC-32
	atomics // Armv8.1 atomic instructions
	asimdrdm // Rounding Double Multiply Accumulate/Subtract (SQRDMLAH/SQRDMLSH)
	sha3 // Hardware-accelerated SHA3
	sm3 // Hardware-accelerated SM3
	sm4 // Hardware-accelerated SM4
	asimddp // Dot product instruction
	asimdfhm // Additional half-precision instructions FMLAL and FMLSL instructions
	flagm // Flag manipulation instructions CFINV, RMIF, SETF16, and SETF8 instructions are implemented
	flagm2 // Additional flag manipulation instructions
	tlbios // Outer shareable TLB maintenance instructions are implemented
	tlbirange // Outer shareable and TLB range maintenance instructions are implemented
	rng // True random number generator support
	// ID_AA64ISAR1_EL1, AArch64 Instruction Set Attribute Register 1
	dpb // Data Persistence writeback(DC CVAP)
	dpb2 // Data Persistence writeback(DC CVAP/DC CVADP)
	pacqarma5 // Address Authentication using the QARMA5 algorithm
	apa_pauth // Address Authentication using the QARMA5 algorithm
	apa_epac // Address Authentication using the QARMA5 algorithm
	apa_pauth2 // Address Authentication using the QARMA5 algorithm
	apa_fpac // Address Authentication using the QARMA5 algorithm
	apa_fpaccombine // Address Authentication using the QARMA5 algorithm
	pacimp // IMPLEMENTATION DEFINED algorithm is implemented
	api_pauth // Address Authentication using an IMPLEMENTATION DEFINED algorithm
	api_epac // Address Authentication using an IMPLEMENTATION DEFINED algorithm
	api_pauth2 // Address Authentication using an IMPLEMENTATION DEFINED algorithm
	api_fpac // Address Authentication using an IMPLEMENTATION DEFINED algorithm
	api_fpaccombine // Address Authentication using an IMPLEMENTATION DEFINED algorithm
	jscvt // Support for JavaScript conversion (FJCVTZS)
	fcma // Floating point complex numbers
	lrcpc // Support for weaker release consistency (LDAPR, etc)
	ilrcpc // Additional support for weaker release consistency
	gpa // Generic Authentication using the QARMA5 algorithm
	gpi // Generic Authentication using an IMPLEMENTATION DEFINED algorithm
	frintts // Floating point to integer rounding FRINT32Z, FRINT32X, FRINT64Z, and FRINT64X instructions
	sb // Speculation barrier
	specres // CFP RCTX, DVP RCTX, and CPP RCTX instructions
	bf16 // BFloat16 instructions
	dgh // Data Gathering Hint instruction
	i8mm // Int8 matrix multiplication instructions
	xs // The XS attribute, the TLBI and DSB instructions with the nXS qualifier, and the HCRX_EL2.{FGTnXS, FnXS} fields are supported
	ls64 // LD64B and ST64B instructions
	ls64_v // The LD64B, ST64B, and ST64BV instructions, and their associated traps are supported
	ls64_accdata // The LD64B, ST64B, ST64BV, and ST64BV0 instructions, the ACCDATA_EL1 register, and their associated traps are supported
	// ID_AA64ISAR2_EL1, AArch64 Instruction Set Attribute Register 2
	wfxt // WFET and WFIT are supported
	rpres // 12-bit reciprocal (square root) estimate precision
	gpa3 // Generic Authentication using the QARMA3 algorithm is implemented
	pacqarma3 // The QARMA3 algorithm is implemented
	apa3_pauth // Address Authentication using the QARMA3 algorithm is implemented
	apa3_epac // Address Authentication using the QARMA3 algorithm is implemented
	apa3_pauth2 // Address Authentication using the QARMA3 algorithm is implemented
	apa3_fpac // Address Authentication using the QARMA3 algorithm is implemented
	apa3_fpaccombine // Address Authentication using the QARMA3 algorithm is implemented
	mops // Standardized memory operations
	bc // BC instruction
	constpacfield // ConstPACField() returns TRUE
	// ID_AA64DFR0_EL1, AArch64 Debug Feature Register 0
	debug_v8 // Armv8 debug architecture
	debug_v8_vhe // Armv8 debug architecture with Virtualization Host Extensions
	debug_v8p2 // Armv8.2 debug architecture
	debug_v8p4 // Armv8.4 debug architecture
	debug_v8p8 // Armv8.8 debug architecture
	trace // PE trace unit System registers implemented
	pmu_v3 // Performance Monitors Extension, PMUv3 implemented
	pmu_v3p1 // Performance Monitors Extension, PMUv3.1 implemented
	pmu_v3p4 // Performance Monitors Extension, PMUv3.4 implemented
	pmu_v3p5 // Performance Monitors Extension, PMUv3.5 implemented
	pmu_v3p7 // Performance Monitors Extension, PMUv3.7 implemented
	pmu_v3p8 // Performance Monitors Extension, PMUv3.8 implemented
	spe // Statistical Profiling Extension implemented
	spe_v1p1 // Statistical Profiling Extension 1.1 implemented
	spe_v1p2 // Statistical Profiling Extension 1.2 implemented
	spe_v1p3 // Statistical Profiling Extension 1.3 implemented
	doublelock // OS Double Lock implemented. OSDLR_EL1 is RW
	trf // Armv8.4 Self-hosted Trace Extension implemented
	mtpmu // Multi-threaded PMU extension
	hpmn0 // Zero PMU event counters for a Guest operating system
	// ID_AA64MMFR0_EL1, AArch64 Memory Model Feature Register 0
	pa_range_4g // Physical Address range 4GB
	pa_range_64g // Physical Address range 64GB
	pa_range_1t // Physical Address range 1TB
	pa_range_4t // Physical Address range 4TB
	pa_range_16t // Physical Address range 16TB
	pa_range_256t // Physical Address range 256TB
	pa_range_4p // Physical Address range 4PB
	asid_8 // Number of ASID bits is 8
	asid_16 // Number of ASID bits is 16
	bigend // Mixed-endian support
	snsmem // support for a distinction between Secure and Non-secure Memory
	bigendel0 // Mixed-endian support at EL0
	tgran16 // 16KB granule supported
	tgran64 // 64KB granule supported
	tgran4 // 4KB granule supported
	tgran16_2 // 16KB granule supported at stage 2
	tgran64_2 // 64KB granule supported at stage 2
	tgran4_2 // 4KB granule supported at stage
	exs // support for disabling context synchronizing exception entry and exit
	fgt // The fine-grained trap controls are implemented
	ecv // Enhanced Counter Virtualization
	// ID_AA64MMFR1_EL1, AArch64 Memory Model Feature Register 1
	hafdbs // Hardware update of the Access flag is supported
	vmidbits_8 // Number of VMID bits is 8
	vmidbits_16 // Number of VMID bits is 16
	vh // Virtualization Host Extensions
	hpds // Hierarchical Permission Disables
	hpds2 // Hierarchical Permission Disables 2
	lo // LORegions
	pan // Privileged Access Never
	pan2 // Privileged Access Never 2
	pan3 // Privileged Access Never 3
	specsei // The PE might generate an SError interrupt due to an External abort on a speculative read
	xnx // Distinction between EL0 and EL1 execute-never control at stage 2 supported
	twed // Configurable delayed trapping of WFE is supported
	ets // Enhanced Translation Synchronization is supported
	hcx // HCRX_EL2 and its associated EL3 trap are supported
	afp // Alternate floating-point behaviour
	ntlbpa // support for intermediate caching of translation table walks
	tidcp1 // SCTLR_EL1.TIDCP bit is implemented. If EL2 is implemented, SCTLR_EL2.TIDCP bit is implemented
	cmow // support for cache maintenance instruction permission
	// ID_AA64MMFR2_EL1, AArch64 Memory Model Feature Register 2
	cnp // Common not Private translations supported
	uao // User Access Override
	lsm // LSMAOE and nTLSMD bits supported
	iesb // IESB bit in the SCTLR_ELx registers is supported
	lva // VMSAv8-64 supports 52-bit VAs when using the 64KB translation granule
	ccidx // 64-bit format implemented for all levels of the CCSIDR_EL
	nv // Nested Virtualization
	ttst // support for small translation tables
	uscat // support for unaligned single-copy atomicity and atomic functions
	idst // All exceptions generated by an AArch64 read access to the feature ID space are reported by ESR_ELx.EC == 0x18
	s2fwb // HCR_EL2.FWB is supported
	ttl // support for TTL field in address operations
	bbm_level0 // Level 0 support for changing block size is supported
	bbm_level1 // Level 1 support for changing block size is supported
	bbm_level2 // Level 2 support for changing block size is supported
	evt // Enhanced Virtualization Traps
	e0pd // E0PDx mechanism is implemented
	// ID_AA64ZFR0_EL1, SVE Feature ID register 0
	svebf16 // SVE BFloat16 instructions
	svei8mm // SVE Int8 matrix multiplication instructions
	svef32mm // SVE FP32 matrix multiplication instruction
	svef64mm // SVE FP64 matrix multiplication instructions
	// not used
	cpuid // Some CPU ID registers readable at user-level
	evtstrm // Generic timer
	// Keep it last. It automatically defines the size of feature_set
	last_id
}
```
FeatureID_ARM64 is the ID of an ARM64 CPU feature.

[[Return to contents]](#Contents)

## FeatureID_X86
```v
enum FeatureID_X86 {
	unknown             = -1
	// generated from https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/cpufeatures.h
	// Intel-defined CPU features, CPUID level 0x00000001 (EDX), word 0
	fpu // bit00 Onboard FPU
	vme // bit01 Virtual Mode Extensions
	de // bit02 Debugging Extensions
	pse // bit03 Page Size Extensions
	tsc // bit04 Time Stamp Counter
	msr // bit05 Model-Specific Registers
	pae // bit06 Physical Address Extensions
	mce // bit07 Machine Check Exception
	cx8 // bit08 CMPXCHG8 instruction
	apic // bit09 Onboard APIC
	sep // bit11 SYSENTER/SYSEXIT
	mtrr // bit12 Memory Type Range Registers
	pge // bit13 Page Global Enable
	mca // bit14 Machine Check Architecture
	cmov // bit15 CMOV instructions (plus FCMOVcc, FCOMI with FPU)
	pat // bit16 Page Attribute Table
	pse36 // bit17 36-bit PSEs
	pn // bit18 Processor serial number
	clflush // bit19 CLFLUSH instruction
	dts // bit21 Debug Store
	acpi // bit22 ACPI via MSR
	mmx // bit23 Multimedia Extensions
	fxsr // bit24 FXSAVE/FXRSTOR, CR4.OSFXSR
	sse // bit25
	sse2 // bit26
	ss // bit27 CPU self snoop
	ht // bit28 Hyper-Threading
	tm // bit29 Automatic clock control
	ia64 // bit30 IA-64 processor
	pbe // bit31 Pending Break Enable
	// AMD-defined CPU features, CPUID level 0x80000001, word 1
	syscall // bit11 SYSCALL/SYSRET
	mp // bit19 MP Capable
	nx // bit20 Execute Disable
	mmxext // bit22 AMD MMX extensions
	fxsr_opt // bit25 FXSAVE/FXRSTOR optimizations
	pdpe1gb // bit26 GB pages
	rdtscp // bit27 RDTSCP
	lm // bit29 Long Mode (x86-64, 64-bit support)
	amd_3dnowext // bit30 AMD 3DNow extensions
	amd_3dnow // bit31 3DNow
	// Intel-defined CPU features, CPUID level 0x00000001 (ECX), word 4
	sse3 // bit00 SSE-3
	pclmulqdq // bit01 PCLMULQDQ instruction
	dtes64 // bit02 64-bit Debug Store
	monitor // bit03 MONITOR/MWAIT support
	ds_cpl // bit04 CPL-qualified (filtered) Debug Store
	vmx // bit05 Hardware virtualization
	smx // bit06 Safer Mode eXtensions
	est // bit07 Enhanced SpeedStep
	tm2 // bit08 Thermal Monitor 2
	ssse3 // bit09 Supplemental SSE-3
	cid // bit10 Context ID
	sdbg // bit11 Silicon Debug
	fma // bit12 Fused multiply-add
	cx16 // bit13 CMPXCHG16B instruction
	xtpr // bit14 Send Task Priority Messages
	pdcm // bit15 Perf/Debug Capabilities MSR
	pcid // bit17 Process Context Identifiers
	dca // bit18 Direct Cache Access
	sse4_1 // bit19 SSE-4.1
	sse4_2 // bit20 SSE-4.2
	x2apic // bit21 X2APIC
	movbe // bit22 MOVBE instruction
	popcnt // bit23 POPCNT instruction
	tsc_deadline_timer // bit24 TSC deadline timer
	aes // bit25 AES instructions
	xsave // bit26 XSAVE/XRSTOR/XSETBV/XGETBV instructions
	osxsave // bit27 XSAVE instruction enabled in the OS
	avx // bit28 Advanced Vector Extensions
	f16c // bit29 16-bit FP conversions
	rdrand // bit30 RDRAND instruction
	hypervisor // bit31 Running on a hypervisor
	// More extended AMD flags: CPUID level 0x80000001, ECX, word 6
	lahf_lm // bit00 LAHF/SAHF in long mode
	cmp_legacy // bit01 If yes HyperThreading not valid
	svm // bit02 Secure Virtual Machine
	extapic // bit03 Extended APIC space
	cr8_legacy // bit04 CR8 in 32-bit mode
	abm // bit05 Advanced bit manipulation
	sse4a // bit06 SSE-4A
	misalignsse // bit07 Misaligned SSE mode
	amd_3dnowprefetch // bit08 3DNow prefetch instructions
	osvw // bit09 OS Visible Workaround
	ibs // bit10 Instruction Based Sampling
	xop // bit11 extended AVX instructions
	skinit // bit12 SKINIT/STGI instructions
	wdt // bit13 Watchdog timer
	lwp // bit15 Light Weight Profiling
	fma4 // bit16 4 operands MAC instructions
	tce // bit17 Translation Cache Extension
	nodeid_msr // bit19 NodeId MSR
	tbm // bit21 Trailing Bit Manipulations
	topoext // bit22 Topology extensions CPUID leafs
	perfctr_core // bit23 Core performance counter extensions
	perfctr_nb // bit24 NB performance counter extensions
	bpext // bit26 Data breakpoint extension
	ptsc // bit27 Performance time-stamp counter
	perfctr_llc // bit28 Last Level Cache performance counter extensions
	mwaitx // bit29 MWAIT extension (MONITORX/MWAITX instructions)
	// Intel-defined CPU features, CPUID level 0x00000007:0 (EBX), word 9
	fsgsbase // bit00 RDFSBASE, WRFSBASE, RDGSBASE, WRGSBASE instructions
	tsc_adjust // bit01 TSC adjustment MSR 0x3B
	sgx // bit02 Software Guard Extensions
	bmi1 // bit03 1st group bit manipulation extensions
	hle // bit04 Hardware Lock Elision
	avx2 // bit05 AVX2 instructions
	fdp_excptn_only // bit06 FPU data pointer updated only on x87 exceptions
	smep // bit07 Supervisor Mode Execution Protection
	bmi2 // bit08 2nd group bit manipulation extensions
	erms // bit09 Enhanced REP MOVSB/STOSB instructions
	invpcid // bit10 Invalidate Processor Context ID
	rtm // bit11 Restricted Transactional Memory
	cqm // bit12 Cache QoS Monitoring
	zero_fcs_fds // bit13 Zero out FPU CS and FPU DS
	mpx // bit14 Memory Protection Extension
	rdt_a // bit15 Resource Director Technology Allocation
	avx512f // bit16 AVX-512 Foundation
	avx512dq // bit17 AVX-512 DQ (Double/Quad granular) Instructions
	rdseed // bit18 RDSEED instruction
	adx // bit19 ADCX and ADOX instructions
	smap // bit20 Supervisor Mode Access Prevention
	avx512ifma // bit21 AVX-512 Integer Fused Multiply-Add instructions
	clflushopt // bit23 CLFLUSHOPT instruction
	clwb // bit24 CLWB instruction
	intel_pt // bit25 Intel Processor Trace
	avx512pf // bit26 AVX-512 Prefetch
	avx512er // bit27 AVX-512 Exponential and Reciprocal
	avx512cd // bit28 AVX-512 Conflict Detection
	sha_ni // bit29 SHA1/SHA256 Instruction Extensions
	avx512bw // bit30 AVX-512 BW (Byte/Word granular) Instructions
	avx512vl // bit31 AVX-512 VL (128/256 Vector Length) Extensions
	// Extended state features, CPUID level 0x0000000d:1 (EAX), word 10
	xsaveopt // bit00 XSAVEOPT instruction
	xsavec // bit01 XSAVEC instruction
	xgetbv1 // bit02 XGETBV with ECX = 1 instruction
	xsaves // bit03 XSAVES/XRSTORS instructions
	xfd // bit04 eXtended Feature Disabling
	// Intel-defined CPU features, CPUID level 0x00000007:1 (EAX), word 12
	avx_vnni // bit04 AVX VNNI instructions
	avx512_bf16 // bit05 AVX512 BFLOAT16 instructions
	cmpccxadd // bit07 CMPccXADD instructions
	arch_perfmon_ext // bit08 Intel Architectural PerfMon Extension
	fzrm // bit10 Fast zero-length REP MOVSB
	fsrs // bit11 Fast short REP STOSB
	fsrc // bit12 Fast short REP {CMPSB,SCASB}
	lkgs // bit18
	amx_fp16 // bit21 AMX fp16 Support
	avx_ifma // bit23 Support for VPMADD52[H,L]UQ
	lam // bit26 Linear Address Masking
	// AMD-defined CPU features, CPUID level 0x80000008 (EBX), word 13
	clzero // bit00 CLZERO instruction
	irperf // bit01 Instructions Retired Count
	xsaveerptr // bit02 Always save/restore FP error pointers
	rdpru // bit04 Read processor register at user level
	wbnoinvd // bit09 WBNOINVD instruction
	amd_ibpb // bit12 Indirect Branch Prediction Barrier
	amd_ibrs // bit14 Indirect Branch Restricted Speculation
	amd_stibp // bit15 Single Thread Indirect Branch Predictors
	amd_stibp_always_on // bit17 Single Thread Indirect Branch Predictors always-on preferred
	amd_ppin // bit23 Protected Processor Inventory Number
	amd_ssbd // bit24 Speculative Store Bypass Disable
	virt_ssbd // bit25 Virtualized Speculative Store Bypass Disable
	amd_ssb_no // bit26 Speculative Store Bypass is fixed in hardware.
	cppc // bit27 Collaborative Processor Performance Control
	amd_psfd // bit28 Predictive Store Forwarding Disable
	btc_no // bit29 Not vulnerable to Branch Type Confusion
	brs // bit31 Branch Sampling available
	// Thermal and Power Management Leaf, CPUID level 0x00000006 (EAX), word 14
	dtherm // bit00 Digital Thermal Sensor
	ida // bit01 Intel Dynamic Acceleration
	arat // bit02 Always Running APIC Timer
	pln // bit04 Intel Power Limit Notification
	pts // bit06 Intel Package Thermal Status
	hwp // bit07 Intel Hardware P-states
	hwp_notify // bit08 HWP Notification
	hwp_act_window // bit09 HWP Activity Window
	hwp_epp // bit10 HWP Energy Perf. Preference
	hwp_pkg_req // bit11 HWP Package Level Request
	hfi // bit19 Hardware Feedback Interface
	// AMD SVM Feature Identification, CPUID level 0x8000000a (EDX), word 15
	npt // bit00 Nested Page Table support
	lbrv // bit01 LBR Virtualization support
	svm_lock // bit02 SVM locking MSR
	nrip_save // bit03 SVM next_rip save
	tsc_scale // bit04 TSC scaling support
	vmcb_clean // bit05 VMCB clean bits support
	flushbyasid // bit06 flush-by-ASID support
	decodeassists // bit07 Decode Assists support
	pausefilter // bit10 filtered pause intercept
	pfthreshold // bit12 pause filter threshold
	avic // bit13 Virtual Interrupt Controller
	v_vmsave_vmload // bit15 Virtual VMSAVE VMLOAD
	vgif // bit16 Virtual GIF
	x2avic // bit18 Virtual x2apic
	v_spec_ctrl // bit20 Virtual SPEC_CTRL
	vnmi // bit25 Virtual NMI
	svme_addr_chk // bit28 SVME addr check
	// Intel-defined CPU features, CPUID level 0x00000007:0 (ECX), word 16
	avx512vbmi // bit01 AVX512 Vector Bit Manipulation instructions
	umip // bit02 User Mode Instruction Protection
	pku // bit03 Protection Keys for Userspace
	ospke // bit04 OS Protection Keys Enable
	waitpkg // bit05 UMONITOR/UMWAIT/TPAUSE Instructions
	avx512_vbmi2 // bit06 Additional AVX512 Vector Bit Manipulation Instructions
	shstk // bit07 Shadow stack
	gfni // bit08 Galois Field New Instructions
	vaes // bit09 Vector AES
	vpclmulqdq // bit10 Carry-Less Multiplication Double Quadword
	avx512_vnni // bit11 Vector Neural Network Instructions
	avx512_bitalg // bit12 Support for VPOPCNT[B,W] and VPSHUF-BITQMB instructions
	tme // bit13 Intel Total Memory Encryption
	avx512_vpopcntdq // bit14 POPCNT for vectors of DW/QW
	la57 // bit16 5-level page tables
	rdpid // bit22 RDPID instruction
	bus_lock_detect // bit24 Bus Lock detect
	cldemote // bit25 CLDEMOTE instruction
	movdiri // bit27 MOVDIRI instruction
	movdir64b // bit28 MOVDIR64B instruction
	enqcmd // bit29 ENQCMD and ENQCMDS instructions
	sgx_lc // bit30 Software Guard Extensions Launch Control
	// AMD-defined CPU features, CPUID level 0x80000007 (EBX), word 17
	overflow_recov // bit00 MCA overflow recovery support
	succor // bit01 Uncorrectable error containment and recovery
	smca // bit03 Scalable MCA
	// Intel-defined CPU features, CPUID level 0x00000007:0 (EDX), word 18
	avx512_4vnniw // bit02 AVX-512 Neural Network Instructions
	avx512_4fmaps // bit03 AVX-512 Multiply Accumulation Single precision
	fsrm // bit04 Fast Short Rep Mov
	avx512_vp2intersect // bit08 AVX-512 Intersect for D/Q
	srbds_ctrl // bit09 SRBDS mitigation MSR available
	md_clear // bit10 VERW clears CPU buffers
	rtm_always_abort // bit11 RTM transaction always aborts
	tsx_force_abort // bit13 TSX_FORCE_ABORT
	serialize // bit14 SERIALIZE instruction
	hybrid_cpu // bit15 This part has CPUs of more than one type
	tsxldtrk // bit16 TSX Suspend Load Address Tracking
	pconfig // bit18 Intel PCONFIG
	arch_lbr // bit19 Intel ARCH LBR
	ibt // bit20 Indirect Branch Tracking
	amx_bf16 // bit22 AMX bf16 Support
	avx512_fp16 // bit23 AVX512 FP16
	amx_tile // bit24 AMX tile Support
	amx_int8 // bit25 AMX int8 Support
	spec_ctrl // bit26 Speculation Control (IBRS + IBPB)
	intel_stibp // bit27 Single Thread Indirect Branch Predictors
	flush_l1d // bit28 Flush L1D cache
	arch_capabilities // bit29 IA32_ARCH_CAPABILITIES MSR (Intel)
	core_capabilities // bit30 IA32_CORE_CAPABILITIES MSR
	spec_ctrl_ssbd // bit31 Speculative Store Bypass Disable
	// AMD-defined memory encryption features, CPUID level 0x8000001f (EAX), word 19
	sme // bit00 AMD Secure Memory Encryption
	sev // bit01 AMD Secure Encrypted Virtualization
	vm_page_flush // bit02 VM Page Flush MSR is supported
	sev_es // bit03 AMD Secure Encrypted Virtualization - Encrypted State
	v_tsc_aux // bit09 Virtual TSC_AUX
	sme_coherent // bit10 AMD hardware-enforced cache coherency
	debug_swap // bit14 AMD SEV-ES full debug state swap support
	// AMD-defined Extended Feature 2 EAX, CPUID level 0x80000021 (EAX), word 20
	no_nested_data_bp // bit00 No Nested Data Breakpoints
	wrmsr_xx_base_ns // bit01 WRMSR to {FS,GS,KERNEL_GS}_BASE is non-serializing
	lfence_rdtsc // bit02 LFENCE always serializing / synchronizes RDTSC
	null_sel_clr_base // bit06 Null Selector Clears Base
	autoibrs // bit08 Automatic IBRS
	no_smm_ctl_msr // bit09 SMM_CTL MSR is not present
	sbpb // bit27 Selective Branch Prediction Barrier
	ibpb_brtype // bit28 MSR_PRED_CMD[IBPB] flushes all branch type predictions
	srso_no // bit29 CPU is not affected by SRSO
	// Keep it last. It automatically defines the size of feature_set
	last_id
}
```
FeatureID_X86 is the ID of a X86 CPU feature.

[[Return to contents]](#Contents)

## Vendor_ARM64
```v
enum Vendor_ARM64 {
	vendor_unknown
	ampere
	arm
	broadcom
	cavium
	dec
	fujitsu
	infineon
	intel
	motorola
	nvidia
	amcc
	qualcomm
	marvell
	phytium
}
```
vfmt off Vendor_ARM64 is a representation of an ARM64 CPU vendor.

[[Return to contents]](#Contents)

## Vendor_X86
```v
enum Vendor_X86 {
	vendor_unknown
	intel
	amd
	via
	transmeta
	nsc
	kvm // Kernel-based Virtual Machine
	msvm // Microsoft Hyper-V or Windows Virtual PC
	vmware
	xenhvm
	bhyve
	hygon
	sis
	rdc
}
```
vfmt off Vendor_X86 is a representation of a X86 CPU vendor.

[[Return to contents]](#Contents)

## AArch64Features
```v
struct AArch64Features {
pub mut:
	midr_el1         u64 // MIDR_EL1, Main ID Register
	id_aa64dfr0_el1  u64 // AArch64 Debug Feature Register 0
	id_aa64dfr1_el1  u64 // AArch64 Debug Feature Register 1
	id_aa64isar0_el1 u64 // AArch64 Instruction Set Attribute Register 0
	id_aa64isar1_el1 u64 // AArch64 Instruction Set Attribute Register 1
	id_aa64isar2_el1 u64 // AArch64 Instruction Set Attribute Register 2
	id_aa64mmfr0_el1 u64 // AArch64 Memory Model Feature Register 0
	id_aa64mmfr1_el1 u64 // AArch64 Memory Model Feature Register 1
	id_aa64mmfr2_el1 u64 // AArch64 Memory Model Feature Register 2
	id_aa64pfr0_el1  u64 // AArch64 Processor Feature Register 0
	id_aa64pfr1_el1  u64 // AArch64 Processor Feature Register 1
	id_aa64zfr0_el1  u64 // SVE Feature ID register 0
}
```
vfmt on

[[Return to contents]](#Contents)

## AMDMemEncryptionSupport
[[Return to contents]](#Contents)

## CPUInfo_ARM64
```v
struct CPUInfo_ARM64 {
pub mut:
	vendor_id        Vendor_ARM64      // Comparable CPU vendor ID
	vendor_string    string            // Raw vendor string.
	feature_set      bitfield.BitField // Features of the CPU
	physical_cores   int // Number of physical processor cores in your CPU. Will be 0 if undetectable.
	threads_per_core int = 1 // Number of threads per physical core. Will be 1 if undetectable.
	logical_cores    int // Number of physical cores times threads that can run on each core through the use of hyperthreading. Will be 0 if undetectable.
	variant          int // CPU variant number
	architecture     int // CPU architecture number
	part_num         int // Primary Part Number for the device
	revision         int // Revision number for the device
	cache_line       int // Cache line size in bytes. Will be 0 if undetectable.
	hz               i64 // Clock speed, if known, 0 otherwise. Will attempt to contain base clock speed.
	boost_freq       i64 // Max clock speed, if known, 0 otherwise
	cache            struct {
	pub mut:
		l1i int = -1 // L1 Instruction Cache (per core or shared). Will be -1 if undetected
		l1d int = -1 // L1 Data Cache (per core or shared). Will be -1 if undetected
		l2  int = -1 // L2 Cache (per core or shared). Will be -1 if undetected
		l3  int = -1 // L3 Cache (per core, per ccx or shared). Will be -1 if undetected
	}

	aarch64 AArch64Features
}
```
CPUInfo_ARM64 contains information about the detected system CPU. If system have multiple cores, the CPUInfo_ARM64 only contains information of the core which current process running on.

[[Return to contents]](#Contents)

## has
```v
fn (mut c CPUInfo_ARM64) has(ids ...FeatureID_ARM64) bool
```
has returns whether the CPU supports one or more of the requested features.

[[Return to contents]](#Contents)

## all
```v
fn (mut c CPUInfo_ARM64) all(ids ...FeatureID_ARM64) bool
```
all returns whether the CPU supports all of the requested features.

[[Return to contents]](#Contents)

## feature_set
```v
fn (c CPUInfo_ARM64) feature_set() []string
```
feature_set returns all available features as strings.

[[Return to contents]](#Contents)

## CPUInfo_X86
```v
struct CPUInfo_X86 {
pub mut:
	brand_name       string            // Brand name reported by the CPU
	vendor_id        Vendor_X86        // Comparable CPU vendor ID
	vendor_string    string            // Raw vendor string.
	feature_set      bitfield.BitField // Features of the CPU
	physical_cores   int // Number of physical processor cores in your CPU. Will be 0 if undetectable.
	threads_per_core int = 1 // Number of threads per physical core. Will be 1 if undetectable.
	logical_cores    int // Number of physical cores times threads that can run on each core through the use of hyperthreading. Will be 0 if undetectable.
	family           int // CPU family number
	model            int // CPU model number
	stepping         int // CPU stepping info
	cache_line       int // Cache line size in bytes. Will be 0 if undetectable.
	hz               i64 // Clock speed, if known, 0 otherwise. Will attempt to contain base clock speed.
	boost_freq       i64 // Max clock speed, if known, 0 otherwise
	cache            struct {
	pub mut:
		l1i int = -1 // L1 Instruction Cache (per core or shared). Will be -1 if undetected
		l1d int = -1 // L1 Data Cache (per core or shared). Will be -1 if undetected
		l2  int = -1 // L2 Cache (per core or shared). Will be -1 if undetected
		l3  int = -1 // L3 Cache (per core, per ccx or shared). Will be -1 if undetected
	}

	sgx                SGXSupport
	amd_mem_encryption AMDMemEncryptionSupport
	max_func           u32
	max_ex_func        u32
}
```
CPUInfo_X86 contains information about the detected system CPU. If system have multiple cores, the CPUInfo_X86 only contains information of the core which current process running on.

[[Return to contents]](#Contents)

## has
```v
fn (mut c CPUInfo_X86) has(ids ...FeatureID_X86) bool
```
has returns whether the CPU supports one or more of the requested features.

[[Return to contents]](#Contents)

## all
```v
fn (mut c CPUInfo_X86) all(ids ...FeatureID_X86) bool
```
all returns whether the CPU supports all of the requested features.

[[Return to contents]](#Contents)

## x86_level
```v
fn (mut c CPUInfo_X86) x86_level() int
```
x86_level returns the microarchitecture level detected on the CPU. If features are lacking or non amd64 mode, 0 is returned. See https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels See https://github.com/Jordan-JD-Peterson/x86-64-level/blob/develop/README.md

[[Return to contents]](#Contents)

## feature_set
```v
fn (c CPUInfo_X86) feature_set() []string
```
feature_set returns all available features as strings.

[[Return to contents]](#Contents)

## rt_counter
```v
fn (mut c CPUInfo_X86) rt_counter() u64
```
rt_counter returns the 64-bit time-stamp counter Uses the RDTSCP instruction. The value 0 is returned if the CPU does not support the instruction.

[[Return to contents]](#Contents)

## ia32_tsc_aux
```v
fn (mut c CPUInfo_X86) ia32_tsc_aux() u32
```
ia32_tsc_aux returns the IA32_TSC_AUX part of the RDTSCP. This variable is OS dependent, but on Linux contains information about the current cpu/core the code is running on. If the RDTSCP instruction isn't supported on the CPU, the value 0 is returned.

[[Return to contents]](#Contents)

## logical_cpu
```v
fn (c CPUInfo_X86) logical_cpu() int
```
logical_cpu will return the Logical CPU the code is currently executing on. This is likely to change when the OS re-schedules the running thread to another CPU. If the current core cannot be detected, -1 will be returned.

[[Return to contents]](#Contents)

## frequencies
```v
fn (mut c CPUInfo_X86) frequencies()
```
frequencies tries to compute the clock speed of the CPU. If leaf 15 is supported, use it, otherwise parse the brand string. Yes, really.

[[Return to contents]](#Contents)

## vm
```v
fn (mut c CPUInfo_X86) vm() bool
```
vm Will return true if the cpu id indicates we are in a virtual machine.

[[Return to contents]](#Contents)

## SGXEPCSection
[[Return to contents]](#Contents)

## SGXSupport
[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 2 Feb 2024 11:21:24
