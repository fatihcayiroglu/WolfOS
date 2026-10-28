"""Offline source-contract checks. Not a replacement for QEMU boot tests."""
from pathlib import Path
import unittest
import tomllib

ROOT = Path(__file__).resolve().parent.parent

class WolfP0ContractTests(unittest.TestCase):
    def test_rust_kernel_no_std(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        self.assertIn("#![no_std]", main)
        self.assertIn("#![no_main]", main)
        self.assertIn('extern "C" fn kmain()', main)
        self.assertIn("#[panic_handler]", main)

    def test_limine_request_markers_not_garbage_collected(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        linker = (ROOT / "kernel/arch/x86_64/linker.ld").read_text()
        for section in (".requests_start_marker", ".requests", ".requests_end_marker"):
            self.assertIn(section, main)
            self.assertIn(f"KEEP(*({section}))", linker)
        self.assertIn("ENTRY(kmain)", linker)

    def test_expected_boot_markers(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        for marker in ("WOLFOS_LIMINE_OK", "WOLFOS_MEMMAP_OK", "WOLFOS_FRAMEBUFFER_OK", "WOLFOS_BOOT_OK"):
            self.assertIn(marker, main)
        cpu = (ROOT / "kernel/src/cpu.rs").read_text()
        self.assertIn("WOLFOS_CPU_OK", cpu)
        self.assertIn("WOLFOS_CPU_OK", (ROOT / "scripts/smoke.py").read_text())
        self.assertIn("returncode != 33", (ROOT / "scripts/smoke.py").read_text())

    def test_physical_frame_allocator_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        pmm = (ROOT / "kernel/src/pmm.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("pmm::initialize(entries, hhdm.offset)", main)
        self.assertIn("HhdmRequest", main)
        self.assertIn("WOLFOS_PMM_TEST_OK", main)
        self.assertIn("WOLFOS_PMM_TEST_OK", smoke)
        self.assertIn("MEMMAP_USABLE", pmm)
        self.assertIn("DoubleFree", pmm)
        self.assertIn("10_000", pmm)
        self.assertIn("metadata_frames", pmm)
        self.assertIn("NoContiguousMetadataRegion", pmm)
        self.assertIn("MetadataReserved", pmm)
        self.assertNotIn("BITMAP_BYTES", pmm)
        self.assertNotIn("MAX_FRAMES", pmm)
        self.assertIn("WOLFOS_PMM_DYNAMIC_OK", smoke)
        self.assertIn("unsafe impl Sync", pmm)

    def test_gdt_idt_and_exception_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        intr = (ROOT / "kernel/src/interrupts.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        exception = (ROOT / "scripts/exception_smoke.py").read_text()
        self.assertIn("#![feature(abi_x86_interrupt)]", main)
        self.assertIn("interrupts::initialize()", main)
        for code in ("Descriptor::tss_segment", "load_tss(tss_sel)", "idt_ref.load()",
                     "set_stack_index(DOUBLE_FAULT_IST_INDEX)", "fn double_fault",
                     "fn page_fault", "fn general_protection_fault", "fn invalid_opcode"):
            self.assertIn(code, intr)
        for marker in ("WOLFOS_GDT_OK", "WOLFOS_IDT_OK",
                       "WOLFOS_EXCEPTION_BP vector=3", "WOLFOS_BREAKPOINT_RETURN_OK"):
            self.assertIn(marker, smoke)
        self.assertIn("WOLFOS_EXCEPTION_UD vector=6", exception)
        self.assertIn("run.returncode != 33", exception)
        self.assertIn("exception-smoke:", (ROOT / "Makefile").read_text())

    def test_pci_discovery_is_read_only(self):
        pci = (ROOT / "kernel/src/pci.rs").read_text()
        main = (ROOT / "kernel/src/main.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("pci::discover()", main)
        for marker in ("WOLFOS_GPU_DETECTED", "WOLFOS_PCI_OK", "WOLFOS_PCI_TEST_OK"):
            self.assertIn(marker, smoke)
        for symbol in ("CONFIG_ADDRESS", "CONFIG_DATA", "0x8000_0000u32",
                       "vendor == 0xffff", "0x03 =>"):
            self.assertIn(symbol, pci)
        self.assertNotIn("CONFIG_DATA, in(", pci)
        self.assertIn('"-vga", "std"', smoke)

    def test_paging_acceptance_contract(self):
        kernel = (ROOT / "kernel/src/main.rs").read_text()
        paging = (ROOT / "kernel/src/paging.rs").read_text()
        interrupt = (ROOT / "kernel/src/interrupts.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        fault = (ROOT / "scripts/paging_fault_smoke.py").read_text()
        self.assertIn("paging::mapping_roundtrip(hhdm.offset)", kernel)
        self.assertIn("paging::trigger_unmapped_read()", kernel)
        for symbol in ("Cr3::read()", "OffsetPageTable::new", "mapper.map_to",
                       "mapper.unmap", "flush.flush()", "pmm::free_frame"):
            self.assertIn(symbol, paging)
        self.assertIn("0x0000_4000_0000_0000", paging)
        self.assertIn("WOLFOS_PAGING_MAP_OK", smoke)
        self.assertIn("WOLFOS_PAGING_UNMAP_OK", smoke)
        self.assertIn("WOLFOS_PAGING_FAULT_OK", interrupt)
        self.assertIn("WOLFOS_EXCEPTION_PF vector=14", fault)
        self.assertIn("run.returncode != 33", fault)
        self.assertIn("paging-fault-smoke:", (ROOT / "Makefile").read_text())

    def test_acpi_rsdp_contract(self):
        kernel = (ROOT / "kernel/src/main.rs").read_text()
        acpi = (ROOT / "kernel/src/acpi.rs").read_text()
        parser = (ROOT / "kernel/src/acpi_layout.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("RsdpRequest", kernel)
        self.assertIn("acpi::report_rsdp(rsdp_response.address)", kernel)
        self.assertIn("WOLFOS_ACPI_RSDP_OK", acpi)
        self.assertIn("WOLFOS_ACPI_RSDP_OK", smoke)
        self.assertIn('b"RSD PTR "', parser)
        self.assertIn("BadChecksum", parser)
        self.assertIn("BadExtendedChecksum", parser)
        self.assertIn("acpi_layout_tests", (ROOT / "Makefile").read_text())

    def test_acpi_topology_parser_contract(self):
        kernel = (ROOT / "kernel/src/main.rs").read_text()
        walker = (ROOT / "kernel/src/acpi_walk.rs").read_text()
        parser = (ROOT / "kernel/src/acpi_tables.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("acpi_walk::discover(acpi_info, hhdm.offset, entries)", kernel)
        self.assertIn("allowed_firmware_region", walker)
        self.assertIn("MEMMAP_ACPI_RECLAIMABLE", walker)
        self.assertIn("WOLFOS_ACPI_ROOT_OK", walker)
        self.assertIn("WOLFOS_ACPI_MADT_OK", walker)
        self.assertIn("WOLFOS_ACPI_ROOT_OK", smoke)
        self.assertIn("WOLFOS_ACPI_MADT_OK", smoke)
        self.assertIn("fn parse_madt", parser)
        self.assertIn("InvalidMadtEntry", parser)
        self.assertIn("acpi_tables_tests", (ROOT / "Makefile").read_text())

    def test_four_cpu_topology_acceptance(self):
        script = (ROOT / "scripts/topology_smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        workflow = (ROOT / ".github/workflows/p0.yml").read_text()
        self.assertIn('"-smp", "4,sockets=1,cores=4,threads=1"', script)
        self.assertIn("WOLFOS_ACPI_MADT_OK enabled_cpus=", script)
        self.assertIn("WOLFOS_BOOT_OK", script)
        self.assertIn("EXPECTED_CPUS = 4", script)
        self.assertIn("topology-smoke:", make)
        self.assertIn("make topology-smoke", workflow)

    def test_secondary_cpu_rust_handoff_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("MpRequest::new(0)", main)
        self.assertIn("smp::boot_aps(mp)", main)
        self.assertIn("WOLFOS_SMP_APS_OK", smp)
        self.assertIn("cpu.bootstrap(secondary_entry", smp)
        self.assertIn("Ordering::Release", smp)
        self.assertIn("Ordering::Acquire", smp)
        self.assertIn("interrupts::disable()", smp)
        self.assertIn("WOLFOS_SMP_APS_OK total=1", smoke)
        self.assertIn("aps != EXPECTED_CPUS - 1", topo)

    def test_secondary_core_descriptor_isolation(self):
        intr = (ROOT / "kernel/src/interrupts.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("pub fn initialize_secondary(index: usize)", intr)
        self.assertIn("AP_TSS[index].initialize(tss)", intr)
        self.assertIn("AP_GDT[index].initialize(gdt)", intr)
        self.assertIn("AP_IST_BANK", intr)
        self.assertIn("IDT_READY.store(true, Ordering::Release)", intr)
        self.assertIn("IDT_READY.load(Ordering::Acquire)", intr)
        self.assertIn("idt_ref.load();", intr)
        self.assertIn("crate::interrupts::initialize_secondary(index)", smp)
        self.assertIn("WOLFOS_SMP_PERCPU_OK", smp)
        self.assertIn("WOLFOS_SMP_PERCPU_OK total=4 ap_tables=3", topo)
        self.assertIn("WOLFOS_SMP_PERCPU_OK total=1 ap_tables=0", smoke)

    def test_ap_private_idt_and_breakpoint_return(self):
        intr = (ROOT / "kernel/src/interrupts.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("static AP_IDT: [BootCell<InterruptDescriptorTable>; MAX_BOOT_CPUS]", intr)
        self.assertIn("AP_IDT[index].initialize(idt)", intr)
        self.assertIn("idt_ref.load()", intr)
        self.assertIn("interrupts::int3()", intr)
        self.assertIn("AP_BREAKPOINTS.fetch_add", intr)
        self.assertIn("ap_breakpoint_count()", smp)
        self.assertIn("WOLFOS_SMP_AP_IDT_OK", smp)
        self.assertIn("ap_bp_returns=", topo)
        self.assertIn("WOLFOS_SMP_AP_IDT_OK total=1", smoke)

    def test_ap_stack_and_parallel_work_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        stacks = (ROOT / "kernel/src/ap_stack.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("mod ap_stack;", main)
        self.assertIn("KERNEL_STACK_SIZE: usize = 32 * 1024", stacks)
        self.assertIn("global_asm!", stacks)
        self.assertIn("mov rsp, rdx", stacks)
        self.assertIn("call wolfos_ap_stack_rust", stacks)
        self.assertIn("prepared_top(index)", smp)
        self.assertIn("ap_stack::verify_active(index)", smp)
        self.assertIn("AP_READY[index].store", smp)
        self.assertIn("START_WORK.store(true, Ordering::Release)", smp)
        self.assertIn("AP_DONE[index].store", smp)
        self.assertIn("WOLFOS_SMP_STACK_OK", smp)
        self.assertIn("WOLFOS_SMP_WORK_OK", smp)
        self.assertIn("WOLFOS_SMP_STACK_OK total=1", smoke)
        self.assertIn("WOLFOS_SMP_WORK_OK total=1", smoke)
        self.assertIn(r"stack_kib=(\d+)", topo)
        self.assertIn(r"rounds=(\d+)", topo)

    def test_cooperative_job_dispatcher_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        queue = (ROOT / "kernel/src/scheduler.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn("mod scheduler;", main)
        self.assertIn("pub const JOB_COUNT: usize = 512", queue)
        self.assertIn("compare_exchange(", queue)
        self.assertIn("self.next.fetch_add(1", queue)
        self.assertIn("self.states[id].load(Ordering::Acquire)", queue)
        self.assertIn("self.completed.load(Ordering::Acquire) != JOB_COUNT", queue)
        self.assertIn("scheduler::BOOT_QUEUE.configure(cpus.len())", smp)
        self.assertIn("scheduler::BOOT_QUEUE.run_worker(index)", smp)
        self.assertIn("scheduler::BOOT_QUEUE.run_worker(bsp_index)", smp)
        self.assertIn("scheduler::BOOT_QUEUE.verify(bsp_index)", smp)
        self.assertIn("WOLFOS_SCHED_OK tasks=", smp)
        self.assertIn("WOLFOS_SCHED_OK tasks=512 cpus=1", smoke)
        self.assertIn("WOLFOS_SCHED_OK tasks=", topo)
        self.assertIn("scheduler_tests", make)

    def test_thread_lifecycle_and_per_cpu_queues(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        scheduler = (ROOT / "kernel/src/thread_scheduler.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn("mod thread_scheduler;", main)
        for marker in ("struct Thread", "struct PerCpuQueue", "enum ThreadState",
                       "Ready,", "Running,", "Blocked,", "Finished,",
                       "fn run_step(", "fn push_ready(", "fn push_blocked(",
                       "fn pop_ready(", "fn pop_blocked(", "fn verify(&self)"):
            self.assertIn(marker, scheduler)
        self.assertIn("thread_scheduler::BOOT_TASKS.configure(cpus.len())", smp)
        self.assertIn("thread_scheduler::BOOT_TASKS.run_cpu(index)", smp)
        self.assertIn("thread_scheduler::BOOT_TASKS.run_cpu(bsp_index)", smp)
        self.assertIn("thread_scheduler::BOOT_TASKS.verify()", smp)
        self.assertIn("WOLFOS_THREADS_OK threads=", smp)
        self.assertIn("WOLFOS_THREADS_OK threads=256 cpus=1", smoke)
        self.assertIn("WOLFOS_THREADS_OK threads=", topo)
        self.assertIn("thread_scheduler_tests", make)

    def test_real_bsp_context_switch_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        module = (ROOT / "kernel/src/context_switch.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topology = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("mod context_switch;", main)
        self.assertIn("context_switch::verify_roundtrip()", main)
        self.assertIn('".global wolfos_switch_context"', module)
        for instruction in ("push rbx", "push rbp", "push r12", "push r13",
                            "push r14", "push r15", "mov [rdi], rsp",
                            "mov rsp, [rsi]", "pop r15", "pop rbx", '"ret"'):
            self.assertIn(instruction, module)
        self.assertIn("switch(&BSP_RSP, &A_RSP)", module)
        self.assertIn("switch(&B_RSP, &BSP_RSP)", module)
        self.assertIn("WOLFOS_CONTEXT_ERROR incorrect_resume_order", module)
        self.assertIn("WOLFOS_CONTEXT_OK tasks=2 switches=", module)
        for expected in ("WOLFOS_CONTEXT_OK tasks=2 switches=7 events=6 stacks_kib=16",):
            self.assertIn(expected, smoke)
            self.assertIn(expected, topology)

    def test_context_backed_kernel_thread_tcbs(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        raw = (ROOT / "kernel/src/context_switch.rs").read_text()
        threads = (ROOT / "kernel/src/kernel_threads.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topology = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("mod kernel_threads;", main)
        self.assertIn("kernel_threads::verify()", main)
        self.assertIn("pub(crate) unsafe fn switch_raw", raw)
        self.assertIn("const WORDS: usize = 8", raw)
        self.assertIn("const FRAME_WORDS: usize = 8", threads)
        for symbol in ("struct Tcb", "saved_rsp: usize", "ThreadState::Ready",
                       "ThreadState::Running", "ThreadState::Blocked",
                       "ThreadState::Finished", "fn enqueue(", "fn dequeue(",
                       "fn wake_if_due(", "fn context_to_bsp(", "fn thread_body(",
                       "context_switch::switch_raw", "EXPECTED_EVENTS",
                       "WOLFOS_KTHREAD_ERROR scheduling_or_resume",
                       "WOLFOS_KTHREAD_OK threads=3"):
            self.assertIn(symbol, threads)
        marker = "WOLFOS_KTHREAD_OK threads=3 dispatches=9 switches=18 yields=5 blocked=1 woken=1 finished=3 stack_kib=16"
        self.assertIn(marker, smoke)
        self.assertIn(marker, topology)

    def test_generic_context_backed_task_batch(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        source = (ROOT / "kernel/src/context_batch.rs").read_text()
        old_threads = (ROOT / "kernel/src/kernel_threads.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("mod context_batch;", main)
        self.assertIn("context_batch::verify()", main)
        self.assertIn("pub const CONTEXT_TASKS: usize = 256", source)
        self.assertIn("MAX_STACK_BANK_BYTES: usize = 4 * 1024 * 1024", source)
        self.assertIn("const _: () = assert!(STACK_BANK_BYTES <= MAX_STACK_BANK_BYTES)", source)
        self.assertIn("saved_stack_pointer_ok(id, tcb.saved_rsp)", source)
        self.assertIn("use crate::thread_scheduler::{ThreadState, THREAD_COUNT};", source)
        for expected in ("struct Tcb", "saved_rsp: usize",
                         "wolfos_batch_thread_start", "wolfos_batch_rust_entry",
                         '"mov rdi, r12"', '"sub rsp, 8"',
                         "const FRAME_WORDS: usize = 8",
                         ".add(3).write(id)", ".add(6).write(",
                         "ThreadState::Blocked", "fn wake_if_due",
                         "context_switch::switch_raw",
                         "WOLFOS_CTX_BATCH_ERROR scheduling_or_resume"):
            self.assertIn(expected, source)
        marker = "WOLFOS_CTX_BATCH_OK threads=256 dispatches=1024 switches=2048 yields=767 blocked=1 woken=1 finished=256 stack_kib=16 bank_kib=4096"
        self.assertIn(marker, smoke)
        self.assertIn(marker, topo)
        self.assertIn("WOLFOS_KTHREAD_OK threads=3", old_threads)

    def test_real_per_cpu_context_switches(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        module = (ROOT / "kernel/src/percpu_context.rs").read_text()
        assembly = (ROOT / "kernel/src/context_switch.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topology = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("mod percpu_context;", main)
        self.assertIn("percpu_context::run(index)", smp)
        self.assertIn("percpu_context::run(bsp_index)", smp)
        self.assertIn("percpu_context::verify_all(cpus.len())", smp)
        self.assertIn("WOLFOS_SMP_CTX_OK", smp)
        self.assertIn("pub const MAX_BANK_KIB", module)
        self.assertIn("const _: () = assert!(BANK_BYTES <= MAX_BANK_BYTES)", module)
        self.assertIn("MAX_BOOT_CPUS", module)
        for marker in ("struct CpuRun", "struct CpuSlot", "unsafe impl Sync for CpuSlot",
                       "wolfos_percpu_context_start", "wolfos_percpu_context_rust",
                       '"mov rdi, r12"', '"mov rsi, r13"', "const WORDS: usize = 8",
                       "ThreadState::Blocked", "ThreadState::Finished",
                       "context_switch::switch_raw", "resume_pointer_ok",
                       "check_cpu(cpu, true)", "pub fn run(cpu: usize) -> bool"):
            self.assertIn(marker, module)
        self.assertIn("Calls on distinct CPUs may", assembly)
        self.assertIn("WOLFOS_SMP_CTX_OK cpus=1 active=1 threads=2 switches=12", smoke)
        self.assertIn("WOLFOS_SMP_CTX_OK cpus=4 active=4 threads=8 switches=48", topology)

    def test_isolated_hardware_timer_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        intr = (ROOT / "kernel/src/interrupts.rs").read_text()
        timer = (ROOT / "kernel/src/timer.rs").read_text()
        smoke = (ROOT / "scripts/timer_smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn('#[cfg(feature = "timer-smoke")]', main)
        self.assertIn("timer::verify()", main)
        self.assertIn("idt[crate::timer::TIMER_VECTOR].set_handler_fn", intr)
        self.assertIn('pub extern "x86-interrupt" fn irq0', timer)
        self.assertIn("TIMER_TICKS.fetch_add", timer)
        self.assertIn("outb(MASTER_COMMAND, 0x20)", timer)
        self.assertIn("WOLFOS_TIMER_IRQ_OK", timer)
        self.assertIn("WOLFOS_TIMER_IRQ_OK", smoke)
        self.assertIn("run.returncode != 33", smoke)
        self.assertIn("timer-smoke:", make)
        self.assertIn("make timer-smoke", (ROOT / ".github/workflows/p0.yml").read_text())

    def test_hardware_timer_gated_context_switch_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        timer = (ROOT / "kernel/src/timer.rs").read_text()
        tasks = (ROOT / "kernel/src/timer_tasks.rs").read_text()
        acceptance = (ROOT / "scripts/timer_smoke.py").read_text()
        self.assertIn("mod timer_tasks;", main)
        self.assertIn("crate::timer_tasks::verify()", timer)
        self.assertIn("pub fn ticks()", timer)
        self.assertIn("WOLFOS_TIMER_TASKS_OK", timer)
        self.assertIn("preemptive=0", timer)
        for mark in ("wolfos_tick_worker_start", "wolfos_tick_worker_rust",
                     "context_switch::switch_raw", "FRAME_WORDS: usize = 8",
                     "timer::ticks()", "interrupts::enable()", "interrupts::disable()",
                     "s.events != [0, 1, 0, 1, 0, 1]", "const STACK_BYTES: usize = 16 * 1024"):
            self.assertIn(mark, tasks)
        self.assertIn("WOLFOS_TIMER_TASKS_OK", acceptance)
        self.assertIn("tuple(map(int, tasks.groups())) != (2, 6, 12, 16, 1, 0)", acceptance)

    def test_local_apic_msr_identity_read_only(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        probe = (ROOT / "kernel/src/lapic_probe.rs").read_text()
        layout = (ROOT / "kernel/src/lapic_layout.rs").read_text()
        single = (ROOT / "scripts/smoke.py").read_text()
        four = (ROOT / "scripts/topology_smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn("mod lapic_probe;", main)
        self.assertIn("mod lapic_layout;", main)
        self.assertIn("lapic_probe::capture(index, info.lapic_id, false)", smp)
        self.assertIn("lapic_probe::capture(bsp_index, mp.bsp_lapic_id, true)", smp)
        self.assertIn("lapic_probe::verify(cpus, bsp_index)", smp)
        self.assertIn("WOLFOS_LAPIC_ID_OK", smp)
        self.assertIn("WOLFOS_LAPIC_ID_OK cpus=1 verified=1", single)
        self.assertIn("WOLFOS_LAPIC_ID_OK", four)
        self.assertIn('asm!("rdmsr"', probe)
        self.assertNotIn('asm!("wrmsr"', probe)
        self.assertIn("IA32_APIC_BASE_MSR", layout)
        self.assertIn("GlobalApicDisabled", layout)
        self.assertIn("lapic_layout_tests", make)

    def test_readonly_uncached_xapic_mmio_probe(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        probe = (ROOT / "kernel/src/lapic_probe.rs").read_text()
        mmio = (ROOT / "kernel/src/lapic_mmio.rs").read_text()
        layout = (ROOT / "kernel/src/lapic_mmio_layout.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topology = (ROOT / "scripts/topology_smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn("mod lapic_mmio;", main)
        self.assertIn("lapic_mmio::verify_bsp(mp.bsp_lapic_id, hhdm.offset, entries)", main)
        self.assertLess(main.index("lapic_mmio::verify_bsp"), main.index("smp::boot_aps(mp)"))
        self.assertIn("pub fn bsp_mmio_base(", probe)
        for symbol in ("Cr3::read()", "OffsetPageTable::new", "mapper.map_to",
                       "mapper.unmap", "flush.flush()", "PageTableFlags::NO_CACHE",
                       "PageTableFlags::WRITE_THROUGH", "read_volatile()",
                       "safe_mmio_region", "MEMMAP_USABLE", "WOLFOS_LAPIC_MMIO_OK"):
            self.assertIn(symbol, mmio)
        self.assertNotIn("write_volatile()", mmio)
        self.assertIn("pub fn decode_version(", layout)
        self.assertIn("WOLFOS_LAPIC_MMIO_OK", smoke)
        self.assertIn("WOLFOS_LAPIC_MMIO_OK", topology)
        self.assertIn("lapic_mmio_layout_tests", make)

    def test_lapic_timer_layout_contract(self):
        parser = (ROOT / "kernel/src/lapic_timer_layout.rs").read_text()
        make = (ROOT / "Makefile").read_text()
        main = (ROOT / "kernel/src/main.rs").read_text()
        self.assertIn("mod lapic_timer_layout;", main)
        for symbol in ("LVT_TIMER_OFFSET", "INITIAL_COUNT_OFFSET",
                       "CURRENT_COUNT_OFFSET", "DIVIDE_CONFIG_OFFSET",
                       "fn encode_divisor", "fn decode_divisor",
                       "fn parse_lvt", "fn make_lvt",
                       "ReservedBits", "InvalidMode", "ZeroInitialCount"):
            self.assertIn(symbol, parser)
        self.assertIn("lapic_timer_layout_tests", make)
        self.assertNotIn("write_volatile", parser)
        self.assertNotIn("wrmsr", parser)

    def test_reproducible_manifest(self):
        m = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(m["package"]["edition"], "2024")
        self.assertEqual(m["bin"][0]["path"], "kernel/src/main.rs")
        self.assertEqual(m["dependencies"]["limine"], "=0.6.5")
        self.assertEqual(m["profile"]["release"]["panic"], "abort")
        self.assertIn("smoke-exit", m["features"])

    def test_never_targets_real_disks(self):
        make = (ROOT / "Makefile").read_text()
        for forbidden in ("dd if=", "sgdisk ", "wipefs ", "mkfs.", "of=/dev/"):
            self.assertNotIn(forbidden, make)
        self.assertIn("xorriso", make)
        self.assertIn("-cdrom", make)

    def test_boot_path_matches_iso(self):
        conf = (ROOT / "boot/limine.conf").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn("kernel_path: boot():/boot/wolfos-kernel", conf)
        self.assertIn("/boot/wolfos-kernel", make)
        self.assertIn("wolfos-smoke.iso", (ROOT / "scripts/smoke.py").read_text())

if __name__ == "__main__":
    unittest.main()
