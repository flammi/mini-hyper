extern crate kvm_ioctls;
extern crate kvm_bindings;

use kvm_ioctls::VcpuExit;
use kvm_ioctls::Kvm;
use bitflags::bitflags;
use bitvec::prelude::*;
use capstone::prelude::*;
//use std::io::Read;

const GDT_BASE_ADDR : u64 = 0x1000;
const IDT_BASE_ADDR : u64 = 0x2000;

bitflags! {
    /// Possible flags for a page table entry.
    pub struct PageTableFlags: u64 {
        /// Specifies whether the mapped frame or page table is loaded in memory.
        const PRESENT =         1;
        /// Controls whether writes to the mapped frames are allowed.
        ///
        /// If this bit is unset in a level 1 page table entry, the mapped frame is read-only.
        /// If this bit is unset in a higher level page table entry the complete range of mapped
        /// pages is read-only.
        const WRITABLE =        1 << 1;
        /// Controls whether accesses from userspace (i.e. ring 3) are permitted.
        const USER_ACCESSIBLE = 1 << 2;
        /// If this bit is set, a “write-through” policy is used for the cache, else a “write-back”
        /// policy is used.
        const WRITE_THROUGH =   1 << 3;
        /// Disables caching for the pointed entry is cacheable.
        const NO_CACHE =        1 << 4;
        /// Set by the CPU when the mapped frame or page table is accessed.
        const ACCESSED =        1 << 5;
        /// Set by the CPU on a write to the mapped frame.
        const DIRTY =           1 << 6;
        /// Specifies that the entry maps a huge frame instead of a page table. Only allowed in
        /// P2 or P3 tables.
        const HUGE_PAGE =       1 << 7;
        /// Indicates that the mapping is present in all address spaces, so it isn't flushed from
        /// the TLB on an address space switch.
        const GLOBAL =          1 << 8;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_9 =           1 << 9;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_10 =          1 << 10;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_11 =          1 << 11;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_52 =          1 << 52;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_53 =          1 << 53;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_54 =          1 << 54;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_55 =          1 << 55;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_56 =          1 << 56;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_57 =          1 << 57;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_58 =          1 << 58;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_59 =          1 << 59;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_60 =          1 << 60;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_61 =          1 << 61;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_62 =          1 << 62;
        /// Forbid code execution from the mapped frames.
        ///
        /// Can be only used when the no-execute page protection feature is enabled in the EFER
        /// register.
        const NO_EXECUTE =      1 << 63;
    }
}
#[allow(dead_code)]
#[derive(Debug)]
pub struct GDTEntry {
    base : u32,
    limit: u32,
    entry_type : u8,
    s : bool,
    dpl: u8,
    p: bool,
    avl: bool,
    l: bool,
    d: bool,
    g: bool
}

impl From<u64> for GDTEntry {
    fn from(from: u64) -> Self {
        let from_bits = from.view_bits::<Lsb0>();
        GDTEntry {
            limit: from_bits[0 .. 16].load::<u32>() + (from_bits[32 + 16 .. 32 + 20].load::<u32>() << 16),
            base: from_bits[16 .. 32 + 7].load::<u32>() + (from_bits[56 .. 64].load::<u32>() << 24),
            entry_type: from_bits[40 .. 44].load(),
            s: from_bits[44],
            dpl: from_bits[45 .. 47].load(),
            p: from_bits[32 + 15],
            avl: from_bits[32 + 20],
            l: from_bits[32 + 21],
            d: from_bits[32 + 22],
            g: from_bits[32 + 23]
        }
    }
}

impl IDTEntry {
    fn to_bytes(e: Self) -> Vec<u64> {
        let mut bv = bitvec![u64, Lsb0;];
        bv.extend(&e.offset.view_bits::<Lsb0>()[0 .. 16]);
        bv.extend(&e.segsel.view_bits::<Lsb0>()[0 .. 16]);
        bv.extend(&e.ist.view_bits::<Lsb0>()[0 .. 16]);
        bv.extend([false; 5].iter()); 
        bv.extend(&e.r#type.view_bits::<Lsb0>()[0 .. 4]);
        bv.push(false)
        bv.push(e.p);
        bv.as_raw_slice().to_vec()
    }
}

#[derive(Debug)]
pub struct IDTEntry {
    offset: u64,
    p: bool,
    dpl: u8,
    r#type : u8,
    ist: u8,
    segsel: u16
}

impl From<[u64; 2]> for IDTEntry {
    fn from(from: [u64; 2]) -> Self {
        let from_bits = from[0].view_bits::<Lsb0>();
        let from_bits2 = from[1].view_bits::<Lsb0>();
        IDTEntry {
            offset: from_bits[0 .. 16].load::<u64>() + from_bits[48 .. 64].load::<u64>() << 16 + from_bits2[0 .. 32].load::<u64>() << 32,
            p: from_bits[47],
            segsel: from_bits[16 .. 32].load::<u16>(),
            dpl: from_bits[45 .. 47].load::<u8>(),
            r#type: from_bits[40 .. 44].load::<u8>(),
            ist: from_bits[32 .. 34].load::<u8>()
        }
    }
}

fn dump_vm_state(regs : kvm_bindings::kvm_regs, guest_addr : u64, slice : &[u8]) {
    println!("{:x?}", regs);
    let cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build().unwrap();
    let data = &slice[(regs.rip - guest_addr) as usize .. regs.rip as usize + 0x40];
    let insns = cs.disasm_count(data, regs.rip, 5);
    for ins in insns.as_ref() {
        println!("{}", ins);
    }
    for i in 0 .. 4 { 
        let loc = (regs.rsp - guest_addr - (i * std::mem::size_of::<u64>() as u64)) as usize;
        println!("{:x}: {:016x}", regs.rsp - (i*8), u64::from_ne_bytes(slice[loc .. loc + 8].try_into().unwrap()));
    }
}

fn main() {
    use std::io::Write;
    use std::ptr::null_mut;
    use std::slice;

    use kvm_bindings::kvm_userspace_memory_region;

    let mem_size = 0x20000;
    let guest_addr = 0x1000;
    let elf_file = std::fs::read("runtime-env/a.out").unwrap();

    // Pagetable
    let mut pml4 = [0u64; 512];
    pml4[0] = 0xa000 | (PageTableFlags::WRITABLE | PageTableFlags::PRESENT).bits;
    
    let mut pdp = [0u64; 512];
    pdp[0] = 0x0000 | (PageTableFlags::WRITABLE | PageTableFlags::PRESENT | PageTableFlags::HUGE_PAGE).bits;

    // GDT
    let gdt = [
        0x0000000000000000u64,
        0x00af9b000000ffff,
        0x00cf9b000000ffff,
    ];

    for (i, g) in gdt.iter().enumerate() {
        println!("GDT {}: {:016x} -> {:x?}", i, g, GDTEntry::from(*g));
    }

    // IDT
    let idt_entry = [0x00018e00000860000u64, 0x0u64];
    //let mut idt = Vec::new();
    println!("IDT {:016x}, {:016x} -> {:x?}", idt_entry[0], idt_entry[1], IDTEntry::from(idt_entry));
    println!("Test: {:x}", 0x0fu16.view_bits::<Lsb0>()[1 .. 5].load::<u8>());
    // for i in 0..10 {
    //     idt.push();
    // }

    // 1. Instantiate KVM.
    let kvm = Kvm::new().unwrap();

    // 2. Create a VM.
    let vm = kvm.create_vm().unwrap();

    // 3. Initialize Guest Memory.
    let load_addr: *mut u8 = unsafe {
        libc::mmap(
            null_mut(),
            mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    let slot = 0;
    // When initializing the guest memory slot specify the
    // `KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
    let mem_region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: guest_addr,
        memory_size: mem_size as u64,
        userspace_addr: load_addr as u64,
        //flags: KVM_MEM_LOG_DIRTY_PAGES,
        flags: 0,
    };
    unsafe { vm.set_user_memory_region(mem_region).unwrap() };

    // Write the code in the guest memory. This will generate a dirty page.
    let slice = unsafe { slice::from_raw_parts_mut(load_addr, mem_size) };
    unsafe { 
        (&mut slice[0x1000 .. ]).write(slice::from_raw_parts(pml4.as_ptr() as *const u8, std::mem::size_of_val(&pml4))).unwrap();
        (&mut slice[0x9000 .. ]).write(slice::from_raw_parts(pdp.as_ptr() as *const u8, std::mem::size_of_val(&pdp))).unwrap();
        (&mut slice[(GDT_BASE_ADDR - guest_addr) as usize .. ]).write(slice::from_raw_parts(gdt.as_ptr() as *const u8, std::mem::size_of_val(&gdt))).unwrap();
    }
    // Copy over stuff from ELF into memory
    let mut entry = 0x0;
    if let goblin::Object::Elf(elf) = goblin::Object::parse(&elf_file).unwrap() {
        entry = elf.entry;
        for ph in elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                if ph.p_vaddr < 0x10000 {
                    panic!("Load into reserved area: 0x{:x}!", ph.p_vaddr);
                }
                println!("Loading 0x{:x}...", ph.p_vaddr);
                (&mut slice[(ph.p_vaddr - guest_addr) as usize ..]).write(&elf_file[ph.file_range()]).unwrap();
            }
        }
    }

    // 4. Create one vCPU.
    let vcpu_fd = vm.create_vcpu(0).unwrap();

    // 5. Initialize general purpose and special registers.
    // x86_64 specific registry setup.
    let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_sregs.cr0 = 1 /* Protected Mode */ | (1 << 31) /* Paging enabled */; 
    vcpu_sregs.cr3 = 0x2000 /* Phys Address starts at bit 12 */;
    vcpu_sregs.cr4 = 0x1 << 5; // Enable PAE
    vcpu_sregs.cs.l = 1; // Enable 64-bit mode vs compat mode
    vcpu_sregs.efer = 0x1 << 10 /* Long mode active */ | 0x1 << 8 /* Long mode enable */ | 0x1 << 11 /* NX-Bit */;
    vcpu_sregs.idt.base = IDT_BASE_ADDR;
    //vcpu_sregs.idt.limit = std::mem::size_of_val(&idt) as u16;
    vcpu_sregs.idt.limit = 30u16;
    vcpu_sregs.gdt.base = GDT_BASE_ADDR;
    vcpu_sregs.gdt.limit = 0x18;
    vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    vcpu_regs.rip = entry;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu_regs.rsp = 0x1500;
    vcpu_fd.set_regs(&vcpu_regs).unwrap();

    // 6. Run code on the vCPU.
    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoIn(addr, data) => {
                println!(
                    "Received an I/O in exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::IoOut(addr, data) => {
                println!(
                    "Received an I/O out exit. Address: {:#x}. Data: {:#x}",
                    addr, data[0],
                );
            }
            VcpuExit::MmioRead(_addr, _data) => {
                //println!("Received an MMIO Read Request for the address {:#x}.", _addr,);
            }
            VcpuExit::MmioWrite(_addr, _data) => {
                //println!("Received an MMIO Write Request to the address {:#x}.", _addr,);
                // The code snippet dirties 1 page when it is loaded in memory
                //let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                //let dirty_pages = dirty_pages_bitmap
                //    .into_iter()
                //    .map(|page| page.count_ones())
                //    .fold(0, |dirty_page_count, i| dirty_page_count + i);
                //assert_eq!(dirty_pages, 1);
            }
            //VcpuExit::InternalError(
            VcpuExit::Hlt => {
                println!("Hlt!", );
                break;
            }
            r => {
                println!("Unexpected exit reason: {:?}", r);
                let regs = vcpu_fd.get_regs().unwrap();
                dump_vm_state(regs, guest_addr, slice);
                panic!("Unexpected exit reason");
            },
        }
    }
}
