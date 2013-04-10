#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	extern void routine_DIVIDE ();
	extern void routine_DEBUG ();
	extern void routine_NMI ();
	extern void routine_BRKPT ();
	extern void routine_OFLOW ();
	extern void routine_BOUND ();
	extern void routine_ILLOP ();
	extern void routine_DEVICE ();
	extern void routine_DBLFLT ();
	extern void routine_TSS ();
	extern void routine_SEGNP ();
	extern void routine_STACK ();
	extern void routine_GPFLT ();
	extern void routine_PGFLT ();
	extern void routine_FPERR ();
	extern void routine_ALIGN ();
	extern void routine_MCHK ();
	extern void routine_SIMDERR ();
	extern void routine_SYSCALL ();

	SETGATE (idt[T_DIVIDE], 0, GD_KT, routine_DIVIDE, 0);
	SETGATE (idt[T_DEBUG], 1, GD_KT, routine_DEBUG, 3);
	SETGATE (idt[T_NMI], 0, GD_KT, routine_NMI, 0);
	// break point needs no kernel mode privilege
	SETGATE (idt[T_BRKPT], 0, GD_KT, routine_BRKPT, 3);
	SETGATE (idt[T_OFLOW], 0, GD_KT, routine_OFLOW, 0);
	SETGATE (idt[T_BOUND], 0, GD_KT, routine_BOUND, 0);
	SETGATE (idt[T_ILLOP], 0, GD_KT, routine_ILLOP, 0);
	SETGATE (idt[T_DEVICE], 0, GD_KT, routine_DEVICE, 0);
	SETGATE (idt[T_DBLFLT], 0, GD_KT, routine_DBLFLT, 0);
	SETGATE (idt[T_TSS], 0, GD_KT, routine_TSS, 0);
	SETGATE (idt[T_SEGNP], 0, GD_KT, routine_SEGNP, 0);
	SETGATE (idt[T_STACK], 0, GD_KT, routine_STACK, 0);
	SETGATE (idt[T_GPFLT], 0, GD_KT, routine_GPFLT, 0);
	SETGATE (idt[T_PGFLT], 0, GD_KT, routine_PGFLT, 0);
	SETGATE (idt[T_FPERR], 0, GD_KT, routine_FPERR, 0);
	SETGATE (idt[T_ALIGN], 0, GD_KT, routine_ALIGN, 0);
	SETGATE (idt[T_MCHK], 0, GD_KT, routine_MCHK, 0);
	SETGATE (idt[T_SIMDERR], 0, GD_KT, routine_SIMDERR, 0);
	//syscall needs no kernel mode privilege
	SETGATE (idt[T_SYSCALL], 1, GD_KT, routine_SYSCALL, 3);

	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate), 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	if(tf -> tf_trapno == T_PGFLT)
	{
		page_fault_handler(tf);
		return;
		
	}
	if (tf->tf_trapno == T_BRKPT || tf->tf_trapno == T_DEBUG)
	{
		monitor (tf);
		return;
	}
	if(tf -> tf_trapno == T_SYSCALL)
	{	
		//cprintf("%d\n",tf -> tf_trapno);
		tf->tf_regs.reg_eax = syscall (
			tf->tf_regs.reg_eax,
			tf->tf_regs.reg_edx,
			tf->tf_regs.reg_ecx,
			tf->tf_regs.reg_ebx,
			tf->tf_regs.reg_edi,
			tf->tf_regs.reg_esi);
		if (tf->tf_regs.reg_eax < 0)
			panic ("trap_dispatch: The System Call number is invalid");
		return;	
	}
	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{

	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);
	cprintf("privilige: %08x\n",tf->tf_cs);

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		assert(curenv);
		//cprintf("Trapped from user mode\n");
		//cprintf("curenv->env_tf.tf_eip in trap: %08x\n",curenv->env_tf.tf_eip);
		//print_trapframe(&curenv->env_tf);
		//cprintf("now_cr3: %08x\n",rcr3());
		
		//cprintf("curenv_cr3: %08x\n",curenv->env_pgdir);

		//cprintf("I read %08x from location 0xf0100000! %08x\n",*(unsigned*)0xf0100000);
		//为什么现在在内核 但是cr3 是用户态的 然后能输出内核态地址的东西？？  明白了现在是看cs的后两位
		//为什么如果开放page fault给用户 用户就能自己分配空间了？
		//kernel的cs存放在哪里？ 存放在TSS里
		//tf_cs是何时压入? 在进入trapentry.s前
		//int 中断 和 普通中断有何不同
		
		//print_trapframe(tf);
		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// Return to the current environment, which should be running.!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if ((tf->tf_cs & 3) == 0)
		panic ("page_fault_handler:kernel-mode page faults");

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

