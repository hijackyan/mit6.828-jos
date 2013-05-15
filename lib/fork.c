// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	if ((err & FEC_WR) == 0 || (uvpd[PDX(addr)] & PTE_P) == 0 || (uvpt[PGNUM(addr)] & PTE_COW) == 0)
		panic ("pgfault: faulting access was (1)not a write, or (2) not a copy-on-write page.");
	// Allocate a new page, map it at a temporary location (PFTEMP),
	if ((r = sys_page_alloc (0, (void *)PFTEMP, PTE_U|PTE_P|PTE_W)) < 0)
		panic ("pgfault: page allocation failed : %e", r);
	// copy the data from the old page to the new page, then move the new
	addr = ROUNDDOWN (addr, PGSIZE);
	memmove (PFTEMP, addr, PGSIZE);
	// page to the old page's address.
	if ((r = sys_page_map (0, PFTEMP, 0, addr, PTE_U|PTE_P|PTE_W)) < 0)
		panic ("pgfault: page mapping failed : %e", r);
	// unmap the PFTEMP
	if((r=sys_page_unmap(0, PFTEMP)) < 0)
		panic("pgfault: sys_page_unmap: %e", r);
	//WHY??????   No need to explicitly delete the old page's mapping.
	//because the page_map call the page_insert which will automatically --ref;

}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	// LAB 4: Your code here.
	void * addr = (void *) (pn * PGSIZE );
	pte_t tmpPte = uvpt[PGNUM(addr)];
	if( (tmpPte & PTE_SHARE) > 0)
	{
		if( (r = sys_page_map (0, addr, envid, addr, tmpPte & PTE_SYSCALL) ) < 0 )
			panic ("duppage: sys_page_map failed at 0 : %e", r);

	}
	else if( (tmpPte & PTE_W) > 0 || (tmpPte & PTE_COW) > 0 )
	{
	//If the page is writable or copy-on-write,the new mapping must be created copy-on-write	
		if( (r = sys_page_map (0, addr, envid, addr, PTE_U|PTE_P|PTE_COW)) < 0 )
			panic ("duppage: sys_page_map failed at 1 : %e", r);
	//then our mapping must be marked copy-on-write as well. 
	//no need to worry about the ref++ because we have detect this in page_insert already!
	//when the process goes on the stack of the father process, 
	//the COW-parent will return to write-parent
	//because the map in stack need to push in stack which will cause a pagefault
	//and the pagefault will alloc a new writeable page for parent stack	
		if( (r = sys_page_map (0, addr, 0, addr, PTE_U|PTE_P|PTE_COW)) < 0 )
			panic ("duppage: sys_page_map failed at 2 : %e", r);
	}
	else
		if( (r = sys_page_map (0, addr, envid, addr, PTE_U|PTE_P)) < 0 )
			panic ("duppage: sys_page_map failed at 3 : %e", r);

	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	//set handler
	set_pgfault_handler(pgfault);
	envid_t envid;
	uint32_t addr;
	int r;	
	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0)
	{
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	
	//map the user space
	for(addr = UTEXT; addr < UXSTACKTOP - PGSIZE; addr += PGSIZE)
	{
		//if the father uer space is mapped
		if((uvpd[PDX(addr)] & PTE_P) 
		&& (uvpt[PGNUM(addr)] & PTE_P) 
		&& (uvpt[PGNUM(addr)] & PTE_U))
		{
			if( (r = duppage(envid, PGNUM(addr))) < 0)
			panic("fork: duppage: %e", r);
		}
	
	}
	// alloc the exception stack
	if((r=sys_page_alloc(envid, (void*)(UXSTACKTOP-PGSIZE), PTE_W|PTE_U|PTE_P))<0)
		panic("fork: sys_page_alloc %e", r);

	//set upcall
	//because they use the same handler so no need to set handler again.
	extern void _pgfault_upcall (void);
	sys_env_set_pgfault_upcall (envid, _pgfault_upcall);
	
	// Start the child environment running
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);
	return envid;
}

// Challenge!
int
sfork(void)
{
	// LAB 4: Your code here.
	//set handler
	set_pgfault_handler(pgfault);
	envid_t envid;
	uint32_t addr;
	int r;	
	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0)
	{
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	
	//map the user space(uvpt[PGNUM(addr)]|0xfff))
	for(addr = UTEXT; addr < UXSTACKTOP - PGSIZE; addr += PGSIZE)
	{
		//if the father uer space is mapped
		if((uvpd[PDX(addr)] & PTE_P) 
		&& (uvpt[PGNUM(addr)] & PTE_P) 
		&& (uvpt[PGNUM(addr)] & PTE_U))
		{
			if( (r = sys_page_map (0, (void *)addr, envid, (void *)addr, (uvpt[PGNUM(addr)]& PTE_SYSCALL) ) ) < 0)
				panic("fork: sys_page_map: %e", r);
		}
	
	}
	//alloc the  normal stack
	if((r = duppage(envid, PGNUM(USTACKTOP-PGSIZE))) < 0)
		panic("fork: duppage: %e", r);

	// alloc the exception stack
	if((r=sys_page_alloc(envid, (void*)(UXSTACKTOP-PGSIZE), PTE_W|PTE_U|PTE_P)) < 0)
		panic("fork: sys_page_alloc %e", r);

	//set upcall
	extern void _pgfault_upcall (void);
	sys_env_set_pgfault_upcall (envid, _pgfault_upcall);
	
	// Start the child environment running
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);
	return envid;
}









