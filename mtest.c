#include <linux/module.h>
#include <linux/kernel.h>  
#include <linux/init.h>  

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>  
#include <linux/slab.h>
#include <linux/mm.h>

static void vma_list(void)
{
	struct mm_struct *mm = current->mm;
	int count = 0;
	struct vm_area_struct *vma = NULL;
	char my_flags[4] = "---";
	printk("listvma for current process (name: %s, pid: %d)\n", current->comm, current->pid );
	printk("-----------------------------------------------------\n");
	down_read(&mm->mmap_sem);
	for(vma = mm->mmap; vma; vma = vma->vm_next)
	{
		count ++;
		if (vma->vm_flags & VM_READ)
            my_flags[0] = 'r';
        else
        	my_flags[0] = '-';
        if (vma->vm_flags & VM_WRITE)
        	my_flags[1] = 'w';
        else
        	my_flags[1] = '-';
        if (vma->vm_flags & VM_WRITE)
        	my_flags[2] = 'x';
        else
        	my_flags[2] = '-';
        printk("%2d: %s\t0x%012lx\t0x%012lx\n", count, my_flags, vma->vm_start, vma->vm_end);
	}

	up_read(&mm->mmap_sem);
}


static struct page* my_follow_page(struct vm_area_struct *vma, unsigned long addr)

{
    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pud_t *pud;
    pte_t *pte;
    spinlock_t *ptl;
    struct page *page = NULL;
    struct mm_struct *mm = vma->vm_mm;
    pgd = pgd_offset(mm, addr);     //get pgd
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
	    return page;
	p4d = p4d_offset(pgd, addr);	//get p4d
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
	    return page;
    pud = pud_offset(p4d, addr);	//get pud
    if (pud_none(*pud) || unlikely(pud_bad(*pud)))
	    return page;
    pmd = pmd_offset(pud, addr);	//get pmd
    if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
	    return page;
    pte = pte_offset_map_lock(mm, pmd, addr, &ptl); //get pte
    if (!pte)
    	return page;
    if (!pte_present(*pte))   //pte not in memory
    	return page;
    page = pfn_to_page(pte_pfn(*pte));
    if (!page)
        goto unlock;
    get_page(page);
unlock:
    pte_unmap_unlock(pte, ptl);
    return page;
}

static void mtest_find_page(unsigned long addr)

{
    struct vm_area_struct *vma;
    struct task_struct *task = current;
    struct mm_struct *mm = task->mm;
    unsigned long kernel_addr;
    struct page *page;
    down_read(&mm->mmap_sem);
    vma = find_vma(mm, addr);
    page = my_follow_page(vma, addr);
    if (!page)
    {
        printk("translation failed.\n");
        goto out;
    }
    kernel_addr = (unsigned long) page_address(page);
    kernel_addr += (addr & ~PAGE_MASK);
    printk("vma 0x%lx -> pma 0x%lx\n", addr, kernel_addr);
out:
    up_read(&mm->mmap_sem);
}



static void mtest_write_val(unsigned long addr, unsigned long val)
{
    struct vm_area_struct *vma;
    struct task_struct *task = current;
    struct mm_struct *mm = task->mm;
    struct page *page;
    unsigned long kernel_addr;
    down_read(&mm->mmap_sem);
    vma = find_vma(mm, addr);
    //test if it is a legal vma

    if (vma && addr >= vma->vm_start && (addr + sizeof(val)) < vma->vm_end)
    {
        if (!(vma->vm_flags & VM_WRITE))   //test if we have rights to write
        {
            printk("cannot write to 0x%lx\n", addr);
            goto out;
        }
        page = my_follow_page(vma, addr);
        if (!page)
        {
            printk("page not found 0x%lx\n", addr);
            goto out;
        }

        kernel_addr = (unsigned long) page_address(page);
        kernel_addr += (addr &~ PAGE_MASK);
        printk("write 0x%lx to address 0x%lx\n", val, kernel_addr);
        *(unsigned long *)kernel_addr = val;
        put_page(page);
    }
    else {
        printk("no vma found for %lx\n", addr);
    }
    out:
        up_read(&mm->mmap_sem);
}




// 4. To build a proc file

static ssize_t mtest_write(struct file *file, const char __user *buffer, size_t count, loff_t *data)
{
    char buf[128];
    unsigned long val, val2;
 
    if (count > sizeof(buf)) {
        return -EINVAL;
    }

    //get the command from shell 
    if (copy_from_user(buf, buffer, count)) {
        return -EINVAL;
    }

    if (memcmp(buf, "listvma", 7) == 0) {
        vma_list();
    }

    else if (memcmp(buf, "findpage", 8) == 0) {
        if (sscanf(buf+8, "%lx", &val) == 1)
            mtest_find_page(val);
    }

    else if (memcmp(buf, "writeval", 8) == 0) {
         if (sscanf(buf+8, "%lx %lx", &val, &val2) == 2) {
            mtest_write_val(val, val2);
        }
    } else {
        printk("%s\n", buf);
    }
    return count;
}

 

static struct file_operations proc_mtest_operation = {
    write: mtest_write,
};


// Init function

static int __init mtest_dump_vma_list(void)
{
	// vma_list();
    proc_create("mtest", 0x0666, NULL, &proc_mtest_operation);
    printk("Create mtest...\n");
	return 0;
}

static void __exit my_exit(void)
{
    remove_proc_entry("mtest", NULL);
	printk("exit\n");
}


module_init(mtest_dump_vma_list);
module_exit(my_exit);

MODULE_AUTHOR("fengchuanheng");
MODULE_LICENSE("GPL");
