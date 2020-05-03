/**
 * Description: KProbes the 'handle_mm_fault' routine (method) call,
 *              for a specific PID passed as command line arg
 *
 * Author: Harshit Vadodaria
 * Date Created: Apr 25, 2020
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/slab.h>

#define MODULE_NAME "kprobing_pids"

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");

static char symbol_name[16] = "handle_mm_fault";
static int count_pids = 0;
static int pids[10000];
static int buffersize = -1;

// For logging and collecting stats
//static char *months[12] =
//        {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
//struct timespec64 ts;
//struct tm now;

module_param_array(pids, int, &count_pids, 0);
module_param(buffersize, int, 0);

// Declaring functions, to be included in struct kprobe
static int handle_pre(struct kprobe *, struct pt_regs *);
static void handle_post(struct kprobe *, struct pt_regs *, unsigned long);
static int handle_fault(struct kprobe *, struct pt_regs *, int);

static struct kprobe kp = {
        .symbol_name = symbol_name,
        .pre_handler = handle_pre,
        .post_handler = handle_post,
        .fault_handler = handle_fault,
};


typedef struct fault_history fault_history;
static  int init_fault_history(int count);
static fault_history* create_history(long faulted_addr, time64_t time, struct task_struct *task);
static void save_to_history(int pid_idx, fault_history *fault);
static void destroy_fault_history(int count);


struct fault_history {
    long faulted_address;
    ktime_t time;
    pid_t pid;
    char *command;
    fault_history *next;
};
// Buffer to keep track of all mem faults from required processes
// 1 table for each PID
typedef struct fault_history_table fault_history_table;
struct fault_history_table {
    fault_history *head;
    fault_history *tail;
    int count;
};
fault_history_table **all_faults;

static int init_fault_history(int count) {
    int i;
    all_faults = (fault_history_table**) kmalloc(sizeof(fault_history_table*) * count, GFP_KERNEL);
    if (!all_faults) {
        printk(KERN_ALERT "Failed to allocate space for creating slots to save page fault data to history\n");
        return -ENOBUFS;
    }
    for (i=0; i<count;i++) {
        if ( ! (all_faults[i] = (fault_history_table*) kmalloc(sizeof(fault_history_table), GFP_KERNEL)) ) {
            printk(KERN_ALERT "Failed to allocate space for creating a slot to save page fault data to history\n");
            destroy_fault_history(i+1);
            return -ENOBUFS;
        }
        all_faults[i]->head = NULL;
        all_faults[i]->tail = NULL;
        all_faults[i]->count = 0;
    }
    return 0;
}

static fault_history* create_history(long faulted_addr, time64_t time, struct task_struct *task) {
    // GFP_ATOMIC flag, since this method is to be called within an interrupt handler (i.e. kprobe breakpoint handler),
    // Hence cannot block/sleep
    fault_history *history = (fault_history*) kmalloc(sizeof(fault_history), GFP_ATOMIC);
    if (!history) {
        printk(KERN_ALERT "Failed to allocate space for saving page fault data to history\n");
        return NULL;
    }
    history->faulted_address = faulted_addr;
    history->time = time;
    history->pid = task->pid;
    history->command = task->comm;
    history->next = NULL;
    return history;
}
static void restrict_buffer_size(int pid_idx) {
    fault_history *history;
    if (buffersize == -1)
        return;
    while (all_faults[pid_idx]->count > buffersize) {
        history = all_faults[pid_idx]->head;
        all_faults[pid_idx]->head = history->next;
        all_faults[pid_idx]->count--;
        kfree(history);
    }
}
static void save_to_history(int pid_idx, fault_history *fault) {
    if (all_faults[pid_idx]->head == NULL) {
        all_faults[pid_idx]->head = fault;
        all_faults[pid_idx]->tail = fault;
    }
    else {
        all_faults[pid_idx]->tail->next = fault;
        if (fault)
            all_faults[pid_idx]->tail = fault;
    }
    all_faults[pid_idx]->count++;
    restrict_buffer_size(pid_idx);
}
static void destroy_fault_history(int count) {
    int i;
    fault_history *history, *next;
    for (i=0; i<count; i++) {
        history = all_faults[i]->head;
        while (history) {
            next = history->next;
            kfree(history);
            history = next;
        }
        kfree(all_faults[i]);
    }
    kfree(all_faults);
}


// Checks if the Mem-Faulted pid is to be tracked,
// i.e. whether it was provided as a command line arg during insmod
static int is_tracked(int pid) {
    int pid_idx = 0;
    while (pid_idx < count_pids) {
        if (pids[pid_idx++] == pid)
            return pid_idx-1;
    }
    return -1;
}

// Currently only contains logic to get register specific to x86 architecture
// Can be made more general, to support other architectures
static long getArg2(struct pt_regs *regs) {
    return (regs->si);
}

// Pre-Handler
static int handle_pre(struct kprobe *p, struct pt_regs *regs) {
    long faulted_address;
    struct task_struct *task;
    pid_t pid;
    int pid_idx;
    ktime_t time;

    // Obtaining task_struct of the current task through the global macro variable 'current'
    // (Refer asm/current.h)
    task = current;
    pid = task->pid;

    time = ktime_get_real();

    if ((pid_idx = is_tracked(pid)) > -1) {
        faulted_address = getArg2(regs);
        save_to_history(pid_idx,
                create_history(faulted_address, time, task));

        // Printing detailed info to system log
        printk(KERN_INFO "[%s][%lld][%d][%s][%ld] : Process [%s] with PID [%d] faulted on virtual address [%ld]\n",
                MODULE_NAME, time, pid, task->comm, faulted_address,
                task->comm, pid, faulted_address
        );
    }

    return 0;
}

// Post-Handler
static void handle_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    // Nothing to do after the probed instruction is executed
    return;
}

static int handle_fault(struct kprobe *kp, struct pt_regs *regs, int trap_num) {
    pr_info("fault_handler: p->addr = 0x%p, trap #%dn", kp->addr, trap_num);
    return 0;
}

static int kprobe_registration(struct kprobe *kp, int status) {
    int ret;
    switch (status) {
        case 0:
            unregister_kprobe(kp);
            printk(KERN_INFO "Removed kprobe from [%p]\n", kp->addr);
            return 0;
        case 1:
            if ( ( ret = register_kprobe(kp) ) < 0) {
                printk(KERN_ERR
                "Failed to register kprobe, return value : [%d]\n", ret);
                return ret;
            }
            printk(KERN_INFO "Planted kprobe at [%p]\n", kp->addr);
            return 0;
    }
    return -EINVAL;
}

static int __init _init_module(void) {
    int ret;
    int i;

    if (count_pids == 0) {
        printk(KERN_WARNING "Module %s expects PIDs of one or more processes "
                            "whose memory faults are to be tracked, as arguments (ex. pids=123,456,789)\n" , MODULE_NAME);
        return -EINVAL;
    }

    if ( ( ret = kprobe_registration(&kp, 1) ) < 0 )
        return ret;

    if ( ( ret = init_fault_history(count_pids) ) < 0 )
        return ret;

    printk(KERN_INFO "KProbing for the following %d PIDs:", count_pids);
    for (i=0; i<count_pids; i++) {
        if (i != 0)
            printk(KERN_CONT ", ");
        printk(KERN_CONT "%d", pids[i]);
    }
    printk(KERN_CONT "\n");

    return 0;
}

static void __exit _exit_module(void) {
    kprobe_registration(&kp, 0);
    destroy_fault_history(count_pids);
}

module_init(_init_module);
module_exit(_exit_module);