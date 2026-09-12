/*
 * ═══════════════════════════════════════════════════════════════════════
 *  PhoenixWAF LD_PRELOAD Protection v4.0
 *  Hooks: execve, unlink, rename, chmod, remove, truncate, symlink, link, fopen,
 *         unlinkat, renameat, fchmodat
 *  execve: 逐参数全量扫描(堆分配, 无 64 参数/2048 字节填充绕过)
 *  *at 变体: 补齐现代 coreutils(rm/mv/chmod)走的 unlinkat/renameat/fchmodat
 * ═══════════════════════════════════════════════════════════════════════
 *
 *  编译环境要求:
 *    - Linux (x86_64 / aarch64 / armv7l)
 *    - GCC >= 4.8 或 musl-gcc
 *    - glibc-devel / musl-dev (提供 dlfcn.h)
 *
 *  ─── 编译命令 ──────────────────────────────────────────────────────────
 *
 *  ★ x86_64 (绝大多数比赛靶机):
 *    gcc -shared -fPIC -O2 -s -o waf_x86_64.so pwaf_ldpreload.c -ldl
 *
 *  ★ aarch64 (ARM64):
 *    gcc -shared -fPIC -O2 -s -o waf_aarch64.so pwaf_ldpreload.c -ldl
 *    或交叉编译:
 *    aarch64-linux-gnu-gcc -shared -fPIC -O2 -s -o waf_aarch64.so pwaf_ldpreload.c -ldl
 *
 *  ★ armv7l (ARM32, 少见):
 *    arm-linux-gnueabihf-gcc -shared -fPIC -O2 -s -o waf_armv7l.so pwaf_ldpreload.c -ldl
 *
 *  ★ 静态链接 musl (兼容性最好，无 glibc 依赖):
 *    musl-gcc -shared -fPIC -O2 -s -o waf_x86_64_musl.so pwaf_ldpreload.c -ldl
 *
 *  编译参数说明:
 *    -shared   生成共享库 (.so)
 *    -fPIC     位置无关代码 (Position Independent Code)
 *    -O2       优化等级
 *    -s        strip 符号表，减小体积 (通常 < 20KB)
 *    -ldl      链接 libdl (dlsym 需要)
 *
 *  ─── 部署方式 ──────────────────────────────────────────────────────────
 *
 *  方法 A: 通过 php.ini / .user.ini 注入 (推荐)
 *    将编译好的 waf.so 放到网站根目录，然后:
 *    echo 'LD_PRELOAD=/var/www/html/waf.so' >> /etc/environment
 *    或在 PHP-FPM pool 配置中:
 *    env[LD_PRELOAD] = /var/www/html/waf.so
 *
 *  方法 B: 通过 Apache .htaccess:
 *    SetEnv LD_PRELOAD /var/www/html/waf.so
 *
 *  方法 C: PhoenixWAF 自动部署 (install 时自动完成)
 *
 *  ─── 自定义路径 ─────────────────────────────────────────────────────────
 *
 *  编译时可通过 -D 参数自定义日志路径和网站根目录:
 *    gcc -shared -fPIC -O2 -s \
 *        -DPWAF_LOG_PATH='"/var/www/html/.pwaf_log"' \
 *        -DPWAF_WEBROOT='"/var/www/html"' \
 *        -o waf.so pwaf_ldpreload.c -ldl
 *
 *  如不指定，默认值:
 *    LOG_PATH = /var/www/html/.pwaf_log
 *    WEBROOT  = /var/www/html
 *
 *  ─── 编译后嵌入 waf.php ────────────────────────────────────────────────
 *
 *  编译完成后，将 .so 转为 base64 硬编码到 waf.php:
 *    base64 -w0 waf_x86_64.so     → 粘贴到 waf.php 中 LDPRELOAD_X86_64 常量
 *    base64 -w0 waf_aarch64.so    → 粘贴到 waf.php 中 LDPRELOAD_AARCH64 常量
 *
 *  或者直接将 base64 写入配置:
 *    php -r "echo base64_encode(file_get_contents('waf_x86_64.so'));" > waf_x86_64.b64
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

/* ── 可配置路径 (编译时 -D 覆盖) ── */

#ifndef PWAF_LOG_PATH
#define PWAF_LOG_PATH "/var/www/html/.pwaf_log"
#endif

#ifndef PWAF_WEBROOT
#define PWAF_WEBROOT "/var/www/html"
#endif

static const char *LOG_PATH = PWAF_LOG_PATH;
static const char *WEBROOT  = PWAF_WEBROOT;

/* ── execve 拦截关键词 ── */
static const char *exec_blocked[] = {
    "flag",
    "LD_PRELOAD",
    "waf.so",
    "waf.php",
    ".pwaf",
    "/dev/tcp/",
    "/dev/udp/",
    "nc -e",
    "nc -lp",
    "ncat -e",
    "mkfifo",
    "socat",
    "/etc/shadow",
    "/etc/passwd",
    "base64 -d",
    "base64 -D",
    "base64 --decode",
    "base64_decode",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "php -r",
    "bash -i",
    "sh -i",
    "chattr",       /* 阻止攻击者解锁受保护文件 (chattr -i) */
    "setfacl",
    "crontab",
    "wget ",        /* 远程下载落地 */
    "curl ",
    NULL
};

/* ── 受保护文件名 (禁止 unlink/rename/chmod) ── */
static const char *protected_names[] = {
    "waf.php",
    "common.inc.php",   /* 隐身部署下 WAF 核心的真实文件名(install 时由 waf.php 重命名而来) */
    ".pwaf.php",
    ".pwaf_bak.php",
    ".common.bak.php",  /* 核心备份(自愈用) */
    ".htaccess",
    ".user.ini",
    "waf.so",
    ".pwaf_watcher.sh",
    ".pwaf_watcher.pid",
    ".pwaf_log",
    ".pwaf_int",
    ".pwaf_rate",
    NULL
};

/* ═══════════════════════════════════════════════════════════════════════
 *  日志记录
 * ═══════════════════════════════════════════════════════════════════════ */
static void pwaf_log(const char *hook, const char *target) {
    FILE *f = fopen(LOG_PATH, "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    fprintf(f,
        "{\"ts\":%ld,\"dt\":\"%s\",\"ip\":\"LDPRELOAD\",\"method\":\"%s\","
        "\"uri\":\"%.200s\",\"rule\":\"ldpreload_%s\","
        "\"payload\":\"%.200s\",\"param\":\"syscall\",\"ua\":\"\","
        "\"action\":\"blocked\"}\n",
        (long)now, ts, hook, target, hook, target);
    fclose(f);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  路径保护检查
 * ═══════════════════════════════════════════════════════════════════════ */
static int is_protected(const char *path) {
    if (!path) return 0;

    /* 提取文件名 (basename) */
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;

    /* 精确匹配保护文件名 */
    for (int i = 0; protected_names[i]; i++) {
        if (strcmp(bn, protected_names[i]) == 0) return 1;
    }

    /* 模糊匹配: 任何包含 .pwaf 的路径 */
    if (strstr(path, ".pwaf") != NULL) return 1;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: execve — 拦截危险命令执行
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_execve_t)(const char *, char *const[], char *const[]);

int execve(const char *filename, char *const argv[], char *const envp[]) {
    real_execve_t real_execve = (real_execve_t)dlsym(RTLD_NEXT, "execve");
    if (!real_execve) { errno = EACCES; return -1; }

    /* 拼接完整命令行用于关键词匹配。旧实现用定长 2048 缓冲 + 前 64 个参数上限，
     * 攻击者塞满无害参数即可把恶意关键词挤出扫描窗口绕过。改为按实际长度在堆上
     * 分配(封顶 1MB 防病理输入)，拼接全部参数，从根本上消除数量/长度绕过；
     * 多词关键词(如 "nc -e"/"bash -i"/"wget ")仍能跨参数命中。 */
    size_t total = (filename ? strlen(filename) : 0) + 2;
    if (argv) for (int i = 0; argv[i] && i < 100000; i++) total += strlen(argv[i]) + 1;
    if (total > 1048576) total = 1048576;   /* 上限 1MB */
    char *cmdline = (char *)malloc(total + 1);
    if (cmdline) {
        size_t off = 0;
        for (int i = 0; argv && argv[i] && off < total; i++) {
            size_t l = strlen(argv[i]);
            if (off + l + 1 >= total) l = total - off - 1;
            if ((int)l <= 0) break;
            memcpy(cmdline + off, argv[i], l); off += l;
            cmdline[off++] = ' ';
        }
        cmdline[off] = '\0';

        for (int j = 0; exec_blocked[j]; j++) {
            if (strstr(cmdline, exec_blocked[j]) != NULL ||
                (filename && strstr(filename, exec_blocked[j]) != NULL)) {
                pwaf_log("execve", cmdline);
                free(cmdline);
                errno = EACCES;
                return -1;
            }
        }
        free(cmdline);
    } else {
        /* 极端内存不足回退：逐参数扫描(多词关键词可能漏，但不崩溃) */
        for (int j = 0; exec_blocked[j]; j++) {
            if (filename && strstr(filename, exec_blocked[j])) { errno = EACCES; return -1; }
            for (int i = 0; argv && argv[i]; i++)
                if (strstr(argv[i], exec_blocked[j])) { errno = EACCES; return -1; }
        }
    }

    /* 检测 env -i 绕过尝试 (清空环境变量以移除 LD_PRELOAD) */
    if (argv) {
        for (int i = 0; argv[i]; i++) {
            if (strstr(argv[i], "env") && argv[i+1] && strstr(argv[i+1], "-i")) {
                pwaf_log("execve", "env -i bypass attempt");
                errno = EACCES;
                return -1;
            }
        }
    }

    /* 检测通过 envp 卸载 LD_PRELOAD */
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            if (strncmp(envp[i], "LD_PRELOAD=", 11) == 0 &&
                strstr(envp[i], "waf.so") == NULL) {
                pwaf_log("execve", "LD_PRELOAD override attempt");
                errno = EACCES;
                return -1;
            }
        }
    }

    return real_execve(filename, argv, envp);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: unlink — 禁止删除受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_unlink_t)(const char *);

int unlink(const char *pathname) {
    real_unlink_t real_unlink = (real_unlink_t)dlsym(RTLD_NEXT, "unlink");
    if (!real_unlink) { errno = EACCES; return -1; }
    if (is_protected(pathname)) {
        pwaf_log("unlink", pathname);
        errno = EPERM;
        return -1;
    }
    return real_unlink(pathname);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: rename — 禁止重命名受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_rename_t)(const char *, const char *);

int rename(const char *oldpath, const char *newpath) {
    real_rename_t real_rename = (real_rename_t)dlsym(RTLD_NEXT, "rename");
    if (!real_rename) { errno = EACCES; return -1; }
    if (is_protected(oldpath)) {
        pwaf_log("rename", oldpath);
        errno = EPERM;
        return -1;
    }
    return real_rename(oldpath, newpath);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: chmod — 禁止修改受保护文件权限
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_chmod_t)(const char *, mode_t);

int chmod(const char *pathname, mode_t mode) {
    real_chmod_t real_chmod = (real_chmod_t)dlsym(RTLD_NEXT, "chmod");
    if (!real_chmod) { errno = EACCES; return -1; }
    if (is_protected(pathname)) {
        pwaf_log("chmod", pathname);
        errno = EPERM;
        return -1;
    }
    return real_chmod(pathname, mode);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: remove — 禁止 remove() 删除受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_remove_t)(const char *);

int remove(const char *pathname) {
    real_remove_t real_remove = (real_remove_t)dlsym(RTLD_NEXT, "remove");
    if (!real_remove) { errno = EACCES; return -1; }
    if (is_protected(pathname)) {
        pwaf_log("remove", pathname);
        errno = EPERM;
        return -1;
    }
    return real_remove(pathname);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: truncate — 禁止截断受保护文件
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_truncate_t)(const char *, off_t);

int truncate(const char *path, off_t length) {
    real_truncate_t real_truncate = (real_truncate_t)dlsym(RTLD_NEXT, "truncate");
    if (!real_truncate) { errno = EACCES; return -1; }
    if (is_protected(path) && length == 0) {
        pwaf_log("truncate", path);
        errno = EPERM;
        return -1;
    }
    return real_truncate(path, length);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: symlink — 禁止对受保护文件/flag 建立软链接绕过读取
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_symlink_t)(const char *, const char *);

int symlink(const char *target, const char *linkpath) {
    real_symlink_t real_symlink = (real_symlink_t)dlsym(RTLD_NEXT, "symlink");
    if (!real_symlink) { errno = EACCES; return -1; }
    if (is_protected(target) || is_protected(linkpath) ||
        (target && strstr(target, "flag")) ||
        (target && strstr(target, "/etc/passwd")) ||
        (target && strstr(target, "/etc/shadow"))) {
        pwaf_log("symlink", target ? target : "?");
        errno = EPERM;
        return -1;
    }
    return real_symlink(target, linkpath);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: link — 禁止对受保护文件建立硬链接
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_link_t)(const char *, const char *);

int link(const char *oldpath, const char *newpath) {
    real_link_t real_link = (real_link_t)dlsym(RTLD_NEXT, "link");
    if (!real_link) { errno = EACCES; return -1; }
    if (is_protected(oldpath) || is_protected(newpath) ||
        (oldpath && strstr(oldpath, "flag"))) {
        pwaf_log("link", oldpath ? oldpath : "?");
        errno = EPERM;
        return -1;
    }
    return real_link(oldpath, newpath);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: fopen — 禁止以写/截断模式打开受保护文件 (阻止 > 覆盖)
 *  注意: 只拦截 'w'(截断) 模式, 放行 'a'(追加) — WAF 自身日志依赖追加写入
 * ═══════════════════════════════════════════════════════════════════════ */
typedef FILE *(*real_fopen_t)(const char *, const char *);

FILE *fopen(const char *path, const char *mode) {
    real_fopen_t real_fopen = (real_fopen_t)dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen) { errno = EACCES; return NULL; }
    if (path && mode && is_protected(path) &&
        (mode[0] == 'w' || (mode[0] == 'r' && strchr(mode, '+')))) {
        pwaf_log("fopen_w", path);
        errno = EPERM;
        return NULL;
    }
    return real_fopen(path, mode);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Hook: unlinkat / renameat / fchmodat — 现代 coreutils(rm/mv/chmod)走 *at
 *  变体系统调用，会绕过上面的 unlink/rename/chmod 钩子；这里补齐同等保护。
 *  均非可变参数、且 WAF 自身运行时从不对受保护文件做这些操作(仅安装器在
 *  .so 未加载/独立进程时做)，故拦截绝对安全。
 * ═══════════════════════════════════════════════════════════════════════ */
typedef int (*real_unlinkat_t)(int, const char *, int);
int unlinkat(int dirfd, const char *pathname, int flags) {
    real_unlinkat_t real_unlinkat = (real_unlinkat_t)dlsym(RTLD_NEXT, "unlinkat");
    if (!real_unlinkat) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("unlinkat", pathname); errno = EPERM; return -1; }
    return real_unlinkat(dirfd, pathname, flags);
}

typedef int (*real_renameat_t)(int, const char *, int, const char *);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    real_renameat_t real_renameat = (real_renameat_t)dlsym(RTLD_NEXT, "renameat");
    if (!real_renameat) { errno = EACCES; return -1; }
    if (is_protected(oldpath)) { pwaf_log("renameat", oldpath); errno = EPERM; return -1; }
    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

typedef int (*real_fchmodat_t)(int, const char *, mode_t, int);
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    real_fchmodat_t real_fchmodat = (real_fchmodat_t)dlsym(RTLD_NEXT, "fchmodat");
    if (!real_fchmodat) { errno = EACCES; return -1; }
    if (is_protected(pathname)) { pwaf_log("fchmodat", pathname); errno = EPERM; return -1; }
    return real_fchmodat(dirfd, pathname, mode, flags);
}

/* ── 关于 open()/openat() 写保护 ──────────────────────────────────────────
 * 有意不 hook open/openat：
 *  (1) 核心文件(waf.php/common.inc.php/.so/.htaccess/.user.ini)在安装时已用
 *      chattr +i 锁定，内核对这些文件的 open(O_WRONLY/O_TRUNC)、unlink、rename
 *      一律拒绝——这是比 LD_PRELOAD 更强的保护(连绕过 LD_PRELOAD 的静态程序也挡)。
 *  (2) glibc 内部大量走 openat/__openat 等符号，单 hook open() 覆盖不全，易生假安全感。
 *  (3) WAF 自身要写可变文件(.pwaf.php 配置、日志、自愈重写 common.inc.php)，一个
 *      过宽的 open() 拦截极易误伤自身运行(与已修复的"chattr 锁配置"同类问题)。
 * 故文件写保护交给 chattr(内核级) + unlink/rename/truncate/fopen(补充) 组合承担。
 * ═══════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════
 *  Constructor — .so 加载时自动执行
 * ═══════════════════════════════════════════════════════════════════════ */
__attribute__((constructor))
static void pwaf_init(void) {
    setenv("PWAF_ACTIVE", "1", 1);
}
