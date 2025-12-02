#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

static void print_link(const char *path, const char *label) {
    char buf[100+1];
    ssize_t n = readlink(path, buf, sizeof(buf)-1);
    if (n < 0) {
        printf("%s: (readlink failed: %s)\n", label, strerror(errno));
        return;
    }
    buf[n] = '\0';
    printf("%s -> %s\n", label, buf);
}

static void print_getcwd(void) {
    char cwd[100];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        printf("getcwd(): (failed: %s)\n", strerror(errno));
    } else {
        printf("getcwd() (view inside process) = %s\n", cwd);
    }
}

static void list_fds(void) {
    printf("open fds -> ");
    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        printf("(cannot open /proc/self/fd: %s)\n", strerror(errno));
        return;
    }
    struct dirent *ent;
    int first = 1;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (!first) printf(", ");
        printf("%s", ent->d_name);
        first = 0;
    }
    closedir(d);
    printf("\n");
}

static void print_snapshot(const char *tag) {
    printf("\n=== %s ===\n", tag);
    printf("pid = %d\n", getpid());
    print_getcwd();
    print_link("/proc/self/cwd", "/proc/self/cwd");
    print_link("/proc/self/root", "/proc/self/root");
    list_fds();
}

int ensure_dir_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "Path exists and is not a directory: %s\n", path);
        return -1;
    }
    if (mkdir(path, 0755) != 0) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <OLD_DIR (cwd)> <NEW_ROOT (chroot)>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s /tmp/real_old /tmp/newroot\n", argv[0]);
        return 2;
    }

    const char *old_dir = argv[1];
    const char *new_root = argv[2];

    printf("Note: chroot() requires root. Run with sudo if needed.\n");

    /* optional: create dirs if missing (safer to run in container) */
    if (access(old_dir, F_OK) != 0) {
        printf("Directory %s does not exist. Creating it.\n", old_dir);
        if (ensure_dir_exists(old_dir) != 0) return 3;
    }
    if (access(new_root, F_OK) != 0) {
        printf("Directory %s does not exist. Creating it.\n", new_root);
        if (ensure_dir_exists(new_root) != 0) return 3;
    }

    /* change to old_dir */
    if (chdir(old_dir) != 0) {
        fprintf(stderr, "chdir(%s) failed: %s\n", old_dir, strerror(errno));
        return 4;
    }

    print_snapshot("Before chroot (after chdir to OLD_DIR)");

    printf("\nCalling chroot(%s)...\n", new_root);
    if (chroot(new_root) != 0) {
        fprintf(stderr, "chroot(%s) failed: %s\n", new_root, strerror(errno));
        fprintf(stderr, "If you are not root, chroot will fail.\n");
        return 5;
    } else {
        printf("chroot returned 0 (success)\n");
    }

    print_snapshot("Immediately after chroot (without chdir('/'))");

    printf("\nNow calling chdir(\"/\") to move cwd inside new root.\n");
    if (chdir("/") != 0) {
        fprintf(stderr, "chdir(\"/\") failed: %s\n", strerror(errno));
    }

    print_snapshot("After chdir(\"/\") (cwd should be inside new root)");

    printf("\nDone. Note: program will exit now. If you created dirs, you can remove them manually.\n");
    return 0;
}
