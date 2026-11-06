
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>

#define CGROUP_PATH "/sys/fs/cgroup/ebpf_myprocess"

static volatile sig_atomic_t running = 1;

void stop_program(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: sudo %s <PID>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);

    if (pid <= 0)
    {
        printf("Invalid PID\n");
        return 1;
    }

    // Create a cgroup
    if (mkdir(CGROUP_PATH, 0755) != 0 && errno != EEXIST)
    {
        perror("mkdir");
        return 1;
    }

    int cgroup_fd = open(CGROUP_PATH, O_RDONLY | O_DIRECTORY);

    if (cgroup_fd < 0)
    {
        perror("Opening cgroup");
        return 1;
    }

    // Open eBPF object file
    struct bpf_object *obj =
        bpf_object__open_file("process_filter.bpf.o", NULL);

    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Failed to open BPF object\n");
        close(cgroup_fd);
        return 1;
    }

    // Load eBPF program
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "Failed to load BPF program\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    // Find program
    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "allow_only_port");

    if (!prog)
    {
        fprintf(stderr, "Program not found\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    // Attach program to cgroup
    struct bpf_link *link =
        bpf_program__attach_cgroup(prog, cgroup_fd);

    if (libbpf_get_error(link))
    {
        fprintf(stderr, "Failed to attach BPF program\n");
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    printf("eBPF program attached successfully!\n");

    // Move target process into cgroup
    int procs_fd = open(CGROUP_PATH "/cgroup.procs", O_WRONLY);

    if (procs_fd < 0)
    {
        perror("Opening cgroup.procs");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    char pid_string[32];
    snprintf(pid_string, sizeof(pid_string), "%d", pid);

    if (write(procs_fd, pid_string, strlen(pid_string)) < 0)
    {
        perror("Moving process into cgroup");
        close(procs_fd);
        bpf_link__destroy(link);
        bpf_object__close(obj);
        close(cgroup_fd);
        return 1;
    }

    close(procs_fd);

    printf("Target PID: %d\n", pid);
    printf("Cgroup: %s\n", CGROUP_PATH);
    printf("Allowed TCP port: 4040\n");
    printf("Other TCP ports will be rejected for this process.\n");
    printf("Press CTRL+C to detach.\n");

    signal(SIGINT, stop_program);
    signal(SIGTERM, stop_program);

    while (running)
    {
        sleep(1);
    }

    printf("\nDetaching eBPF program...\n");

    bpf_link__destroy(link);
    bpf_object__close(obj);
    close(cgroup_fd);

    printf("eBPF program detached.\n");

    return 0;
}
