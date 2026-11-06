
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>

#include <linux/pkt_cls.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAP_PIN_PATH "/sys/fs/bpf/config_map"

int main(int argc, char **argv)
{
    uint32_t key = 0;
    uint32_t port;

    struct bpf_object *obj;
    struct bpf_program *prog;
    int map_fd, prog_fd, err;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <port>\n",
                argv[0]);
        return 1;
    }

    /* Validate port */
    char *end;
    errno = 0;

    unsigned long input_port = strtoul(argv[2], &end, 10);

    if (errno || end == argv[2] || *end != '\0' ||
        input_port < 1 || input_port > 65535) {
        fprintf(stderr, "Invalid TCP port\n");
        return 1;
    }

    port = (uint32_t)input_port;

    /* Validate interface */
    unsigned int ifindex = if_nametoindex(argv[1]);

    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", argv[1]);
        return 1;
    }

    /* Check for an existing pinned map */
    map_fd = bpf_obj_get(MAP_PIN_PATH);

    if (map_fd >= 0) {

        /* Update existing map */
        err = bpf_map_update_elem(
            map_fd, &key, &port, BPF_ANY
        );

        if (err) {
            perror("Map update failed");
            close(map_fd);
            return 1;
        }

        printf("Existing BPF map found.\n");
        printf("Blocked TCP port updated to: %u\n", port);
        printf("Existing TC attachment retained.\n");

        close(map_fd);
        return 0;
    }

    if (errno != ENOENT) {
        perror("Unable to open pinned map");
        return 1;
    }

    /* First-time initialization */
    printf("Initializing eBPF firewall...\n");

    obj = bpf_object__open_file("drop_port.bpf.o", NULL);

    err = (int)libbpf_get_error(obj);

    if (err) {
        fprintf(stderr, "Object open failed: %s\n",
                strerror(-err));
        return 1;
    }

    /* Load program and map into kernel */
    err = bpf_object__load(obj);

    if (err) {
        fprintf(stderr, "BPF load failed: %s\n",
                strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* Find map */
    map_fd = bpf_object__find_map_fd_by_name(
        obj, "config_map"
    );

    if (map_fd < 0) {
        fprintf(stderr, "Map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Set initial blocked port */
    err = bpf_map_update_elem(
        map_fd, &key, &port, BPF_ANY
    );

    if (err) {
        perror("Map update failed");
        bpf_object__close(obj);
        return 1;
    }

    /* Find program */
    prog = bpf_object__find_program_by_name(
        obj, "drop_tcp_port"
    );

    if (!prog) {
        fprintf(stderr, "Program not found\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

    /* Configure TC ingress */
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS
    };

    err = bpf_tc_hook_create(&hook);

    if (err && err != -EEXIST) {
        fprintf(stderr, "TC hook creation failed: %s\n",
                strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .prog_fd = prog_fd,
        .handle = 1,
        .priority = 1
    };

    /* Attach program */
    err = bpf_tc_attach(&hook, &opts);

    if (err) {
        fprintf(stderr, "TC attachment failed: %s\n",
                strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* Pin map for future userspace access */
    err = bpf_obj_pin(map_fd, MAP_PIN_PATH);

    if (err) {
        perror("Map pinning failed");
        bpf_tc_detach(&hook, &opts);
        bpf_object__close(obj);
        return 1;
    }

    printf("\nFirewall initialized successfully!\n");
    printf("Interface: %s\n", argv[1]);
    printf("Blocked TCP port: %u\n", port);
    printf("Pinned map: %s\n", MAP_PIN_PATH);

    bpf_object__close(obj);

    return 0;
}
