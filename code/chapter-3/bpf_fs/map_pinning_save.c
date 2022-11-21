#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include "bpf.h"

static const char* file_path = "/sys/fs/bpf/my_fucker_4";

int main(int argc, char** argv) {
    int key, value, fd, added, result, pinned;

    fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 1000, 0);
    if (fd < 0) {
        printf("Failed to create map: %d (%s)\n", fd, strerror(errno));
        return -1;
    }

    for (int i = 0; i < 1000; i++) {
        key = i, value = i * 100;
        added = bpf_map_update_elem(fd, &key, &value,
                                    BPF_ANY);  // BPF_ANY: upsert symantic
        if (added < 0) {
            printf("Failed to update map: %d (%s)\n", added, strerror(errno));
            return -1;
        }
        printf("Value updated to map: '%d'. key [%d]\n", value, key);

        value += 1;
    }

    pinned = bpf_obj_pin(fd, file_path);
    if (pinned < 0) {
        printf("Failed to pin map to the file system: %d (%s)\n", pinned,
               strerror(errno));
        return -1;
    }

    return 0;
}
