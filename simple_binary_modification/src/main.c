#include <zephyr/kernel.h>

#define SLEEP_TIME_MS 1000

int main() {
    while (1) {
        printf("Hello, World!\n");
        k_msleep(SLEEP_TIME_MS);
    }

    return 0;
}
