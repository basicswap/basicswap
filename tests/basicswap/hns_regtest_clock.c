/* Test-only realtime offset shared by isolated regtest processes.
 * The eight-byte file contains a native-endian signed seconds offset.
 * Monotonic clocks stay unchanged so harness timeouts remain meaningful.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile const int64_t *offset_seconds;
static pthread_once_t offset_once = PTHREAD_ONCE_INIT;

static void open_offset(void) {
    const char *path = getenv("BASICSWAP_HNS_REGTEST_CLOCK_FILE");
    if (path == NULL) return;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    void *shared = mmap(NULL, sizeof(int64_t), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (shared != MAP_FAILED) offset_seconds = shared;
}

static int64_t current_offset(void) {
    pthread_once(&offset_once, open_offset);
    if (offset_seconds == NULL) return 0;
    return *offset_seconds;
}

int clock_gettime(clockid_t clock_id, struct timespec *result) {
    int status = (int)syscall(SYS_clock_gettime, clock_id, result);
    if (status == 0 && clock_id == CLOCK_REALTIME)
        result->tv_sec += current_offset();
    return status;
}

int gettimeofday(struct timeval *result, void *timezone) {
    int status = (int)syscall(SYS_gettimeofday, result, timezone);
    if (status == 0)
        result->tv_sec += current_offset();
    return status;
}

time_t time(time_t *result) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return (time_t)-1;
    if (result != NULL) *result = now.tv_sec;
    return now.tv_sec;
}
