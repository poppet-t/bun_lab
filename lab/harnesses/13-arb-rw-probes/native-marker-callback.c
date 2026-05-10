#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((visibility("default")))
void bun_uaf_noop_callback(void *data, void *ctx) {
  (void)data;
  (void)ctx;
}

__attribute__((visibility("default")))
void bun_uaf_marker_callback(void *data, void *ctx) {
  int fd = open("/tmp/bun_uaf_marker_callback", O_CREAT | O_WRONLY | O_TRUNC, 0600);
  dprintf(2, "[bun-uaf-marker] called data=%p ctx=%p\n", data, ctx);
  if (fd < 0) return;

  dprintf(fd, "called data=%p ctx=%p\n", data, ctx);
  if (ctx) {
    unsigned char *bytes = (unsigned char *)ctx;
    dprintf(fd, "ctx_prefix=");
    for (int i = 0; i < 64; i++) dprintf(fd, "%02x", bytes[i]);
    dprintf(fd, "\n");
  }
  close(fd);
}
