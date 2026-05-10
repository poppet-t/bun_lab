#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

__attribute__((visibility("default")))
void bun_uaf_noop_callback(void *data, void *ctx) {
  (void)data;
  (void)ctx;
}

static int find_image(uintptr_t pc, const char **out_name, uintptr_t *out_base) {
  uint32_t count = _dyld_image_count();
  uintptr_t best_base = 0;
  const char *best_name = NULL;
  for (uint32_t i = 0; i < count; i++) {
    uintptr_t base = (uintptr_t)_dyld_get_image_header(i);
    intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    const char *name = _dyld_get_image_name(i);
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)base;
    if (hdr->magic != MH_MAGIC_64) continue;
    const struct load_command *lc = (const struct load_command *)((const char *)hdr + sizeof(*hdr));
    for (uint32_t j = 0; j < hdr->ncmds; j++) {
      if (lc->cmd == LC_SEGMENT_64) {
        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
        uintptr_t lo = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
        uintptr_t hi = lo + (uintptr_t)seg->vmsize;
        if (pc >= lo && pc < hi) {
          best_base = base;
          best_name = name;
          break;
        }
      }
      lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    if (best_name) break;
  }
  if (!best_name) return 0;
  *out_name = best_name;
  *out_base = best_base;
  return 1;
}

__attribute__((visibility("default")))
void bun_uaf_marker_callback(void *data, void *ctx) {
  void *ra = __builtin_return_address(0);
  uintptr_t pc = (uintptr_t)ra;
  const char *img_name = "?";
  uintptr_t img_base = 0;
  uintptr_t off = 0;
  if (find_image(pc, &img_name, &img_base)) {
    off = pc - img_base;
  }

  int fd = open("/tmp/bun_uaf_marker_callback", O_CREAT | O_WRONLY | O_TRUNC, 0600);
  dprintf(2, "[bun-uaf-marker] called data=%p ctx=%p ra=%p img=%s base=0x%lx off=0x%lx\n",
          data, ctx, ra, img_name, (unsigned long)img_base, (unsigned long)off);
  if (fd < 0) return;

  dprintf(fd, "called data=%p ctx=%p ra=%p img=%s base=0x%lx off=0x%lx\n",
          data, ctx, ra, img_name, (unsigned long)img_base, (unsigned long)off);
  if (ctx) {
    unsigned char *bytes = (unsigned char *)ctx;
    dprintf(fd, "ctx_prefix=");
    for (int i = 0; i < 256; i++) dprintf(fd, "%02x", bytes[i]);
    dprintf(fd, "\n");
  }
  /* dump 320 bytes of the caller's code (-64..+256 around ra) so we can
   * identify the JIT-mmap'd IC stub even though no dyld image owns it. */
  if (ra) {
    const unsigned char *code = (const unsigned char *)ra - 64;
    dprintf(fd, "ra_code=");
    for (int i = 0; i < 320; i++) dprintf(fd, "%02x", code[i]);
    dprintf(fd, "\n");
  }
  /* dump 256 bytes upstream from the current frame so we can see saved
   * registers, link chain, and JIT prologue bookkeeping. */
  void *fp = __builtin_frame_address(0);
  if (fp) {
    const unsigned char *frame = (const unsigned char *)fp;
    dprintf(fd, "frame_dump=");
    for (int i = 0; i < 256; i++) dprintf(fd, "%02x", frame[i]);
    dprintf(fd, "\n");
  }
  close(fd);
}
