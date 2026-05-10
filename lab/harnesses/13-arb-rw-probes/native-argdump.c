#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((visibility("default")))
uint64_t record_args(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {
  const char *path = "/tmp/bun_uaf_native_argdump";
  FILE *f = fopen(path, "w");
  if (f) {
    fprintf(f, "a0=0x%016llx\n", (unsigned long long)a0);
    fprintf(f, "a1=0x%016llx\n", (unsigned long long)a1);
    fprintf(f, "a2=0x%016llx\n", (unsigned long long)a2);
    fprintf(f, "a3=0x%016llx\n", (unsigned long long)a3);
    fprintf(f, "a4=0x%016llx\n", (unsigned long long)a4);
    fprintf(f, "a5=0x%016llx\n", (unsigned long long)a5);
    fprintf(f, "a6=0x%016llx\n", (unsigned long long)a6);
    fprintf(f, "a7=0x%016llx\n", (unsigned long long)a7);
    if (a0) {
      const unsigned char *p = (const unsigned char *)a0;
      fprintf(f, "a0_bytes=");
      for (unsigned i = 0; i < 32; i++) {
        fprintf(f, "%02x", p[i]);
      }
      fprintf(f, "\n");
    }
    fclose(f);
  }
  return 0x41424344ULL;
}
