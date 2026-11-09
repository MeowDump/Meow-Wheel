#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <mntent.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <sched.h>
#include <unistd.h>
#include <limits.h>

#include "utils.h"
#include "elf_util.h"

#include "zygisk.h"

static struct maps *g_maps = NULL;

struct maps *get_global_maps(void) {
  return g_maps;
}

int do_preinitialize(void) {
  g_maps = parse_maps("/proc/self/maps");
  if (!g_maps) {
    LOGE("Failed to parse /proc/self/maps");

    return 0;
  }

  LOGI("Parsed /proc/self/maps, found %zu maps", g_maps->size);

  return 1;
}

void do_deinitialize(void) {
  if (g_maps) {
    free_maps(g_maps);
    g_maps = NULL;

    LOGI("Deinitialized /proc/self/maps");
  }
}

int do_gsi_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table; (void) tw_env;

  LOGI("GH: GSI hiding is enabled, hiding traces.");

  if (getenv("PHH_STEP1")) unsetenv("PHH_STEP1");
  if (getenv("PHH_STEP2")) unsetenv("PHH_STEP2");
  if (getenv("PHH_STEP3")) unsetenv("PHH_STEP3");

  LOGI("GH: Finished hiding GSI traces.");

  return 1;
}

#define BIONIC_LINE_BUFFER_SIZE 1024

/*
 * mincore() catches unmapped ranges; /proc/self/maps additionally ensures the
 * complete range is writable before we overwrite the cached mount entry.
 */
static bool zmlh_range_is_writable(const void *addr, size_t length) {
  if (!addr || length == 0) return false;

  uintptr_t start = (uintptr_t)addr;
  if (length > UINTPTR_MAX - start) return false;
  uintptr_t end = start + length;

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return false;

  uintptr_t page_start = start - (start % (uintptr_t)page_size);
  uintptr_t span = end - page_start;
  if (span > UINTPTR_MAX - ((uintptr_t)page_size - 1)) return false;
  uintptr_t page_span = ((span + (uintptr_t)page_size - 1) / (uintptr_t)page_size) * (uintptr_t)page_size;
  size_t page_count = (size_t)(page_span / (uintptr_t)page_size);

  unsigned char vec[8];
  if (page_count == 0 || page_count > sizeof(vec) ||
      mincore((void *)page_start, (size_t)page_span, vec) == -1) return false;

  FILE *maps_fp = fopen("/proc/self/maps", "r");
  if (!maps_fp) {
    PLOGE("ZMLH: Open /proc/self/maps");
    return false;
  }

  char line[512];
  bool writable = false;
  while (fgets(line, sizeof(line), maps_fp)) {
    unsigned long long map_start = 0;
    unsigned long long map_end = 0;
    char perms[5] = { 0 };

    if (sscanf(line, "%llx-%llx %4s", &map_start, &map_end, perms) != 3) continue;
    if ((uintptr_t)map_start <= start && (uintptr_t)map_end >= end) {
      writable = perms[1] == 'w';
      break;
    }
  }

  fclose(maps_fp);
  return writable;
}

static bool zmlh_cached_mntent_is_valid(const char *addr) {
  return zmlh_range_is_writable(addr, BIONIC_LINE_BUFFER_SIZE);
}

static bool zmlh_capture_mntent(char *mntent_string, char **mntent_line) {
  int pipes[2];
  if (pipe(pipes) == -1) {
    PLOGE("ZMLH: Pipe");
    return false;
  }

  int pid = syscall(SYS_clone, SIGCHLD, 0);
  if (pid == -1) {
    PLOGE("ZMLH: Clone");
    close(pipes[0]);
    close(pipes[1]);
    return false;
  }

  if (pid == 0) {
    close(pipes[0]);

    FILE *fp = setmntent("/proc/self/mounts", "r");
    if (!fp) {
      PLOGE("ZMLH: setmntent mounts");
      close(pipes[1]);
      _exit(1);
    }

    uintptr_t value = 0;
    while (true) {
      struct mntent *entry = getmntent(fp);
      if (!entry) break;
      /* mnt_fsname points to the beginning of bionic's reusable line buffer. */
      value = (uintptr_t)entry->mnt_fsname;
    }
    endmntent(fp);

    if (value == 0 ||
        write_loop(pipes[1], (void *)value, BIONIC_LINE_BUFFER_SIZE) != BIONIC_LINE_BUFFER_SIZE ||
        write_loop(pipes[1], &value, sizeof(value)) != sizeof(value)) {
      PLOGE("ZMLH: Write captured mount entry");
      close(pipes[1]);
      _exit(1);
    }

    close(pipes[1]);
    _exit(0);
  }

  close(pipes[1]);
  ssize_t string_size = read_loop(pipes[0], mntent_string, BIONIC_LINE_BUFFER_SIZE);
  ssize_t pointer_size = string_size == BIONIC_LINE_BUFFER_SIZE
      ? read_loop(pipes[0], mntent_line, sizeof(*mntent_line)) : -1;
  close(pipes[0]);

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited == -1 && errno == EINTR);

  if (string_size != BIONIC_LINE_BUFFER_SIZE || pointer_size != (ssize_t)sizeof(*mntent_line) ||
      waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    LOGE("ZMLH: Failed to capture mount entry from child process");
    return false;
  }

  LOGD("ZMLH: Captured mount entry: %.*s", BIONIC_LINE_BUFFER_SIZE, mntent_string);
  return true;
}

static bool zmlh_publish_mntent(uint8_t result, char *mntent_line, char *mntent_string) {
  if (write_loop(cfd, &result, sizeof(result)) != sizeof(result)) {
    PLOGE("ZMLH: Write mount cache result");
    return false;
  }

  if (result != MNT_CACHE_READY) return true;

  if (write_loop(cfd, &mntent_line, sizeof(mntent_line)) != sizeof(mntent_line) ||
      write_loop(cfd, mntent_string, BIONIC_LINE_BUFFER_SIZE) != BIONIC_LINE_BUFFER_SIZE) {
    PLOGE("ZMLH: Publish mount cache");
    return false;
  }

  return true;
}

static bool zmlh_read_cached_mntent(char *mntent_string, char **mntent_line) {
  if (read_loop(cfd, mntent_line, sizeof(*mntent_line)) != (ssize_t)sizeof(*mntent_line) ||
      read_loop(cfd, mntent_string, BIONIC_LINE_BUFFER_SIZE) != BIONIC_LINE_BUFFER_SIZE) {
    PLOGE("ZMLH: Read cached mount entry");
    return false;
  }

  return true;
}

static bool zmlh_query_mnt_cache(uint8_t *cache_state) {
  enum daemon_operations op = DAEMON_GET_MNT_STRING;
  if (write_loop(cfd, &op, sizeof(op)) != sizeof(op) ||
      read_loop(cfd, cache_state, sizeof(*cache_state)) != (ssize_t)sizeof(*cache_state)) {
    PLOGE("ZMLH: Query mount cache");
    return false;
  }

  return true;
}

static bool zmlh_clear_mnt_cache(void) {
  enum daemon_operations op = DAEMON_CLEAR_MNT_STRING;
  if (write_loop(cfd, &op, sizeof(op)) != sizeof(op)) {
    PLOGE("ZMLH: Clear mount cache");
    return false;
  }

  return true;
}

int do_zygote_mountinfo_leak_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table; (void) tw_env;

  LOGI("ZMLH: Zygote mountinfo leak hiding is enabled, hiding traces.");

  static char mntent_string[BIONIC_LINE_BUFFER_SIZE];
  char *mntent_line = NULL;
  uint8_t cache_state = MNT_CACHE_EMPTY;

  if (!zmlh_query_mnt_cache(&cache_state)) return 0;

  if (cache_state == MNT_CACHE_SKIP) {
    LOGI("ZMLH: Companion marked mount entry as unsafe; skipping.");
    return 1;
  }

  if (cache_state == MNT_CACHE_READY) {
    if (!zmlh_read_cached_mntent(mntent_string, &mntent_line)) return 0;

    if (!zmlh_cached_mntent_is_valid(mntent_line)) {
      LOGW("ZMLH: Cached mount entry address %p is stale; recapturing.", (void *)mntent_line);
      if (!zmlh_clear_mnt_cache() || !zmlh_query_mnt_cache(&cache_state)) return 0;

      if (cache_state == MNT_CACHE_SKIP) return 1;

      if (cache_state == MNT_CACHE_READY) {
        if (!zmlh_read_cached_mntent(mntent_string, &mntent_line)) return 0;
        if (!zmlh_cached_mntent_is_valid(mntent_line)) {
          LOGW("ZMLH: Replacement mount entry address %p is still invalid; skipping.", (void *)mntent_line);
          if (!zmlh_clear_mnt_cache() || !zmlh_query_mnt_cache(&cache_state)) return 0;
          if (cache_state != MNT_CACHE_EMPTY) return cache_state == MNT_CACHE_SKIP;
        }
      }
    }
  }

  if (cache_state == MNT_CACHE_EMPTY) {
    if (!zmlh_capture_mntent(mntent_string, &mntent_line)) {
      if (!zmlh_publish_mntent(MNT_CACHE_EMPTY, NULL, NULL)) return 0;
      return 0;
    }

    if (!zmlh_cached_mntent_is_valid(mntent_line)) {
      LOGW("ZMLH: Captured mount entry address %p is unsafe to overwrite; skipping.", (void *)mntent_line);
      if (!zmlh_publish_mntent(MNT_CACHE_SKIP, NULL, NULL)) return 0;
      return 1;
    }

    memcpy(mntent_line, mntent_string, BIONIC_LINE_BUFFER_SIZE);
    return zmlh_publish_mntent(MNT_CACHE_READY, mntent_line, mntent_string) ? 1 : 0;
  }

  if (cache_state == MNT_CACHE_READY) {
    if (!mntent_line) {
      LOGE("ZMLH: Companion returned a NULL mount entry address.");
      return 0;
    }

    memcpy(mntent_line, mntent_string, BIONIC_LINE_BUFFER_SIZE);
  } else if (cache_state != MNT_CACHE_EMPTY && cache_state != MNT_CACHE_SKIP) {
    LOGE("ZMLH: Unexpected mount cache state %u", cache_state);
    return 0;
  }

  #ifdef DEBUG
    char mntent_log[BIONIC_LINE_BUFFER_SIZE + 1] = { 0 };
    memcpy(mntent_log, mntent_string, BIONIC_LINE_BUFFER_SIZE);
    for (size_t i = 0; i < BIONIC_LINE_BUFFER_SIZE; i++) {
      if (mntent_log[i] == '\0') mntent_log[i] = ' ';
    }
    LOGI("ZMLH: Finished hiding Zygote mountinfo leak traces: %s", mntent_log);
  #endif

  return 1;
}

int do_maps_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table; (void) tw_env;

  LOGI("MH: Maps hiding is enabled, hiding traces.");

  struct stat st;
  if (stat("/data", &st) == -1) {
    PLOGE("MH: Stat /data");

    return 0;
  }

  if (g_maps->size == 0) {
    LOGI("MH: No suspicious maps found, returning.");

    return 1;
  }

  for (size_t i = 0; i < g_maps->size; i++) {
    struct map *map = &g_maps->maps[i];

    if (map->path == NULL || map->dev != st.st_dev ||
        str_starts_with(map->path, "/data/adb/modules/rezygisk/") ||
        str_starts_with(map->path, "/data/adb/modules/treat_wheel/") ||
        (!str_starts_with(map->path, "/data/adb/") &&
        !str_starts_with(map->path, "/data/local/tmp/"))
    ) {
      continue;
    }

    LOGI("MH: Hiding suspicious map: %p - %p", (void *)map->addr_start, (void *)map->addr_end);

    size_t size = (size_t)(map->addr_end - map->addr_start);
    void *copy = mmap(NULL, size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if ((map->perms & PROT_READ) == 0) mprotect((void *)map->addr_start, size, PROT_READ);

    memcpy(copy, (void *)map->addr_start, size);
    mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, (void *)map->addr_start);
    mprotect((void *)map->addr_start, size, map->perms);
  }

  LOGI("MH: Finished hiding maps traces.");

  return 1;
}

int do_revanced_mounts_umount(struct api_table *api_table, JNIEnv *tw_env, const char *process_name) {
  (void) api_table; (void) tw_env;

  LOGI("RVU: Revanced mounts umount is enabled, hiding traces.");

  enum daemon_operations op = DAEMON_GET_RVX_MOUNTS;
  if (write(cfd, &op, sizeof(op)) == -1) {
    PLOGE("RVU: Write operation");

    return 0;
  }

  LOGD("RVU: Waiting for ReVanced mounts data...");

  pid_t pid = getpid();
  if (write_loop(cfd, &pid, sizeof(pid)) == -1) {
    PLOGE("RVU: Write pid");

    return 0;
  }

  size_t process_name_len = strlen(process_name);
  if (write_loop(cfd, &process_name_len, sizeof(process_name_len)) == -1) {
    PLOGE("RVU: Write process_name_len");

    return 0;
  }

  if (write_loop(cfd, process_name, process_name_len) == -1) {
    PLOGE("RVU: Write process_name");

    return 0;
  }

  uint8_t has_rvx_checked;
  if (read(cfd, &has_rvx_checked, sizeof(has_rvx_checked)) == -1) {
    PLOGE("RVU: Read has_rvx_checked");

    return 0;
  }

  if (has_rvx_checked == 0) {
    LOGI("RVU: Something went wrong, returning.");

    return 1;
  }

  LOGI("RVU: Finished hiding revanced mounts traces.");

  return 1;
}

int do_custom_font_loading(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table; (void) tw_env;

  LOGI("CFL: Custom font loading is enabled, hiding traces.");

  enum daemon_operations op = DAEMON_CHECK_FONTS;
  if (write(cfd, &op, sizeof(op)) == -1) {
    PLOGE("CFL: Write operation");

    return 0;
  }

  uint8_t finished_verifying;
  if (read(cfd, &finished_verifying, sizeof(finished_verifying)) == -1) {
    PLOGE("CFL: Read verification");

    return 0;
  }

  if (finished_verifying == 0) {
    LOGI("CFL: No custom fonts to be loaded, returning.");

    return 1;
  }

  size_t fonts_length;
  if (read_loop(cfd, &fonts_length, sizeof(fonts_length)) == -1) {
    PLOGE("CFL: Read fonts length");

    return 0;
  }

  int *fonts_fds = (int *)calloc(fonts_length, sizeof(int));
  if (!fonts_fds) {
    PLOGE("CFL: Allocate memory for fonts fds");

    return 0;
  }

  for (size_t i = 0; i < fonts_length; i++) {
    fonts_fds[i] = read_fd(cfd);
    if (fonts_fds[i] == -1) {
      PLOGE("CFL: Read font cfd");

      for (size_t j = 0; j < i; j++) {
        if (fonts_fds[j] == 0) continue;

        close(fonts_fds[j]);
      }
      free(fonts_fds);

      return 0;
    }

    LOGI("CFL: Found font cfd: %d", fonts_fds[i]);
  }

  jclass font_class = (*tw_env)->FindClass(tw_env, "android/graphics/Typeface");
  if (font_class == NULL) {
    LOGE("CFL: Failed to find Typeface class");

    for (size_t j = 0; j < fonts_length; j++) {
      if (fonts_fds[j] == 0) continue;

      close(fonts_fds[j]);
    }
    free(fonts_fds);

    return 0;
  }

  jmethodID native_warm_up_cache = (*tw_env)->GetStaticMethodID(tw_env, font_class, "nativeWarmUpCache", "(Ljava/lang/String;)V");
  if (native_warm_up_cache == NULL) {
    LOGE("CFL: Failed to find nativeWarmUpCache method");

    (*tw_env)->ExceptionClear(tw_env);

    for (size_t j = 0; j < fonts_length; j++) {
      if (fonts_fds[j] == 0) continue;

      close(fonts_fds[j]);
    }
    free(fonts_fds);

    return 0;
  }

  for (size_t i = 0; i < fonts_length; i++) {
    if (fonts_fds[i] == 0) continue;

    char tmp_file_path[PATH_MAX];
    snprintf(tmp_file_path, sizeof(tmp_file_path), "/proc/self/fd/%d", fonts_fds[i]);

    (*tw_env)->CallStaticVoidMethod(tw_env, font_class, native_warm_up_cache, (*tw_env)->NewStringUTF(tw_env, tmp_file_path));

    if ((*tw_env)->ExceptionCheck(tw_env)) {
      LOGE("CFL: Exception occurred while calling nativeWarmUpCache");

      (*tw_env)->ExceptionClear(tw_env);

      goto cleanup;
    }

    LOGI("CFL: Warmed up cache for font cfd: %d", fonts_fds[i]);

    continue;

    cleanup:
      for (size_t j = 0; j < fonts_length; j++) {
        close(fonts_fds[j]);
      }
      free(fonts_fds);

      return 0;
  }

  for (size_t i = 0; i < fonts_length; i++) {
    if (fonts_fds[i] == 0) continue;

    close(fonts_fds[i]);
  }

  free(fonts_fds);

  LOGI("CFL: Finished hiding custom font loading traces.");

  return 1;
}

int do_denylist_logic_inversion(struct api_table *api_table, JNIEnv *tw_env, enum process_flags flags) {
  (void) api_table; (void) tw_env;

  LOGI("DLI: Denylist logic inversion is enabled, inverting logic.");

  if ((flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
    LOGI("DLI: Process is Root Manager, skipping.");

    return 1;
  }

  if ((flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST) {
    LOGI("DLI: Process is on denylist, setting mount namespace to Mounted.");

    update_mnt_ns(Mounted);
  } else {
    LOGI("DLI: Process is not on denylist, setting mount namespace to Clean.");

    update_mnt_ns(Clean);
  }

  LOGI("DLI: Finished inverting denylist logic.");

  return 1;
}

struct AtExitEntry {
  void (*func_ptr)(void*);
  void *arg;
  void *dso_handle;
};

struct AtExitArray {
  struct AtExitEntry *array_;
  size_t size_;
  size_t extracted_count_;
  size_t capacity_;
  // An entry can be appended by a __cxa_finalize callback. Track the number of appends so we
  // restart concurrent __cxa_finalize passes.
  uint64_t total_appends_;
};

static size_t system_page_size = 0;

static inline uintptr_t _page_start(uintptr_t addr) {
  return addr & ~(system_page_size - 1);
}

static inline uintptr_t _page_end(uintptr_t addr) {
  return _page_start(addr + system_page_size - 1);
}

int set_writable(struct AtExitArray *array, bool writable, size_t start_idx, size_t num_entries) {
  if (num_entries == 0) return 1;
  if (array == NULL || array->array_ == NULL || system_page_size == 0) return 0;
  if (start_idx > array->capacity_ || num_entries > array->capacity_ - start_idx) {
    LOGE("Invalid atexit protection range: start=%zu count=%zu capacity=%zu", start_idx, num_entries, array->capacity_);
    return 0;
  }
  if (start_idx > SIZE_MAX / sizeof(struct AtExitEntry) ||
      num_entries > SIZE_MAX / sizeof(struct AtExitEntry) - start_idx) {
    LOGE("Atexit protection range overflow");
    return 0;
  }

  size_t start_byte = _page_start(start_idx * sizeof(struct AtExitEntry));
  size_t stop_byte = _page_end((start_idx + num_entries) * sizeof(struct AtExitEntry));
  if (stop_byte <= start_byte) {
    LOGE("Invalid atexit page range: start=%zu end=%zu", start_byte, stop_byte);
    return 0;
  }
  size_t byte_len = stop_byte - start_byte;

  int prot = PROT_READ | (writable ? PROT_WRITE : 0);
  if (mprotect((char *)array->array_ + start_byte, byte_len, prot) != 0) {
    LOGE("Failed to mprotect atexit array: %s", strerror(errno));
    return 0;
  }

  LOGI("Atexit array set to %s writable from index %zu to %zu", writable ? "writable" : "read-only", start_idx, start_idx + num_entries - 1);
  return 1;
}

struct map_range {
  uintptr_t start;
  uintptr_t end;
};

int do_atexit_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table; (void) tw_env;

  LOGI("AH: Atexit hiding is enabled, hiding traces.");

  long new_system_page_size = sysconf(_SC_PAGESIZE);
  if (new_system_page_size <= 0) {
    LOGE("AH: Failed to get system page size");

    return 0;
  }
  system_page_size = (size_t)new_system_page_size;

  struct elf_img *libc = elf_create("libc.so", NULL);
  if (!libc) {
    LOGE("AH: Failed to create elf image for libc.so");

    return 0;
  }

  struct AtExitArray *atexit_array = (struct AtExitArray *)getSymbAddress(libc, "_ZL7g_array.0");
  if (!atexit_array) {
    atexit_array = (struct AtExitArray *)getSymbAddress(libc, "_ZL7g_array");
    if (!atexit_array) {
      LOGE("AH: Failed to find atexit array");

      elf_destroy(libc);

      return 0;
    }
  }

  pthread_mutex_t *atexit_lock = (pthread_mutex_t *)getSymbAddressByPrefix(libc, "_ZL13g_atexit_lock");
  if (!atexit_lock) {
    LOGE("AH: Failed to find atexit lock");

    elf_destroy(libc);

    return 0;
  }

  pthread_mutex_lock(atexit_lock);

  LOGD("AH: Found atexit array at %p with size %zu and capacity %zu", (void *)atexit_array->array_, atexit_array->size_, atexit_array->capacity_);

  // Some 32-bit bionic processes expose an empty atexit array here. Do not
  // calculate an inclusive end index for zero entries (size - 1 underflows).
  if (atexit_array->size_ == 0) {
    LOGI("AH: Atexit array is empty; skipping trace cleanup.");
    pthread_mutex_unlock(atexit_lock);
    elf_destroy(libc);
    return 1;
  }

  if (atexit_array->array_ == NULL || atexit_array->capacity_ == 0 ||
      atexit_array->size_ > atexit_array->capacity_) {
    LOGE("AH: Invalid atexit array metadata; skipping trace cleanup.");
    pthread_mutex_unlock(atexit_lock);
    elf_destroy(libc);
    return 0;
  }

  if (!set_writable(atexit_array, true, 0, atexit_array->size_)) {
    pthread_mutex_unlock(atexit_lock);
    elf_destroy(libc);
    return 0;
  }

  size_t old_size = atexit_array->size_;

  /* TODO: Optimize by quickly iterating to see which is the real end (without counting
             the Zygisk module handlers), and set the size to there, and before that, memset
             the old ones. */
  for (size_t i = atexit_array->size_; i > 0; i--) {
    struct AtExitEntry *entry = &atexit_array->array_[i - 1];

    if (entry->func_ptr == NULL) {
      size_t remove_index = i - 1;
      if (remove_index + 1 < atexit_array->size_)
        memmove(&atexit_array->array_[remove_index],  &atexit_array->array_[remove_index + 1],  (atexit_array->size_ - remove_index - 1) * sizeof(struct AtExitEntry));

      atexit_array->size_--;
      if (atexit_array->total_appends_ > 0) atexit_array->total_appends_--;

      LOGD("AH: Removed atexit entry at index %zu, new size is %zu", remove_index, atexit_array->size_);

      continue;
    }

    Dl_info info;
    if (dladdr((void *)entry->func_ptr, &info) == 0) {
      LOGE("AH: Failed to get dladdr for atexit entry at index %zu (%p), skipping", i - 1, (void *)entry->func_ptr);

      continue;
    }

    if (strstr(info.dli_fname, "libminikin.so") != NULL) {
      LOGD("AH: Found Minikin entry at index %zu, stopping.", i - 1);

      break;
    }

    // LOGD("AH: Atexit entry at index %zu: func_ptr=%p (%s), arg=%p, dso_handle=%p", i - 1, (void *)entry->func_ptr, info.dli_fname, entry->arg, entry->dso_handle);
  }

  size_t old_bytes = _page_end(old_size * sizeof(struct AtExitEntry));
  size_t new_bytes = _page_end(atexit_array->size_ * sizeof(struct AtExitEntry));
  if (new_bytes < old_bytes) {
    madvise((char *)atexit_array->array_ + new_bytes, old_bytes - new_bytes, MADV_DONTNEED);
  }

  // Restore protection over the full range made writable above, even if all
  // entries were removed while cleaning the array.
  if (!set_writable(atexit_array, false, 0, old_size)) {
    pthread_mutex_unlock(atexit_lock);
    elf_destroy(libc);
    return 0;
  }

  pthread_mutex_unlock(atexit_lock);

  elf_destroy(libc);

  LOGI("AH: Finished hiding __cxa_atexit traces.");

  return 1;
}

typedef void SoInfo;

int do_frida_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table; (void) tw_env;

  LOGI("FH: Frida hiding is enabled, hiding traces.");

  struct elf_img *linker = elf_create("/linker", NULL);
  if (!linker) {
    LOGE("FH: Failed to create elf image for linker");

    return 0;
  }

  void (*protected_data_protect)(void) = (void (*)(void))getSymbAddress(linker, "__dl__ZN18ProtectedDataGuardD2Ev");
  if (!protected_data_protect) {
    protected_data_protect = (void (*)(void))getSymbAddress(linker, "__dl__ZN18ProtectedDataGuardD1Ev");
  
    if (!protected_data_protect) {
      LOGE("FH: Failed to find protected_data_protect");

      elf_destroy(linker);

      return 0;
    }
  }

  void (*protected_data_unprotect)(void) = (void (*)(void))getSymbAddress(linker, "__dl__ZN18ProtectedDataGuardC2Ev");
  if (!protected_data_unprotect) {
    protected_data_unprotect = (void (*)(void))getSymbAddress(linker, "__dl__ZN18ProtectedDataGuardC1Ev");
    if (!protected_data_unprotect) {
      LOGE("FH: Failed to find protected_data_unprotect");

      elf_destroy(linker);

      return 0;
    }
  }

  const char *(*get_realpath)(void *) = (const char *(*)(void *))getSymbAddress(linker, "__dl__ZNK6soinfo12get_realpathEv");
  if (!get_realpath) {
    LOGE("FH: Failed to find get_realpath");

    elf_destroy(linker);

    return 0;
  }

  void (*soinfo_unload)(SoInfo *) = (void (*)(SoInfo *))getSymbAddressByPrefix(linker, "__dl__ZL13soinfo_unloadP6soinfo");
  if (!soinfo_unload) {
    LOGE("FH: Failed to find soinfo_unload");

    elf_destroy(linker);

    return 0;
  }

  SoInfo *(*solist_get_head)(void) = (SoInfo *(*)(void))getSymbAddress(linker, "__dl__Z15solist_get_headv");
  if (!solist_get_head) {
    LOGE("FH: Failed to find solist_get_head");

    elf_destroy(linker);

    return 0;
  }

  SoInfo *head = solist_get_head();
  if (!head) {
    LOGE("FH: solist_get_head returned NULL");

    elf_destroy(linker);

    return 0;
  }

  LOGI("FH: Found head of SoInfo list at %p", head);

  SoInfo *somain = getSymbValueByPrefix(linker, "__dl__ZL6somain");
  if (somain == NULL) {
    LOGE("FH: Failed to find somain __dl__ZL6somain");

    elf_destroy(linker);

    return 0;
  }

  SoInfo *(*solist_get_vdso)(void) = (SoInfo *(*)(void))getSymbAddress(linker, "__dl__Z15solist_get_vdsov");
  if (solist_get_vdso == NULL) {
    LOGE("FH: Failed to find solist_get_vdso");

    elf_destroy(linker);

    return 0;
  }

  SoInfo *vdso = solist_get_vdso();
  LOGI("FH: Found vdso at %p", vdso);

  SoInfo *solinker = getSymbValueByPrefix(linker, "__dl__ZL8solinker");
  if (solinker == NULL) {
    LOGE("FH: Failed to find solinker __dl__ZL8solinker");

    elf_destroy(linker);

    return 0;
  }

  LOGD("FH: Found solinker at %p", solinker);

  int solist_next_offset = -1;
  int solist_size_offset = -1;
  int solist_size_constructors_called_offset = -1;

  for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
    SoInfo *possible_next = *(void **)((uintptr_t)solist_get_head() + i * sizeof(void *));

    if (solist_next_offset == -1 && (possible_next == somain || possible_next == solinker || (vdso != NULL && possible_next == vdso)))
      solist_next_offset = i * sizeof(void *);

    size_t possible_size_of_somain = *(size_t *)((uintptr_t)somain + i * sizeof(void *));

    if (solist_size_offset == -1 && (possible_size_of_somain < 0x100000 && possible_size_of_somain > 0x100))
      solist_size_offset = i * sizeof(void *);

    if (solist_size_constructors_called_offset == -1) {
      uintptr_t field_solinker = (uintptr_t)solinker + i * sizeof(void *);
      struct link_map *map = (struct link_map *)field_solinker;

      size_t index_gap = (sizeof(struct link_map) + sizeof(void *) - 1) / sizeof(void *);
      uintptr_t look_forward = (uintptr_t)field_solinker + index_gap * sizeof(void *);

      bool *is_constructors_called = (bool *)look_forward;
      if (*is_constructors_called == true && map->l_name == get_realpath(solinker))
        solist_size_constructors_called_offset = look_forward - (uintptr_t)solinker;
    }

    if (solist_next_offset != -1 && solist_size_offset != -1 && solist_size_constructors_called_offset != -1) break;
  }

  if (solist_next_offset == -1 || solist_size_offset == -1 || solist_size_constructors_called_offset == -1) {
    LOGE("FH: Failed to find solist_next offset, solist_size_offset or solist_size_constructors_called_offset");

    elf_destroy(linker);

    return 0;
  }

  LOGI("FH: Found solist_next offset at %d", solist_next_offset);
  LOGI("FH: Found solist_size_offset at %d", solist_size_offset);
  LOGI("FH: Found solist_size_constructors_called_offset at %d", solist_size_constructors_called_offset);

  bool found_frida = false;
  for (SoInfo *so = head; so; so = *(SoInfo **)((uintptr_t)so + solist_next_offset)) {
    const char *realpath = get_realpath(so);
    if (!realpath || (!str_equal(realpath, "/memfd:frida-agent-64.so") && !str_equal(realpath, "/memfd:frida-agent-32.so"))) continue;

    LOGI("FH: Found frida SoInfo at %p with realpath %s, removing from list", so, realpath);

    found_frida = true;

    (*protected_data_unprotect)();
    *(size_t *)((uintptr_t)so + solist_size_offset) = 0;
    *(bool *)((uintptr_t)so + solist_size_constructors_called_offset) = false;
    soinfo_unload(so);
    (*protected_data_protect)();

    break;
  }

  if (found_frida) {
    size_t *g_module_load_counter = (size_t *)getSymbAddress(linker, "__dl__ZL21g_module_load_counter");
    if (g_module_load_counter) {
      LOGI("FH: Found g_module_load_counter at %p, decrementing", (void *)g_module_load_counter);

      (*g_module_load_counter)--;
    }

    size_t *g_module_unload_counter = (size_t *)getSymbAddress(linker, "__dl__ZL23g_module_unload_counter");
    if (g_module_unload_counter) {
      LOGI("FH: Found g_module_unload_counter at %p, decrementing", (void *)g_module_unload_counter);

      (*g_module_unload_counter)--;
    }
  }

  elf_destroy(linker);

  LOGI("FH: Finished hiding Frida traces.");

  return 1;
}
