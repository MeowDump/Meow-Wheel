#ifndef HIDING_H
#define HIDING_H

#include <stdbool.h>
#include <stdint.h>

#include "zygisk.h"

struct maps *get_global_maps(void);

int do_preinitialize(void);

void do_deinitialize(void);

int do_gsi_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_zygote_mountinfo_leak_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_maps_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_revanced_mounts_umount(struct api_table *api_table, JNIEnv *tw_env, const char *process_name);

int do_custom_font_loading(struct api_table *api_table, JNIEnv *tw_env);

bool is_process_exempt_from_denylist(uint32_t process_flags);

int do_denylist_logic_inversion(struct api_table *api_table, JNIEnv *tw_env, uint32_t process_flags);

int do_atexit_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_frida_hiding(struct api_table *api_table, JNIEnv *tw_env);

#endif /* HIDING_H */
