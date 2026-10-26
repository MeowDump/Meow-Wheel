/* INFO: MeowZygisk code */

#ifndef RZ_DAEMON_H
#define RZ_DAEMON_H

#include <stdbool.h>
#include <stdint.h>

#include <unistd.h>

#ifdef __LP64__
  #define LP_SELECT(lp32, lp64) lp64
#else
  #define LP_SELECT(lp32, lp64) lp32
#endif

#define SOCKET_FILE_NAME LP_SELECT("cp32", "cp64") ".sock"

enum rezygiskd_actions {
  PingHeartbeat,
  GetProcessFlags,
  GetInfo,
  ReadModules,
  RequestCompanionSocket,
  GetModuleDir,
  ZygoteRestart,
  UpdateMountNamespace
};

enum mount_namespace_state {
  Clean,
  Mounted
};

#define TMP_PATH "/data/adb/rezygisk"

int rezygiskd_connect(uint8_t retry);

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size);

#endif /* RZ_DAEMON_H */
