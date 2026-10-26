/* INFO: MeowZygisk code */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#include <linux/un.h>

#include "utils.h"

#include "rz_daemon.h"

int rezygiskd_connect(uint8_t retry) {
  retry++;

  int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd == -1) {
    PLOGE("socket create");

    return -1;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };

  /* 
    INFO: Application must assume that sun_path can hold _POSIX_PATH_MAX characters.

    Sources:
     - https://pubs.opengroup.org/onlinepubs/009696699/basedefs/sys/un.h.html
  */
  strcpy(addr.sun_path, TMP_PATH "/" SOCKET_FILE_NAME);
  socklen_t socklen = sizeof(addr);

  while (--retry) {
    int ret = connect(fd, (struct sockaddr *)&addr, socklen);
    if (ret == 0) return fd;
    if (retry) {
      PLOGE("Retrying to connect to MeowZygiskd, sleep 1s");

      sleep(1);
    }
  }

  close(fd);

  return -1;
}

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) {
    PLOGE("connection to MeowZygiskd");

    return false;
  }

  write_uint8_t(fd, (uint8_t)UpdateMountNamespace);
  write_uint32_t(fd, (uint32_t)getpid());
  write_uint8_t(fd, (uint8_t)nms_state);

  uint32_t target_pid = 0;
  if (read_uint32_t(fd, &target_pid) < 0) {
    PLOGE("Failed to read target pid");

    close(fd);

    return false;
  }

  uint32_t target_fd = 0;
  if (read_uint32_t(fd, &target_fd) < 0) {
    PLOGE("Failed to read target fd");

    close(fd);

    return false;
  }

  if (target_fd == 0) {
    LOGE("Failed to get target fd");

    close(fd);

    return false;
  }

  snprintf(buf, buf_size, "/proc/%u/fd/%u", target_pid, target_fd);

  close(fd);

  return true;
}
