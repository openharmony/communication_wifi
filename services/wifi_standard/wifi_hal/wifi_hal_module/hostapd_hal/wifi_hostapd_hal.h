/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WIFI_HOSTAPD_CLI_HAL_H
#define WIFI_HOSTAPD_CLI_HAL_H

#include <dirent.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include "wifi_hal_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PRINTF_BUF 1
#define RELOAD_PRINTF_BUF 1
#define BUFSIZE_VAL 128
#define BUFSIZE_KEY BUFSIZE_VAL
#define BUFSIZE_CMD 256
#define FILE_NAME_SIZE 256
#define BUFSIZE_LINE 1024
#define BUFSIZE_REQUEST 4096
#define BUFSIZE_REQUEST_SMALL 64
#define BUFSIZE_RECV 4096
#define MAC_MAX_LEN 32
#define PASSWD_MIN_LEN 8
#define FAIL_LENTH 4
#define OK_LENTH 2
#define UNKNOWN_COMMAND_LENTH 15
#define REQUEST_FAILED (-2)

#define BUFFER_SIZE_64 64
#define BUFFER_SIZE_32 32
#define BUFFER_SIZE_16 16

/* *************** hostapd_cli struct ******************* */
typedef struct StStatusInfo {
    char state[BUFFER_SIZE_16];
    char phy[BUFFER_SIZE_16];
    int freq;
    int channel;
    char supportedRates[BUFFER_SIZE_64];
    char bss[BUFFER_SIZE_16];
    char bssid[BUFFER_SIZE_32];
    char ssid[BUFFER_SIZE_32];
} StatusInfo;

typedef struct StApInfo {
    char ssid[BUFFER_SIZE_32];
    char passwd[BUFFER_SIZE_32];
    char authType[BUFFER_SIZE_16];
    int encryptionMode;
    int channel;
    char bssid[BUFFER_SIZE_32];
    char wpsState[BUFFER_SIZE_16];
    int wpa;
    char keyMgmt[BUFFER_SIZE_16];
    char groupCipher[BUFFER_SIZE_16];
    char rsnPairwiseCipher[BUFFER_SIZE_16];
} ApInfo;

typedef struct StDeviceInfo {
    char staSsid[BUFFER_SIZE_64];
    char staIp[BUFFER_SIZE_16];
    char staMac[BUFFER_SIZE_32];
    int aid;
    int listenInterval;
    char supportedRates[BUFFER_SIZE_64];
    char timeoutNext[BUFFER_SIZE_32];
    int rxPackets;
    int txPackets;
    int rxBytes;
    int txBytes;
} DeviceInfo;

/* ************** hostapd_cli struct end ***************** */

/* Defines the HAL device structure. */
typedef struct StWifiHostapdHalDevice {
    struct wpa_ctrl *ctrlConn;
    struct wpa_ctrl *ctrlRecv;
    pthread_t tid;
    int threadRunFlag;
    int execDisable;

    /* *************** hostapd_cli Function Interface************** */
    int (*hostapdCliConnect)(const char *ifname);
    int (*hostapdCliClose)();
    int (*setApInfo)(HostsapdConfig *info);
    int (*enableAp)();
    int (*disableAp)();
    int (*addBlocklist)(const char *mac);
    int (*delBlocklist)(const char *mac);
    int (*status)(StatusInfo *info);
    int (*showConnectedDevList)(char *info, const int *size);
    int (*reloadApConfigInfo)();
    int (*cancelVerify)(const char *mac);
    int (*disConnectedDev)(const char *mac);
    int (*setCountryCode)(const char *code);
    /* *********** hostapd_cli Function Interface end*************** */
} WifiHostapdHalDevice;

/**
 * @Description Get the Wifi Hostapd Dev object.
 *
 * @return WifiHostapdHalDevice*
 */
WifiHostapdHalDevice *GetWifiHostapdDev(void);
/**
 * @Description Release the Wifi Hostapd Dev object.
 *
 */
void ReleaseHostapdDev(void);

#ifdef __cplusplus
}
#endif
#endif /* WIFI_HOSTAPD_CLI_HAL_H */