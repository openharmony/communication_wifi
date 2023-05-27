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
#ifndef WIFI_HOSTAPD_HAL_H
#define WIFI_HOSTAPD_HAL_H

#include <dirent.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include "wifi_hal_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BUFSIZE_CMD 256
#define FILE_NAME_SIZE 256
#define BUFSIZE_REQUEST 4096
#define BUFSIZE_REQUEST_SMALL 64
#define BUFSIZE_RECV 4096
#define PASSWD_MIN_LEN 8
#define FAIL_LENGTH 4
#define UNKNOWN_COMMAND_LENGTH 15
#define REQUEST_FAILED (-2)
#define BUFFER_SIZE_128 128
#define BUFFER_SIZE_64 64
#define BUFFER_SIZE_32 32
#define BUFFER_SIZE_16 16

#if (AP_NUM > 1)
typedef enum EnApInstance {
    AP_5G_MAIN_INSTANCE,
    AP_2G_MAIN_INSTANCE,
    AP_MAX_INSTANCE
} ApInstance;
#else
typedef enum EnApInstance {
    AP_2G_MAIN_INSTANCE,
    AP_MAX_INSTANCE
} ApInstance;
#endif

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

/* Defines the HAL device structure. */
typedef struct StWifiHostapdHalDevice {
    struct wpa_ctrl *ctrlConn;
    struct wpa_ctrl *ctrlRecv;
    pthread_t tid;
    int threadRunFlag;
    int execDisable;
    int (*setApInfo)(HostapdConfig *info, int id);
    int (*enableAp)(int id);
    int (*disableAp)(int id);
    int (*addBlocklist)(const char *mac, int id);
    int (*delBlocklist)(const char *mac, int id);
    int (*status)(StatusInfo *info, int id);
    int (*showConnectedDevList)(char *info, int size, int id);
    int (*reloadApConfigInfo)(int id);
    int (*disConnectedDev)(const char *mac, int id);
    int (*setCountryCode)(const char *code, int id);
} WifiHostapdHalDevice;

typedef struct StWifiHostapdHalDeviceInfo {
    int id;
    WifiHostapdHalDevice *hostapdHalDev;
    char *cfgName;
    char *config;
    char *udpPort;
} WifiHostapdHalDeviceInfo;

WifiHostapdHalDeviceInfo *GetWifiCfg(int *len);
/**
 * @Description Get the Wifi Hostapd Dev object.
 *
 * @return WifiHostapdHalDevice*
 */
WifiHostapdHalDevice *GetWifiHostapdDev(int id);

/**
 * @Description Release the Wifi Hostapd Dev object.
 *
 */
void ReleaseHostapdDev(int id);

/**
 * @Description Hostpad string concatenation.
 *
 */
void GetDestPort(char *destPort, size_t len, int id);

#ifdef __cplusplus
}
#endif
#endif /* WIFI_HOSTAPD_HAL_H */