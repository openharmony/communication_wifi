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

#ifndef WIFI_WPA_CLI_HAL_H
#define WIFI_WPA_CLI_HAL_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include "wifi_hal_struct.h"
#include "wifi_hal_define.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSSID_LENG 20
#define SSID_LENG 128
#define KEY_MGMT_LENG 20
#define FLAGS_LENG 128
#define NUM_LENG 32

#define REPLY_BUF_LENGTH 4096
#define REPLY_BUF_SMALL_LENGTH 32
#define CMD_RTUEN_TIMEOUT (-2)
#define CMD_RETURN_FAIL (-1)
#define CMD_RETURN_OK_LENGTH 2
#define CMD_RESULT_MAX_NUM 100

/* Register event callback, event type */
#define WPA_CB_EVENT_SCAN_NOTIFY 1    /* Scan end event */
#define WPA_CB_EVENT_CONNECT_NOTIFY 2 /* Connection status event */
#define WPA_CB_EVENT_WPA_STATUS 3     /* WPA status change event */
#define WPA_CB_EVENT_WRONG_KEY 4      /* incorrect password */
#define WPA_CB_EVENT_WPS_OVERLAP 5    /* wps_pbc_overlap */
#define WPA_CB_EVENT_WPS_TIME_OUT 6   /* wps connect time out */

#define WPA_CB_SCAN_FAILED 1
#define WPA_CB_SCAN_OVER_OK 2
#define WPA_CB_CONNECTED 1
#define WPA_CB_DISCONNECTED 2

/* ******************** wpa_cli struct*************** */
struct WpaHalCmdStatus {
    char bssid[BSSID_LENG];
    int freq;
    char ssid[SSID_LENG];
    int id;
    char key_mgmt[KEY_MGMT_LENG];
    char address[BSSID_LENG];
};

struct WpaSetNetworkArgv {
    int id;          /* network id */
    DeviceConfigType param; /* set network param */
    char value[WIFI_NETWORK_CONFIG_VALUE_LENGTH];  /* set network value */
};

typedef struct WpaSsidField {
    DeviceConfigType field;
    char fieldName[32];
    int flag; /* 0 need add "" 1 no need */
} WpaSsidField;

struct WpaGetNetworkArgv {
    int id;                  /* network id. */
    char parame[FLAGS_LENG]; /* parameter */
};

struct WpaWpsPbcArgv {
    int anyflag;
    int multi_ap;
    char bssid[SSID_LENG];
};

struct WpaWpsPinArgv {
    char bssid[SSID_LENG];
};

/* ***************** wpa_cli struct end*********************** */

/* Defines the HAL device structure. */
typedef struct WifiHalDevice {
    struct wpa_ctrl *ctrlConn; /* Deliver messages to wpa_supplicant. */
    struct wpa_ctrl *monConn;  /* Receives messages reported by wpa_supplicant. */
    pthread_t tid;
    int threadRunFlag;

    /* ******************** wpa_cli Function Interface********************** */
    int (*WifiWpaCliConnectWpa)();
    void (*WifiWpaCliWpaCtrlClose)();
    int (*WpaCliCmdStatus)(struct WpaHalCmdStatus *pcmd);
    int (*WpaCliCmdAddNetworks)();
    int (*WpaCliCmdReconnect)();
    int (*WpaCliCmdReassociate)();
    int (*WpaCliCmdDisconnect)();
    int (*WpaCliCmdSaveConfig)();
    int (*WpaCliCmdSetNetwork)(const struct WpaSetNetworkArgv *argv);
    int (*WpaCliCmdEnableNetwork)(int networkId);
    int (*WpaCliCmdSelectNetwork)(int networkId);
    int (*WpaCliCmdDisableNetwork)(int networkId);
    int (*WpaCliCmdRemoveNetwork)(int networkId);
    int (*WpaCliCmdGetNetwork)(const struct WpaGetNetworkArgv *argv, char *pcmd, unsigned size);
    int (*WpaCliCmdWpsPbc)(const struct WpaWpsPbcArgv *wpspbc);
    int (*WpaCliCmdWpsPin)(const struct WpaWpsPinArgv *wpspin, int *pincode);
    int (*WpaCliCmdWpsCancel)();
    int (*WpaCliCmdPowerSave)(BOOL enable);
    int (*WpaCliCmdSetCountryCode)(const char *countryCode);
    int (*WpaCliCmdGetCountryCode)(char *countryCode, int codeSize);
    int (*WpaCliCmdSetAutoConnect)(int enable);
    int (*WpaCliCmdReconfigure)();
    int (*WpaCliCmdWpaBlockListClear)();
    int (*WpaCliCmdListNetworks)(NetworkList *pcmd, int *size);
    int (*WpaCliCmdScan)(const ScanSettings *settings);
    int (*WpaCliCmdScanResult)(ScanResult *pcmd, int *size);

    /* ******************************* wpa_cli end******************************** */
} WifiHalDevice;

/* This interface is used to open a device for external invocation. */
/**
 * @Description Get the Wifi Hal Dev object.
 *
 * @return WifiHalDevice*.
 */
WifiHalDevice *GetWifiHalDev(void);
/**
 * @Description Get the Wifi Hal Dev object.
 *
 */
void ReleaseWpaHalDev(void);

#ifdef __cplusplus
}
#endif
#endif