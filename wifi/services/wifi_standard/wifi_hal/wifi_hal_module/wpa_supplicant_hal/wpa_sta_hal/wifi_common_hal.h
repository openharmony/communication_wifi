/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_COMMON_HAL_H
#define WIFI_COMMON_HAL_H

#include "server.h"
#include "wifi_hal_struct.h"
#include "wifi_hal_define.h"
#include "wifi_hal_chba_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_CMD_STR_LENGTH 512

typedef struct stWifiWpaChbaInterface WifiWpaChbaInterface;
struct stWifiWpaChbaInterface {
    char ifname[WIFI_IFACE_NAME_MAXLEN];
    ChbaSupplicantErrCode (*wpaChbaCliCmdCreateGroup)(WifiWpaChbaInterface *p, int freq);
    ChbaSupplicantErrCode (*wpaChbaCliCmdRemoveGroup)(WifiWpaChbaInterface *p, const char *ifname);
    ChbaSupplicantErrCode (*wpaChbaCliCmdConnect)(WifiWpaChbaInterface *p, const ChbaConnectInfo *connect);
    ChbaSupplicantErrCode (*wpaChbaCliCmdDisConnect)(WifiWpaChbaInterface *p, const char *ifname, const char *address);
    ChbaSupplicantErrCode (*wpaChbaCliCmdConnectNotify)(WifiWpaChbaInterface *p, const ChbaConnNotifyInfo *connectNotify);
};


/**
 * @Description Receive the issued string command and send.
 *
 * @param sendcmd - send hal common cmd
 * @return int 0 successful -1 failed
 */
int SendComCmd(const char* sendcmd);

/**
 * @Description send the issued string command.
 *
 * @param event - recv common notify
 * @return int 0 successful
 */
int HalCallbackNotify(const char* event);

/**
 * @Description Get wpa interface about wpachba.
 *
 * @return WifiWpaChbaInterface*.
 */
WifiWpaChbaInterface *GetWifiWpaChbaInterface();

/**
 * @Description Release wpachba interface
 */
void ReleaseWpaChbaInterface(void);
#ifdef __cplusplus
}
#endif
#endif