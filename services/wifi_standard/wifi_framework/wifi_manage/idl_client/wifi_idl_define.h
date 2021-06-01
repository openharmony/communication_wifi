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

#ifndef OHOS_WIFIIDLEVENTDEFINE_H
#define OHOS_WIFIIDLEVENTDEFINE_H

/* IWifiEventCallback */
#define WIFI_IDL_CBK_CMD_FAILURE 100 /* Driver loading/unloading failure */
#define WIFI_IDL_CBK_CMD_STARTED 101 /* The driver has been loaded. */
#define WIFI_IDL_CBK_CMD_STOPED 102  /* The Wi-Fi driver has been uninstalled. */
/* IWifiChipEventCallback */
#define WIFI_IDL_CBK_CMD_ADD_IFACE 103    /* The network device interface has been added. */
#define WIFI_IDL_CBK_CMD_REMOVE_IFACE 104 /* The network device interface has been deleted. */
/* AP AsscociatedEvent */
#define WIFI_IDL_CBK_CMD_STA_JOIN 105  /* STA connection notification in AP mode */
#define WIFI_IDL_CBK_CMD_STA_LEAVE 106 /* STA leaving notification in AP mode */
/* SupplicantEventCallback */
#define WIFI_IDL_CBK_CMD_SCAN_RESULT_NOTIFY 107 /* SCAN Scan Result Notification */
#define WIFI_IDL_CBK_CMD_CONNECT_CHANGED 108    /* Connection status change notification */
#define WIFI_IDL_CBK_CMD_AP_ENABLE 109          /* AP enabling notification */
#define WIFI_IDL_CBK_CMD_AP_DISABLE 110         /* AP closure notification */
#define WIFI_IDL_CBK_CMD_WPA_STATE_CHANGEM 111  /* WPA status change notification */
#define WIFI_IDL_CBK_CMD_SSID_WRONG_KEY 112     /* Password error status notification */
#define WIFI_IDL_CBK_CMD_WPS_OVERLAP 113        /* wps PBC overlap */
#define WIFI_IDL_CBK_CMD_WPS_TIME_OUT 114       /* wps connect time out */

#define SINGLE_SCAN_FAILED 1  /* Scan failure notification */
#define SINGLE_SCAN_OVER_OK 2 /* Scan success notification */
#define PNO_SCAN_OVER_OK 3    /* PNO Scan success notification */
#define WPA_CB_CONNECTED 1    /* The connection is successfully. */
#define WPA_CB_DISCONNECTED 2 /* Disconnect */

#define WIFI_IDL_GET_MAX_SCAN_RESULT 256 /* Maximum number of scan results obtained at a time */
#define WIFI_IDL_GET_MAX_NETWORK_LIST 100
#define WIFI_IDL_GET_MAX_BANDS 16                   /* Obtains the number of bands. */
#define WIFI_IDL_INTERFACE_SUPPORT_COMBINATIONS 256 /* chip support valid interface combinations */
#define WIFI_IDL_GET_INTERFACE_NUMS 16              /* max get interface size */

#define WIFI_PSK_MIN_LENGTH (8)
#define WIFI_PSK_MAX_LENGTH (63)

#endif