/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_NATIVE_DEFINE_H
#define OHOS_WIFI_NATIVE_DEFINE_H

#define HAL_MAX_WEPKEYS_SIZE 4
#define HAL_AUTH_ALGORITHM_MAX 8
#define HAL_PASSWORD_LEN 128
#define HAL_COUNTRY_CODE_LENGTH 2
#define HAL_GET_MAX_SCAN_INFO 256               /* Maximum number of scan infos obtained at a time */
#define HAL_GET_MAX_NETWORK_LIST 128
#define HAL_GET_MAX_BANDS 32                    /* Obtains the number of bands. */
#define HAL_INTERFACE_SUPPORT_COMBINATIONS 32   /* chip support valid interface combinations */
#define HAL_PSK_MIN_LENGTH 8
#define HAL_PSK_MAX_LENGTH 64
#define HAL_SAE_PSK_MIN_LENGTH 1
#define HAL_BSSID_LENGTH 17                     /* bssid - mac address length */
#define HAL_PIN_CODE_LENGTH 8
#define HAL_P2P_DEV_ADDRESS_LEN 32
#define HAL_P2P_LISTEN_MIN_TIME 1
#define HAL_P2P_LISTEN_MAX_TIME 65535
#define HAL_P2P_GO_INTENT_MIN_LENGTH 0
#define HAL_P2P_GO_INTENT_MAX_LENGTH 15
#define HAL_P2P_GO_INTENT_DEFAULT_LENGTH 6
#define HAL_P2P_TMP_BUFFER_SIZE_128 128
#define HAL_P2P_SERVICE_TYPE_MIN_SIZE 3
#define HAL_P2P_SERVICE_TYPE_2_POS 2

typedef enum DeathType {
    WPA_DEATH = 0,
    AP_DEATH = 1
} DeathType;

typedef enum HalScanResult {
    HAL_SINGLE_SCAN_FAILED = 1,     /* Scan failure notification */
    HAL_SINGLE_SCAN_OVER_OK = 2,    /* Scan success notification */
    HAL_PNO_SCAN_OVER_OK = 3,       /* PNO Scan success notification */
} HalScanResult;

typedef enum Hal80211ScanCmd {
    HAL_CMD_NEW_SCAN_RESULTS = 34,
    HAL_CMD_SCAN_ABORTED = 35,
    HAL_CMD_SCHED_SCAN_RESULTS = 77,
} Hal80211ScanCmd;
 
typedef enum HalConnectStatus {
    HAL_WPA_CB_CONNECTED = 1,
    HAL_WPA_CB_DISCONNECTED = 2,
    HAL_WPA_CB_ASSOCIATING = 3,
    HAL_WPA_CB_ASSOCIATED = 4,
} HalConnectStatus;

typedef enum HalPortType {
    HAL_PORT_TYPE_STATION    = 0,
    HAL_PORT_TYPE_AP         = 1,
    HAL_PORT_TYPE_P2P_CLIENT = 2,
    HAL_PORT_TYPE_P2P_GO     = 3,
    HAL_PORT_TYPE_P2P_DEVICE = 4,
    HAL_PORT_TYPE_BUTT,
} HalPortType;

typedef enum HalCallbackEvent {
    /* IWifiEventCallback */
    HAL_CBK_CMD_FAILURE = 100,      /* Driver loading/unloading failure */
    HAL_CBK_CMD_STARTED,            /* The driver has been loaded. */
    HAL_CBK_CMD_STOPED,             /* The Wi-Fi driver has been uninstalled. */

    /* IWifiChipEventCallback */
    HAL_CBK_CMD_ADD_IFACE,          /* The network device interface has been added. */
    HAL_CBK_CMD_REMOVE_IFACE,       /* The network device interface has been deleted. */

    /* AP AsscociatedEvent */
    HAL_CBK_CMD_STA_JOIN,           /* STA connection notification in AP mode */
    HAL_CBK_CMD_STA_LEAVE,          /* STA leaving notification in AP mode */
    
    /* SupplicantEventCallback */
    HAL_CBK_CMD_SCAN_INFO_NOTIFY,       /* SCAN Scan Result Notification */
    HAL_CBK_CMD_CONNECT_CHANGED,        /* Connection status change notification */
    HAL_CBK_CMD_BSSID_CHANGED,          /* bssid change notification */
    HAL_CBK_CMD_AP_ENABLE,              /* AP enabling notification */
    HAL_CBK_CMD_AP_DISABLE,             /* AP closure notification */
    HAL_CBK_CMD_WPA_STATE_CHANGEM,      /* WPA status change notification */
    HAL_CBK_CMD_SSID_WRONG_KEY,         /* Password error status notification */
    HAL_CBK_CMD_WPS_CONNECTION_FULL,    /* network connection full */
    HAL_CBK_CMD_WPS_CONNECTION_REJECT,  /* network connection reject */
    HAL_CBK_CMD_WPS_OVERLAP,            /* wps PBC overlap */
    HAL_CBK_CMD_WPS_TIME_OUT,           /* wps connect time out */

    /* P2p callback */
    HAL_CBK_CMD_P2P_SUPPLICANT_CONNECT,            /* p2p connect supplicant */
    HAL_CBK_CMD_SUP_CONN_FAILED_EVENT,             /* Wpa_supplicant client connection failure event */
    HAL_CBK_CMD_P2P_DEVICE_FOUND_EVENT,            /* Device discovery event */
    HAL_CBK_CMD_P2P_DEVICE_LOST_EVENT,             /* Device loss event */
    HAL_CBK_CMD_P2P_GO_NEGOTIATION_REQUEST_EVENT,  /* Event of receiving a GO negotiation request */
    HAL_CBK_CMD_P2P_GO_NEGOTIATION_SUCCESS_EVENT,  /* The GO negotiation is successful */
    HAL_CBK_CMD_P2P_GO_NEGOTIATION_FAILURE_EVENT,  /* The GO negotiation fails */
    HAL_CBK_CMD_P2P_INVITATION_RECEIVED_EVENT,     /* P2P invitation request event */
    HAL_CBK_CMD_P2P_INVITATION_RESULT_EVENT,       /* P2P invitation result */
    HAL_CBK_CMD_P2P_GROUP_FORMATION_SUCCESS_EVENT, /* The group is created successfully */
    HAL_CBK_CMD_P2P_GROUP_FORMATION_FAILURE_EVENT, /* The group is created failure */
    HAL_CBK_CMD_P2P_GROUP_STARTED_EVENT,           /* Group Start Event */
    HAL_CBK_CMD_P2P_GROUP_REMOVED_EVENT,           /* Group removed event */
    HAL_CBK_CMD_P2P_PROV_DISC_PBC_REQ_EVENT,       /* Provision Discovery request event */
    HAL_CBK_CMD_P2P_PROV_DISC_PBC_RSP_EVENT,       /* Provision Discovery Response Event */
    HAL_CBK_CMD_P2P_PROV_DISC_ENTER_PIN_EVENT,     /* Provision Discovery PIN input event */
    HAL_CBK_CMD_P2P_PROV_DISC_SHOW_PIN_EVENT,      /* Provision Discovery Display PIN Event */
    HAL_CBK_CMD_P2P_FIND_STOPPED_EVENT,            /* Device search stop event */
    HAL_CBK_CMD_P2P_SERV_DISC_RESP_EVENT,          /* Service response event */
    HAL_CBK_CMD_P2P_PROV_DISC_FAILURE_EVENT,       /* Provision Discovery failure event */
    HAL_CBK_CMD_AP_STA_DISCONNECTED_EVENT,         /* STA Disconnected from AP */
    HAL_CBK_CMD_AP_STA_CONNECTED_EVENT,            /* STA and AP connected event */
    HAL_CBK_CMD_P2P_SERV_DISC_REQ_EVENT,           /* Service discovery request event */
    HAL_CBK_CMD_P2P_IFACE_CREATED_EVENT,           /* P2P interface created event */
    HAL_CBK_CMD_STA_AP_TEMP_EVENT,
    HAL_CBK_CMD_AP_STA_PSK_MISMATCH_EVENT,         /* AP STA possible PSK mismatch event*/
    HAL_CBK_CMD_P2P_CONNECT_FAILED,                /* P2P connect failed event */
    HAL_CBK_CMD_P2P_CHANNEL_SWITCH_EVENT,          /* P2P Channel switch event */
    HAL_CBK_CMD_STA_DISCONNECT_REASON_EVENT,       /* sta disconnect reason report */
} HalCallbackEvent;

typedef enum Wifi80211StatusCode {
    WLAN_STATUS_EXT_DRIVER_FAIL = -1,
    WLAN_STATUS_UNSPECIFIED_FAILURE = 1,
    WLAN_STATUS_CHALLENGE_FAIL = 15,
    WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17,
    WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY = 30,
    WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH = 33,
} Wifi80211StatusCode;

typedef enum Wifi80211ReasonCode {
    WLAN_REASON_UNSPECIFIED = 1,
    WLAN_REASON_PREV_AUTH_NOT_VALID = 2,
    WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
    WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
    WLAN_REASON_IE_IN_4WAY_DIFFERS = 17,
    WLAN_REASON_DISASSOC_LOW_ACK = 34,

} Wifi80211ReasonCode;

typedef enum Wifi80211AuthType {
    WLAN_AUTH_SAE = 3,
} Wifi80211AuthType;
#endif
