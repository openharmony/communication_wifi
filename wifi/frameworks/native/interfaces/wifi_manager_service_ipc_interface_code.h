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
#ifndef OHOS_WIFI_MANAGER_SERVICE_IPC_INTERFACE_CODE_H
#define OHOS_WIFI_MANAGER_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Wifi {
/* SAID: 1120 */
enum class  DevInterfaceCode {
    WIFI_MGR_GET_DEVICE_SERVICE = 0,
    WIFI_SVR_CMD_ENABLE_WIFI = 0x1001,               /* open wifi */
    WIFI_SVR_CMD_DISABLE_WIFI = 0x1002,              /* close wifi */
    WIFI_SVR_CMD_ADD_DEVICE_CONFIG = 0x1006,         /* add a network config */
    WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG = 0x1007,      /* remove a network config */
    WIFI_SVR_CMD_GET_DEVICE_CONFIGS = 0x1008,        /* get current saved network configs */
    WIFI_SVR_CMD_ENABLE_DEVICE = 0x1009,             /* set a network enabled */
    WIFI_SVR_CMD_DISABLE_DEVICE = 0x100A,            /* disabled a network */
    WIFI_SVR_CMD_CONNECT_TO = 0x100B,                /* connect to a network with networkid */
    WIFI_SVR_CMD_CONNECT2_TO = 0x100C,               /* connect to a network with network config */
    WIFI_SVR_CMD_RECONNECT = 0x100D,                 /* reconnect */
    WIFI_SVR_CMD_REASSOCIATE = 0x100E,               /* reassociate */
    WIFI_SVR_CMD_DISCONNECT = 0x1010,                /* disconnect */
    WIFI_SVR_CMD_START_WPS = 0x1011,                 /* start wps */
    WIFI_SVR_CMD_CANCEL_WPS = 0x1012,                /* stop wps */
    WIFI_SVR_CMD_IS_WIFI_ACTIVE = 0x1013,            /* whether current wifi active */
    WIFI_SVR_CMD_GET_WIFI_STATE = 0x1014,            /* get current wifi state */
    WIFI_SVR_CMD_GET_LINKED_INFO = 0x1017,           /* get current link info */
    WIFI_SVR_CMD_GET_DHCP_INFO = 0x1018,             /* get dhcp info */
    WIFI_SVR_CMD_SET_COUNTRY_CODE = 0x1019,          /* set country code */
    WIFI_SVR_CMD_GET_COUNTRY_CODE = 0x101A,          /* get country code */
    WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT = 0x101B,  /* api register callback event */
    WIFI_SVR_CMD_GET_SIGNAL_LEVEL = 0x101C,          /* get signal level */
    WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG = 0x101F,      /* update a network config */
    WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG = 0x1020,  /* remove all network configs */
    WIFI_SVR_CMD_GET_SUPPORTED_FEATURES = 0x1021,    /* get supported features */
    WIFI_SVR_CMD_GET_DERVICE_MAC_ADD = 0x1022,       /* get mac address */
    WIFI_SVR_CMD_INIT_WIFI_PROTECT = 0x1023,        /* init the Wi-Fi protect. */
    WIFI_SVR_CMD_GET_WIFI_PROTECT = 0x1024,         /* get the Wi-Fi protect. */
    WIFI_SVR_CMD_PUT_WIFI_PROTECT = 0x1025,         /* put the Wi-Fi protect. */
    WIFI_SVR_CMD_IS_WIFI_CONNECTED = 0x1026,         /* is Wi-Fi connected */
    WIFI_SVR_CMD_SET_LOW_LATENCY_MODE = 0x1027,    /* set low latency mode */
    WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG = 0x1028, /* remove an candidate network config */
    WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED = 0x1029,    /* get taget bandtype supported */
    WIFI_SVR_CMD_GET_5G_CHANNELLIST = 0x1030,        /* get 5g channellist */
    WIFI_SVR_CMD_GET_DISCONNECTED_REASON = 0x1031,   /* get disconnect reason */
    WIFI_SVR_CMD_GET_DHCP_IPV6INFO = 0x1032,         /* get dhcp IPV6 info */
    WIFI_SVR_CMD_SET_FROZEN_APP = 0x1033,            /* set frozen app */
    WIFI_SVR_CMD_RESET_ALL_FROZEN_APP = 0x1034,      /* reset all frozen app */
    WIFI_SVR_CMD_START_PORTAL_CERTIF = 0x1035,       /* start portal certification */
    WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT = 0x1036,      /* is held the Wi-Fi protect. */
    WIFI_SVR_CMD_IS_SET_FACTORY_RESET = 0x1037,      /* factory reset */
    WIFI_SVR_CMD_IS_METERED_HOTSPOT = 0x1038,       /* whether current link is metered hotspot */
    WIFI_SVR_CMD_DISABLE_AUTO_JOIN = 0x1039,         /* disable auto join */
    WIFI_SVR_CMD_ENABLE_AUTO_JOIN = 0x103A,          /* enable auto join */
    WIFI_SVR_CMD_LIMIT_SPEED = 0x103B,               /* limit app speed */
    WIFI_SVR_CMD_IS_HILINK_CONNECT = 0x103C,          /* hilink connect */
    /* 新增WIFI_SVR_CMD_类code，请在此下方添加 */

    /* 以下CALL BACK类code，不需要进行权限校验 */
    WIFI_CBK_CMD_STATE_CHANGE = 0x3000,         /* STA state change event */
    WIFI_CBK_CMD_CONNECTION_CHANGE = 0x3001,    /* STA connection state change event */
    WIFI_CBK_CMD_RSSI_CHANGE = 0x3002,          /* RSSI */
    WIFI_CBK_CMD_STREAM_DIRECTION = 0x3003,     /* traffic up/down state event */
    WIFI_CBK_CMD_WPS_STATE_CHANGE = 0x3004,     /* wps state change event */
    WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE = 0x3005,    /* device config change event */
    WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE = 0x3006,    /* device config change event */
};

/* SAID: 1121 */
enum class  HotspotInterfaceCode {
    WIFI_MGR_GET_HOTSPOT_SERVICE = 0,
    WIFI_SVR_CMD_ENABLE_WIFI_AP = 0x1100,            /* open ap */
    WIFI_SVR_CMD_DISABLE_WIFI_AP = 0x1101,           /* close ap */
    WIFI_SVR_CMD_GETAPSTATE_WIFI = 0x1102,           /* get current ap state */
    WIFI_SVR_CMD_SETAPCONFIG_WIFI = 0x1103,          /* set ap config */
    WIFI_SVR_CMD_GET_HOTSPOT_CONFIG = 0x1104,        /* get ap config */
    WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE = 0x1105,         /* whether current ap active */
    WIFI_SVR_CMD_GET_STATION_LIST = 0x1106,          /* get ap's connected sta infos */
    WIFI_SVR_CMD_ADD_BLOCK_LIST = 0x110A,            /* add a block */
    WIFI_SVR_CMD_DEL_BLOCK_LIST = 0x110B,            /* remove a block */
    WIFI_SVR_CMD_GET_BLOCK_LISTS = 0x110C,           /* get total block list */
    WIFI_SVR_CMD_DISCONNECT_STA = 0x110D,            /* disconnect a sta connection */
    WIFI_SVR_CMD_GET_VALID_BANDS = 0x110E,           /* get current valid frequency according band */
    WIFI_SVR_CMD_GET_VALID_CHANNELS = 0x110F,        /* get current valid channels associated with the band */
    WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK = 0x1110, /* register scan callback */
    WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL = 0x1111, /* get supported power model */
    WIFI_SVR_CMD_GET_POWER_MODEL = 0x1112, /* get power model */
    WIFI_SVR_CMD_SET_POWER_MODEL = 0x1113, /* set power model */
    WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED = 0x1114, /* whether dual band is supported */
    WIFI_SVR_CMD_SETTIMEOUT_AP = 0x1115,             /* set hotspot idle timeout */
    WIFI_SVR_CMD_GET_IFACE_NAME = 0x1116,            /* get hotspot iface name */
    /* 新增WIFI_SVR_CMD_类code，请在此下方添加 */

    /* 以下CALL BACK类code，不需要进行权限校验 */
    WIFI_CBK_CMD_HOTSPOT_STATE_CHANGE = 0x3100, /* AP state change event */
    WIFI_CBK_CMD_HOTSPOT_STATE_JOIN = 0x3101,   /* AP join a sta event */
    WIFI_CBK_CMD_HOTSPOT_STATE_LEAVE = 0x3102,  /* AP leave a sta event */
};

/* SAID: 1123 */
enum class  P2PInterfaceCode {
    WIFI_SVR_CMD_P2P_ENABLE = 0x2000,                 /* open p2p */
    WIFI_SVR_CMD_P2P_DISABLE = 0x2001,                /* close p2p */
    WIFI_SVR_CMD_P2P_DISCOVER_DEVICES = 0x2002,       /* start Wi-Fi P2P device search */
    WIFI_SVR_CMD_P2P_STOP_DISCOVER_DEVICES = 0x2003,  /* stop Wi-Fi P2P device search */
    WIFI_SVR_CMD_P2P_DISCOVER_SERVICES = 0x2004,      /* start Wi-Fi P2P service search */
    WIFI_SVR_CMD_P2P_STOP_DISCOVER_SERVICES = 0x2005, /* stop Wi-Fi P2P service search */
    WIFI_SVR_CMD_P2P_REQUEST_SERVICES = 0x2006,       /* request the P2P service */
    WIFI_SVR_CMD_P2P_PUT_LOCAL_SERVICES = 0x2007,     /* add local P2P service */
    WIFI_SVR_CMD_P2P_DELETE_LOCAL_SERVICES = 0x2008,  /* remove local P2P service */
    WIFI_SVR_CMD_P2P_START_LISTEN = 0x2009,           /* enable Wi-Fi P2P listening */
    WIFI_SVR_CMD_P2P_STOP_LISTEN = 0x200A,            /* disable Wi-Fi P2P listening */
    WIFI_SVR_CMD_P2P_CREATE_GROUP = 0x200B,           /* creating a P2P Group */
    WIFI_SVR_CMD_P2P_REMOVE_GROUP = 0x200C,           /* remove a P2P Group */
    WIFI_SVR_CMD_P2P_DELETE_GROUP = 0x200D,           /* delete a P2P Group */
    WIFI_SVR_CMD_P2P_CONNECT = 0x200E,                /* p2p connect */
    WIFI_SVR_CMD_P2P_CANCEL_CONNECT = 0x200F,         /* p2p cancel connect */
    WIFI_SVR_CMD_P2P_QUERY_INFO = 0x2010,             /* querying Wi-Fi P2P Connection Information */
    WIFI_SVR_CMD_P2P_GET_CURRENT_GROUP = 0x2011,      /* get the P2P current group */
    WIFI_SVR_CMD_P2P_GET_ENABLE_STATUS = 0x2012,      /* obtains the P2P switch status */
    WIFI_SVR_CMD_P2P_GET_DISCOVER_STATUS = 0x2013,    /* obtains the P2P discovery status */
    WIFI_SVR_CMD_P2P_GET_CONNECTED_STATUS = 0x2014,   /* obtains the P2P connected status */
    WIFI_SVR_CMD_P2P_QUERY_DEVICES = 0x2015,          /* query the information about the found devices */
    WIFI_SVR_CMD_P2P_QUERY_GROUPS = 0x2016,           /* query the information about the found groups */
    WIFI_SVR_CMD_P2P_QUERY_SERVICES = 0x2017,         /* query the information about the found services */
    WIFI_SVR_CMD_P2P_REGISTER_CALLBACK = 0x2018,
    WIFI_SVR_CMD_P2P_SET_DEVICE_NAME = 0x2019,        /* set device name */
    WIFI_SVR_CMD_P2P_SET_WFD_INFO = 0x201A,           /* set p2p wifi display info */
    WIFI_SVR_CMD_P2P_HID2D_APPLY_IP = 0x201B,    /* hid2d apply ip */
    WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_INCREASE = 0x201C,    /* hid2d shared link increase */
    WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_DECREASE = 0x201D,    /* hid2d shared link decrease */
    WIFI_SVR_CMD_P2P_HID2D_CREATE_GROUP = 0x201E,    /* hid2d create group */
    WIFI_SVR_CMD_P2P_HID2D_REMOVE_GC_GROUP = 0x201F,    /* hid2d remove GC group */
    WIFI_SVR_CMD_P2P_HID2D_CONNECT = 0x2020,    /* hid2d connect to group */
    WIFI_SVR_CMD_P2P_HID2D_CONFIG_IP = 0x2021,    /* hid2d configure IP address */
    WIFI_SVR_CMD_P2P_HID2D_RELEASE_IP = 0x2022,    /* hid2d release IP address */
    WIFI_SVR_CMD_GET_P2P_RECOMMENDED_CHANNEL = 0x2023,    /* get recommended channel */
    WIFI_SVR_CMD_GET_5G_CHANNEL_LIST = 0x2024,    /* get recommended channel */
    WIFI_SVR_CMD_GET_SELF_WIFI_CFG = 0x2025,    /* get self wifi configuration */
    WIFI_SVR_CMD_SET_PEER_WIFI_CFG = 0x2026,    /* set peer wifi configuration */
    WIFI_SVR_CMD_P2P_QUERY_LOCAL_DEVICE = 0x2027, /* query the information about the local device */
    WIFI_SVR_CMD_SET_UPPER_SCENE = 0x2028,    /* set the scene of upper layer */
    /* 新增WIFI_SVR_CMD_类code，请在此下方添加 */
    WIFI_SVR_CMD_P2P_REMOVE_GROUP_CLIENT = 0x3000,
    /* 以下CALL BACK类code，不需要进行权限校验 */
    WIFI_CBK_CMD_P2P_STATE_CHANGE = 0x3200,         /* p2p state change event */
    WIFI_CBK_CMD_PERSISTENT_GROUPS_CHANGE = 0x3201, /* Persistent Group Updated */
    WIFI_CBK_CMD_THIS_DEVICE_CHANGE = 0x3202,       /* The current device information has been updated */
    WIFI_CBK_CMD_PEER_CHANGE = 0x3203,
    WIFI_CBK_CMD_SERVICE_CHANGE = 0x3204,
    WIFI_CBK_CMD_CONNECT_CHANGE = 0x3205,
    WIFI_CBK_CMD_DISCOVERY_CHANGE = 0x3206,
    WIFI_CBK_CMD_P2P_ACTION_RESULT = 0x3207,
    WIFI_CBK_CMD_CFG_CHANGE = 0x3208,
    WIFI_CBK_CMD_P2P_GC_JOIN_GROUP = 0x3209,    /* Gc joined group and obtained IP */
    WIFI_CBK_CMD_P2P_GC_LEAVE_GROUP = 0x3210,    /* Gc disconnected */
};

/* SAID: 1124 */
enum class  ScanInterfaceCode {
    WIFI_MGR_GET_SCAN_SERVICE = 0,
    WIFI_SVR_CMD_FULL_SCAN = 0x1004,                 /* scan request */
    WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN = 0x1005,     /* scan with params request */
    WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE = 0x1015,     /* whether set scan always */
    WIFI_SVR_CMD_GET_SCAN_INFO_LIST = 0x1016,        /* get scan results */
    WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO = 0x101D,     /* set scan control policy */
    WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK = 0x101E,    /* register scan callback */
    /* 新增WIFI_SVR_CMD_类code，请在此下方添加 */
    WIFI_SVR_CMD_SET_WIFI_SCAN_ONLY = 0x1200,        /*set scan only*/
    WIFI_SVR_CMD_GET_WIFI_SCAN_ONLY = 0x1201,        /*get scan only*/
    WIFI_SVR_CMD_START_PNO_SCAN = 0x1202,            /*start pno scan*/

    /* 以下CALL BACK类code，不需要进行权限校验 */
    WIFI_CBK_CMD_SCAN_STATE_CHANGE = 0x3300,    /* SCAN state change event */
};
} // namespace wifi
} // namespace OHOS

#endif // end of OHOS_WIFI_MANAGER_SERVICE_IPC_INTERFACE_CODE_H
