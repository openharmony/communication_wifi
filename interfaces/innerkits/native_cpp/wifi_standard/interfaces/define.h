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
#ifndef OHOS_DEFINE_H
#define OHOS_DEFINE_H

/* ------------sta module message define--------- */
#define WIFI_SVR_CMD_ENABLE_WIFI 0x1001               /* open wifi */
#define WIFI_SVR_CMD_DISABLE_WIFI 0x1002              /* close wifi */
#define WIFI_SVR_CMD_SET_POWER_MODE 0x1003            /* wifi lock, not used */
#define WIFI_SVR_CMD_FULL_SCAN 0x1004                 /* scan request */
#define WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN 0X1005     /* scan with params request */
#define WIFI_SVR_CMD_ADD_DEVICE_CONFIG 0X1006         /* add a network config */
#define WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG 0X1007      /* remove a network config */
#define WIFI_SVR_CMD_GET_DEVICE_CONFIGS 0x1008        /* get current saved network configs */
#define WIFI_SVR_CMD_ENABLE_DEVICE 0X1009             /* set a network enabled */
#define WIFI_SVR_CMD_DISABLE_DEVICE 0X100A            /* disabled a network */
#define WIFI_SVR_CMD_CONNECT_TO 0X100B                /* connect to a network with networkid */
#define WIFI_SVR_CMD_CONNECT2_TO 0x100C               /* connect to a network with network config */
#define WIFI_SVR_CMD_RECONNECT 0X100D                 /* reconnect */
#define WIFI_SVR_CMD_REASSOCIATE 0x100E               /* reassociate */
#define WIFI_SVR_CMD_DISCONNECT 0x1010                /* disconnect */
#define WIFI_SVR_CMD_START_WPS 0x1011                 /* start wps */
#define WIFI_SVR_CMD_CANCEL_WPS 0x1012                /* stop wps */
#define WIFI_SVR_CMD_IS_WIFI_ACTIVE 0x1013            /* whether current wifi active */
#define WIFI_SVR_CMD_GET_WIFI_STATE 0x1014            /* get current wifi state */
#define WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE 0x1015     /* whether set scan always */
#define WIFI_SVR_CMD_GET_SCAN_INFO_LIST 0x1016        /* get scan results */
#define WIFI_SVR_CMD_GET_LINKED_INFO 0x1017           /* get current link info */
#define WIFI_SVR_CMD_GET_DHCP_INFO 0x1018             /* get dhcp info */
#define WIFI_SVR_CMD_SET_COUNTRY_CODE 0X1019          /* set country code */
#define WIFI_SVR_CMD_GET_COUNTRY_CODE 0x101A          /* get country code */
#define WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT 0x101B  /* api register callback event */
#define WIFI_SVR_CMD_GET_SIGNAL_LEVEL 0x101C          /* get signal level */
#define WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO 0x1022     /* set scan control policy */
#define WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK 0x1023    /* register scan callback */

/* -------------ap module message define----------------- */
#define WIFI_SVR_CMD_ENABLE_WIFI_AP 0x1100      /* open ap */
#define WIFI_SVR_CMD_DISABLE_WIFI_AP 0x1101     /* close ap */
#define WIFI_SVR_CMD_GETAPSTATE_WIFI 0x1102     /* get current ap state */
#define WIFI_SVR_CMD_SETAPCONFIG_WIFI 0x1103    /* set ap config */
#define WIFI_SVR_CMD_GET_HOTSPOT_CONFIG 0x1104  /* get ap config */
#define WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE 0x1105   /* whether current ap active */
#define WIFI_SVR_CMD_GET_STATION_LIST 0x1106    /* get ap's connected sta infos */
#define WIFI_SVR_CMD_GET_DERVICE_MAC_ADD 0x1107 /* get mac address */
#define WIFI_SVR_CMD_SETBAND_AP 0X1108          /* set band */
#define WIFI_SVR_CMD_GETBAND_AP 0X1109          /* get band */
#define WIFI_SVR_CMD_ADD_BLOCK_LIST 0X110A      /* add a block */
#define WIFI_SVR_CMD_DEL_BLOCK_LIST 0X110B      /* remove a block */
#define WIFI_SVR_CMD_GET_BLOCK_LISTS 0X110C     /* get total block list */
#define WIFI_SVR_CMD_DISCONNECT_STA 0X110D      /* disconnect a sta connection */
#define WIFI_SVR_CMD_GET_VALID_BANDS 0X110E     /* get current valid frequency according band */
#define WIFI_SVR_CMD_GET_VALID_CHANNELS 0X110F  /* get current valid channels associated with the band */
#define WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK 0X1110    /* register scan callback */

/* -----------register event type and message define-------------- */
#define WIFI_CBK_CMD_STATE_CHANGE 0x1001         /* STA state change event */
#define WIFI_CBK_CMD_CONNECTION_CHANGE 0x1002    /* STA connection state change event */
#define WIFI_CBK_CMD_SCAN_STATE_CHANGE 0x1003    /* SCAN state change event */
#define WIFI_CBK_CMD_RSSI_CHANGE 0x1004          /* RSSI */
#define WIFI_CBK_CMD_HOTSPOT_STATE_CHANGE 0x1005 /* AP state change event */
#define WIFI_CBK_CMD_HOTSPOT_STATE_JOIN 0x1006   /* AP join a sta event */
#define WIFI_CBK_CMD_HOTSPOT_STATE_LEAVE 0x1007  /* AP leave a sta event */
#define WIFI_CBK_CMD_STREAM_DIRECTION 0x1008     /* traffic up/down state event */
#define WIFI_CBK_CMD_WPS_STATE_CHANGE 0x1009     /* wps state change event */

#define WIFI_CBK_MSG_STATE_CHANGE 0x1001
#define WIFI_CBK_MSG_CONNECTION_CHANGE 0x1002
#define WIFI_CBK_MSG_RSSI_CHANGE 0x1003
#define WIFI_CBK_MSG_STREAM_DIRECTION 0x1004
#define WIFI_CBK_MSG_WPS_STATE_CHANGE 0x1005
#define WIFI_CBK_MSG_SCAN_STATE_CHANGE 0x1006
#define WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE 0x1007
#define WIFI_CBK_MSG_HOTSPOT_STATE_JOIN 0x1008
#define WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE 0x1009

/* --------------moc test message define--------------- */
#define WIFI_SVR_CMD_MOCK_CHANGE_STATE 0X1201      /* change outer state message */
#define WIFI_SVR_CMD_MOCK_CHANGE_PERMISSION 0X1202 /* change permission value message */

/* -----------Feature service name-------------- */
#define WIFI_SERVICE_STA "StaService"     /* STA */
#define WIFI_SERVICE_AP "ApService"       /* AP */
#define WIFI_SERVICE_P2P "P2pService"     /* P2P */
#define WIFI_SERVICE_SCAN "ScanService"   /* SCAN */
#define WIFI_SERVICE_AWARE "AwareService" /* AWARE */

#define MODE_STATE_SCREEN (1)
#define MODE_STATE_AIR_PLANE (2)
#define MODE_STATE_APP_RUN (3)
#define MODE_STATE_POWER_SAVING (4)
#define MODE_STATE_CUSTOM_SCENE (5)

#define STATE_OPEN (1)
#define STATE_CLOSE (2)

/* ---------Feature service ability id */
#define WIFI_DEVICE_ABILITY_ID (1125)
#define WIFI_SCAN_ABILITY_ID (1126)
#define WIFI_HOTSPOT_ABILITY_ID (1127)

#endif