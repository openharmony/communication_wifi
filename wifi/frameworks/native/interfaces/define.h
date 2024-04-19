/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ARCH_LITE
#include "system_ability_definition.h"
#endif

/* The response message ID of callback */
#define WIFI_CBK_MSG_STATE_CHANGE 0x1001
#define WIFI_CBK_MSG_CONNECTION_CHANGE 0x1002
#define WIFI_CBK_MSG_RSSI_CHANGE 0x1003
#define WIFI_CBK_MSG_STREAM_DIRECTION 0x1004
#define WIFI_CBK_MSG_WPS_STATE_CHANGE 0x1005
#define WIFI_CBK_MSG_DEVICE_CONFIG_CHANGE 0x1006
#define WIFI_CBK_MSG_MAX_INVALID_STA 0x1FFF /* STA invalid value */

#define WIFI_CBK_MSG_SCAN_STATE_CHANGE 0x2001

#define WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE 0x3001
#define WIFI_CBK_MSG_HOTSPOT_STATE_JOIN 0x3002
#define WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE 0x3003
#define WIFI_CBK_MSG_MAX_INVALID_HOTSPOT 0x3FFF /* HOTSPOT invalid value */

#define WIFI_CBK_MSG_P2P_STATE_CHANGE 0x4001
#define WIFI_CBK_MSG_PERSISTENT_GROUPS_CHANGE 0x4002 /* Persistent Group Updated */
#define WIFI_CBK_MSG_THIS_DEVICE_CHANGE 0x4003
#define WIFI_CBK_MSG_PEER_CHANGE 0x4004
#define WIFI_CBK_MSG_SERVICE_CHANGE 0x4005
#define WIFI_CBK_MSG_CONNECT_CHANGE 0x4006
#define WIFI_CBK_MSG_DISCOVERY_CHANGE 0x4007
#define WIFI_CBK_MSG_P2P_ACTION_RESULT 0x4008
#define WIFI_CBK_MSG_CFG_CHANGE 0x4009
#define WIFI_CBK_MSG_P2P_GC_JOIN_GROUP 0x4010
#define WIFI_CBK_MSG_P2P_GC_LEAVE_GROUP 0x4011
#define WIFI_CBK_MSG_MAX_INVALID_P2P 0x4FFF /* P2P invalid value */

/* -----------Callback event name define-------------- */
#define EVENT_STA_POWER_STATE_CHANGE "wifiStateChange"
#define EVENT_STA_CONN_STATE_CHANGE "wifiConnectionChange"
#define EVENT_STA_RSSI_STATE_CHANGE "wifiRssiChange"
#define EVENT_STA_WPS_STATE_CHANGE "wifiWpsStateChange"
#define EVENT_STREAM_CHANGE "streamChange"
#define EVENT_STA_DEVICE_CONFIG_CHANGE "deviceConfigChange"
#define EVENT_STA_SCAN_STATE_CHANGE "wifiScanStateChange" /*  STA*/

#define EVENT_HOTSPOT_STATE_CHANGE "hotspotStateChange"
#define EVENT_HOTSPOT_STA_JOIN "hotspotStaJoin"
#define EVENT_HOTSPOT_STA_LEAVE "hotspotStaLeave" /* AP */

#define EVENT_P2P_STATE_CHANGE "p2pStateChange"
#define EVENT_P2P_PERSISTENT_GROUP_CHANGE "p2pPersistentGroupChange"
#define EVENT_P2P_DEVICE_STATE_CHANGE "p2pDeviceChange"
#define EVENT_P2P_PEER_DEVICE_CHANGE "p2pPeerDeviceChange"
#define EVENT_P2P_SERVICES_CHANGE "p2pServicesChange"
#define EVENT_P2P_CONN_STATE_CHANGE "p2pConnectionChange"
#define EVENT_P2P_DISCOVERY_CHANGE "p2pDiscoveryChange"
#define EVENT_P2P_ACTION_RESULT "p2pActionResult"
#define EVENT_P2P_CONFIG_CHANGE "p2pConfigChange"
#define EVENT_P2P_GC_JOIN_GROUP "p2pGcJoinGroup"
#define EVENT_P2P_GC_LEAVE_GROUP "p2pGcLeaveGroup" /* P2P */

/* -----------Feature service name-------------- */
#define WIFI_SERVICE_STA "StaService"     /* STA */
#define WIFI_SERVICE_SELFCURE "SelfCureService"  /* SELFCURE */
#define WIFI_SERVICE_AP "ApService"       /* AP */
#define WIFI_SERVICE_P2P "P2pService"     /* P2P */
#define WIFI_SERVICE_SCAN "ScanService"   /* SCAN */
#define WIFI_SERVICE_AWARE "AwareService" /* AWARE */
#define WIFI_SERVICE_ENHANCE "EnhanceService" /* ENHANCE */
/* ---------Feature service ability id */
#ifdef OHOS_ARCH_LITE
#define WIFI_DEVICE_ABILITY_ID 1120
#define WIFI_HOTSPOT_ABILITY_ID 1121
#define WIFI_P2P_ABILITY_ID 1123
#define WIFI_SCAN_ABILITY_ID 1124
#else
#define WIFI_DEVICE_ABILITY_ID OHOS::WIFI_DEVICE_SYS_ABILITY_ID /* 1120 */
#define WIFI_HOTSPOT_ABILITY_ID OHOS::WIFI_HOTSPOT_SYS_ABILITY_ID /* 1121 */
#define WIFI_P2P_ABILITY_ID OHOS::WIFI_P2P_SYS_ABILITY_ID /* 1123 */
#define WIFI_SCAN_ABILITY_ID OHOS::WIFI_SCAN_SYS_ABILITY_ID /* 1124 */
#endif

#define MODE_STATE_SCREEN (1)
#define MODE_STATE_AIR_PLANE (2)
#define MODE_STATE_APP_RUN (3)
#define MODE_STATE_POWER_SAVING (4)
#define MODE_STATE_FREEZE (5)
#define MODE_STATE_NO_CHARGER_PLUG (6)

#define MODE_STATE_DEFAULT (-1)
#define MODE_STATE_OPEN (1)
#define MODE_STATE_CLOSE (2)
#define WIFI_STATE_DISABLED (0)
#define WIFI_STATE_ENABLED (1)
#define WIFI_STATE_ENABLED_AIRPLANEMODE_OVERRIDE (2)
#define WIFI_STATE_DISABLED_AIRPLANEMODE_ON (3)
#define INTERFACEDESCRIPTORL1  u"ohos.wifi.IWifiDeviceService"
#define DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH (sizeof(INTERFACEDESCRIPTORL1)/sizeof(uint16_t))
#define DECLARE_INTERFACE_DESCRIPTOR_L1 ((uint16_t*)&INTERFACEDESCRIPTORL1[0])
#endif
