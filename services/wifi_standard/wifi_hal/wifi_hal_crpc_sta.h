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

#ifndef OHOS_WIFI_HAL_CRPC_STA_H
#define OHOS_WIFI_HAL_CRPC_STA_H

#include "server.h"

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              Start and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStart(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              Stop and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStop(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StartScan and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStartScan(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetScanResults and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetScanResults(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StartPnoScan and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStartPnoScan(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StopPnoScan and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStopPnoScan(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              Connect and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcConnect(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              Reconnect and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcReconnect(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              Reassociate and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcReassociate(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              Disconnect and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcDisconnect(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetExternalSim and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetExternalSim(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetBluetoothCoexistenceScanMode and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetBluetoothCoexistenceScanMode(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StopFilteringMulticastV4Packets and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStopFilteringMulticastV4Packets(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StopFilteringMulticastV6Packets and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStopFilteringMulticastV6Packets(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              EnableStaAutoReconnect and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcEnableStaAutoReconnect(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetConcurrencyPriority and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetConcurrencyPriority(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetSuspendModeEnabled and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetSuspendModeEnabled(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetStaCapabilities and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetStaCapabilities(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetDeviceMacAddress and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetDeviceMacAddress(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetFrequencies and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetFrequencies(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetAssocMacAddr and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetAssocMacAddr(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetScanningMacAddress and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetScanningMacAddress(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              DeauthLastRoamingBssid and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcDeauthLastRoamingBssid(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetSupportFeature and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetSupportFeature(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              RunCmd and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcRunCmd(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetWifiTxPower and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetWifiTxPower(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              RemoveNetwork and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcRemoveNetwork(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              AddNetwork and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcAddNetwork(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              EnableNetwork and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcEnableNetwork(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              DisableNetwork and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcDisableNetwork(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetNetwork and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetNetwork(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SaveNetworkConfig and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSaveNetworkConfig(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StartWpsPbcMode and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStartWpsPbcMode(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StartWpsPinMode and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStartWpsPinMode(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              StopWps and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcStopWps(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetRoamingCapabilities and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetRoamingCapabilities(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              SetRoamConfig and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcSetRoamConfig(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              WpaGetNetwork and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcWpaGetNetwork(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              WpaAutoConnect and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcWpaAutoConnect(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              WpaReconfigure and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcWpaReconfigure(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              WpaBlocklistClear and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcWpaBlocklistClear(RpcServer *server, Context *context);

/**
 * @Description Parse the context to obtain data. Call the corresponding function
 *              GetNetworkList and assemble the function to obtain data.
 *
 * @param server - Pointer to the global structure of the communication server.
 * @param context - Pointer to the global communication context structure of the server.
 * @return int - 0 Success, -1 Failed.
 */
int RpcGetNetworkList(RpcServer *server, Context *context);
#endif