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

#include "mock_netconn_client.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {

NetConnClient &NetConnClient::GetInstance()
{
    static NetConnClient gNetConnClient;
    return gNetConnClient;
}

int32_t NetConnClient::UnregisterNetSupplier(uint32_t supplierId)
{
    return NETMANAGER;
}

int32_t NetConnClient::RegisterNetSupplierCallback(uint32_t supplierId, const sptr<NetSupplierCallbackBase> &callback)
{
    return NETMANAGER;
}

int32_t NetConnClient::UpdateNetSupplierInfo(uint32_t supplierId, const sptr<NetSupplierInfo> &netSupplierInfo)
{
    return NETMANAGER;
}

int32_t NetConnClient::UpdateNetLinkInfo(uint32_t supplierId, const sptr<NetLinkInfo> &netLinkInfo)
{
    return NETMANAGER;
}

int32_t NetConnClient::RegisterNetDetectionCallback(int32_t netId, const sptr<INetDetectionCallback> &callback)
{
    return NETMANAGER;
}

int32_t NetConnClient::UnRegisterNetDetectionCallback(int32_t netId, const sptr<INetDetectionCallback> &callback)
{
    return NETMANAGER;
}

int32_t NetConnClient::GetAllNets(std::list<sptr<NetHandle>> &netList)
{
    return NETMANAGER;
}

int32_t NetConnClient::GetNetCapabilities(const NetHandle &netHandle, NetAllCapabilities &netAllCap)
{
    return NETMANAGER;
}

int32_t NetConnClient::NetDetection(const NetHandle &netHandle)
{
    return NETMANAGER;
}

int32_t NetConnClient::RegisterNetInterfaceCallback(const sptr<INetInterfaceStateCallback> &callback)
{
    return NETMANAGER;
}
} // namespace Wifi
} // namespace OHOS
