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

#ifndef OHOS_MOCK_NET_CONN_MANAGER_H
#define OHOS_MOCK_NET_CONN_MANAGER_H

#define NETMANAGER (0)
#include "net_all_capabilities.h"
#include "net_conn_client.h"

namespace OHOS {
using namespace NetManagerStandard;
namespace Wifi {
class NetConnClient {
public:
    static NetConnClient &GetInstance();

    int32_t UnregisterNetSupplier(uint32_t supplierId);

    int32_t RegisterNetSupplierCallback(uint32_t supplierId, const sptr<NetSupplierCallbackBase> &callback);

    int32_t UpdateNetSupplierInfo(uint32_t supplierId, const sptr<NetSupplierInfo> &netSupplierInfo);

    int32_t UpdateNetLinkInfo(uint32_t supplierId, const sptr<NetLinkInfo> &netLinkInfo);

    int32_t RegisterNetDetectionCallback(int32_t netId, const sptr<INetDetectionCallback> &callback);

    int32_t UnRegisterNetDetectionCallback(int32_t netId, const sptr<INetDetectionCallback> &callback);

    int32_t GetAllNets(std::list<sptr<NetHandle>> &netList);

    int32_t GetNetCapabilities(const NetHandle &netHandle, NetAllCapabilities &netAllCap);

    int32_t NetDetection(const NetHandle &netHandle);

    int32_t RegisterNetInterfaceCallback(const sptr<INetInterfaceStateCallback> &callback);
};
} // namespace NetManagerStandard
} // namespace OHOS

#endif // NET_CONN_MANAGER_H
