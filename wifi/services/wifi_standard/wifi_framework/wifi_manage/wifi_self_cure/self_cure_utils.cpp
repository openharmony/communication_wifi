/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "self_cure_utils.h"
#include "net_conn_client.h"
#include "net_handle.h"
#include "netsys_controller.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("SelfCureUtils");
SelfCureUtils::SelfCureUtils()
{
    WIFI_LOGI("SelfCureUtils()");
}

SelfCureUtils::~SelfCureUtils()
{
    WIFI_LOGI("~SelfCureUtils()");
}

void SelfCureUtils::RegisterDnsResultCallback()
{
    dnsResultCallback_ = std::make_unique<SelfCureDnsResultCallback>().release();
    int32_t regDnsResult =
        NetManagerStandard::NetsysController::GetInstance().RegisterDnsResultCallback(dnsResultCallback_, 0);
    WIFI_LOGI("RegisterDnsResultCallback result = %{public}d", regDnsResult);
}

void SelfCureUtils::UnRegisterDnsResultCallback()
{
    WIFI_LOGI("UnRegisterDnsResultCallback");
    if (dnsResultCallback_ != nullptr) {
        NetManagerStandard::NetsysController::GetInstance().UnregisterDnsResultCallback(dnsResultCallback_);
    }
}

int32_t SelfCureUtils::GetCurrentDnsFailedCounter()
{
    return dnsResultCallback_->dnsFailedCounter_;
}

void SelfCureUtils::ClearDnsFailedCounter()
{
    dnsResultCallback_->dnsFailedCounter_ = 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::OnDnsResultReport(uint32_t size,
    const std::list<NetsysNative::NetDnsResultReport> netDnsResultReport)
{
    int32_t wifiNetId = GetWifiNetId();
	int32_t defaultNetId = GetDefaultNetId();
    for (auto &it : netDnsResultReport) {
        int32_t netId = static_cast<int32_t>(it.netid_);
        int32_t targetNetId = netId > 0 ? netId : (defaultNetId > 0 ? defaultNetId : 0);
        if (wifiNetId > 0 && wifiNetId == targetNetId) {
            if (it.queryresult_ != 0) {
                dnsFailedCounter_++;
            }
        }
    }
    return 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::GetWifiNetId()
{
    std::list<sptr<NetManagerStandard::NetHandle>> netList;
    int32_t ret = NetManagerStandard::NetConnClient::GetInstance().GetAllNets(netList);
    if (ret != 0) {
        return 0;
    }

    for (auto iter : netList) {
        NetManagerStandard::NetAllCapabilities netAllCap;
        NetManagerStandard::NetConnClient::GetInstance().GetNetCapabilities(*iter, netAllCap);
        if (netAllCap.bearerTypes_.count(NetManagerStandard::BEARER_WIFI) > 0) {
            return iter->GetNetId();
        }
    }
    return 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::GetDefaultNetId()
{
    NetManagerStandard::NetHandle defaultNet;
    NetManagerStandard::NetConnClient::GetInstance().GetDefaultNet(defaultNet);
    return defaultNet.GetNetId();
}
} // namespace Wifi
} // namespace OHOS