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
#include "self_cure_common.h"
#include "self_cure_msg.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
using namespace NetManagerStandard;
DEFINE_WIFILOG_LABEL("SelfCureUtils");
SelfCureUtils::SelfCureUtils()
{
    WIFI_LOGI("SelfCureUtils()");
}

SelfCureUtils::~SelfCureUtils()
{
    WIFI_LOGI("~SelfCureUtils()");
}

SelfCureUtils& SelfCureUtils::GetInstance()
{
    static SelfCureUtils instance;
    return instance;
}

void SelfCureUtils::RegisterDnsResultCallback()
{
    dnsResultCallback_ = std::make_unique<SelfCureDnsResultCallback>().release();
    int32_t regDnsResult = NetsysController::GetInstance().RegisterDnsResultCallback(dnsResultCallback_, 0);
    WIFI_LOGI("RegisterDnsResultCallback result = %{public}d", regDnsResult);
}

void SelfCureUtils::UnRegisterDnsResultCallback()
{
    WIFI_LOGI("UnRegisterDnsResultCallback");
    if (dnsResultCallback_ != nullptr) {
        NetsysController::GetInstance().UnregisterDnsResultCallback(dnsResultCallback_);
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
    WIFI_LOGD("OnDnsResultReport, wifiNetId: %{public}d, defaultNetId: %{public}d, dnsFailedCounter_: %{public}d",
        wifiNetId, defaultNetId, dnsFailedCounter_);
    return 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::GetWifiNetId()
{
    std::list<sptr<NetHandle>> netList;
    int32_t ret = NetConnClient::GetInstance().GetAllNets(netList);
    if (ret != 0) {
        return 0;
    }

    for (auto iter : netList) {
        NetAllCapabilities netAllCap;
        NetConnClient::GetInstance().GetNetCapabilities(*iter, netAllCap);
        if (netAllCap.bearerTypes_.count(BEARER_WIFI) > 0) {
            return iter->GetNetId();
        }
    }
    return 0;
}

int32_t SelfCureUtils::SelfCureDnsResultCallback::GetDefaultNetId()
{
    NetHandle defaultNet;
    NetConnClient::GetInstance().GetDefaultNet(defaultNet);
    return defaultNet.GetNetId();
}

int32_t SelfCureUtils::GetSelfCureType(int32_t currentCureLevel)
{
    SelfCureType ret = SelfCureType::SCE_TYPE_INVALID;
    switch (currentCureLevel) {
        case WIFI_CURE_RESET_LEVEL_LOW_1_DNS:
            ret = SelfCureType::SCE_TYPE_DNS;
            break;
        case WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC:
            ret = SelfCureType::SCE_TYPE_REASSOC;
            break;
        case WIFI_CURE_RESET_LEVEL_WIFI6:
            ret = SelfCureType::SCE_TYPE_WIFI6;
            break;
        case WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP:
            ret = SelfCureType::SCE_TYPE_STATIC_IP;
            break;
        case WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY:
            ret = SelfCureType::SCE_TYPE_MULTI_GW;
            break;
        case WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC:
            ret = SelfCureType::SCE_TYPE_RANDMAC;
            break;
        case WIFI_CURE_RESET_LEVEL_HIGH_RESET:
            ret = SelfCureType::SCE_TYPE_RESET;
            break;
        default:
            break;
    }
    return static_cast<int32_t>(ret);
}
} // namespace Wifi
} // namespace OHOS