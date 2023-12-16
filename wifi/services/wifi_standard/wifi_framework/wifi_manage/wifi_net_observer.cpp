/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "wifi_logger.h"
#include <unistd.h>
#include <pthread.h>
#include <thread>
#include "wifi_net_observer.h"
#include "net_conn_client.h"
#include "net_conn_constants.h"
#include "net_all_capabilities.h"

DEFINE_WIFILOG_LABEL("WifiNetObserver");

namespace OHOS {
namespace Wifi {
using namespace NetManagerStandard;
constexpr int32_t RETRY_MAX_TIMES = 10;

NetStateObserver &NetStateObserver::GetInstance()
{
    static NetStateObserver gNetStateObserver;
    return gNetStateObserver;
}

NetStateObserver::NetStateObserver(): m_Callback(nullptr)
{
    WIFI_LOGD("construct NetStateObserver");
}

void NetStateObserver::SetNetStateCallback(std::function<void(SystemNetWorkState)> callback)
{
    m_Callback = callback;
}

void NetStateObserver::StartNetStateObserver()
{
    WIFI_LOGI("StartNetObserver");
    std::thread th = std::thread([this]() {
        NetManagerStandard::NetSpecifier netSpecifier;
        NetManagerStandard::NetAllCapabilities netAllCapabilities;
        netAllCapabilities.netCaps_.insert(NetManagerStandard::NetCap::NET_CAPABILITY_INTERNET);
        netSpecifier.ident_ = "";
        netSpecifier.netCapabilities_ = netAllCapabilities;
        int32_t retryCount = 0;
        int32_t ret = 0;
        do {
            ret = NetManagerStandard::NetConnClient::GetInstance().RegisterNetConnCallback(this);
            if (ret == 0) {
                WIFI_LOGI("StartNetObserver register success");
                return;
            }
            retryCount++;
            WIFI_LOGI("StartNetObserver retry, ret = %{public}d", ret);
            sleep(1);
        } while (retryCount < RETRY_MAX_TIMES);
        WIFI_LOGI("StartNetObserver failed");
    });
    th.detach();
}

void NetStateObserver::StopNetStateObserver()
{
    WIFI_LOGI("StopNetObserver");
    std::thread th = std::thread([this]() {
        int32_t retryCount = 0;
        int32_t ret = 0;
        do {
            ret = NetManagerStandard::NetConnClient::GetInstance().UnregisterNetConnCallback(this);
            if (ret == 0) {
                WIFI_LOGI("StopNetObserver unregister success");
                return;
            }
            retryCount++;
            WIFI_LOGE("StopNetObserver retry, ret = %{public}d", ret);
            sleep(1);
        } while (retryCount < RETRY_MAX_TIMES);
        WIFI_LOGE("StopNetObserver failed");
    });
    th.detach();
}

int32_t NetStateObserver::NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
    const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap)
{
    if (netAllCap == nullptr) {
        return 0;
    }

    for (auto info : netAllCap->netCaps_) {
        WIFI_LOGI("netAllCap: %{public}d", info);
    }

    if (netAllCap->bearerTypes_.count(NetManagerStandard::BEARER_CELLULAR) > 0) {
        WIFI_LOGI("NetCapabilitiesChange NetBearType BEARER_CELLULAR");
        if (m_Callback != nullptr) {
            m_Callback(NETWORK_CELL_WORKING);
        }
    } else {
        WIFI_LOGI("NetCapabilitiesChange NetBearType NO CELL");
        if (m_Callback != nullptr) {
            m_Callback(NETWORK_CELL_NOWORK);
        }
    }

    return 0;
}

SystemNetWorkState NetStateObserver::GetCellNetState()
{
    NetHandle netHandle;
    NetManagerStandard::NetAllCapabilities netAllCap;
    int32_t result = NetConnClient::GetInstance().GetDefaultNet(netHandle);
    if (result != NETMANAGER_SUCCESS) {
        WIFI_LOGE("GetCellNetState GetDefaultNet failed!");
        return NETWORK_UNKNOWN;
    }
    NetConnClient::GetInstance().GetNetCapabilities(netHandle, netAllCap);
    
    if (netAllCap.bearerTypes_.count(NetManagerStandard::BEARER_CELLULAR) > 0) {
        WIFI_LOGI("GetCellNetState is cell working");
        return NETWORK_CELL_WORKING;
    }
    WIFI_LOGI("GetCellNetState is cell no work");
    return NETWORK_CELL_NOWORK;
}
}
}
