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
#include "wifi_hisysevent.h"

DEFINE_WIFILOG_LABEL("WifiNetObserver");

namespace OHOS {
namespace Wifi {
using namespace NetManagerStandard;

#define NETWORK 1
#define NO_NETWORK 0
#define ARP_OPT 0

NetStateObserver::NetStateObserver(): m_callback(nullptr)
{
    WIFI_LOGD("construct NetStateObserver");
}

NetStateObserver::~NetStateObserver()
{
    WIFI_LOGD("~NetStateObserver");
}

void NetStateObserver::SetNetStateCallback(const std::function<void(SystemNetWorkState, std::string)> &callback)
{
    m_callback = callback;
}

void NetStateObserver::StartNetStateObserver(sptr<NetStateObserver> &netStateObserverPtr)
{
    int32_t netId = GetWifiNetId();
    int32_t ret = NetManagerStandard::NetConnClient::GetInstance().RegisterNetDetectionCallback(
        netId, netStateObserverPtr);
    if (ret == 0) {
        WIFI_LOGI("StartNetObserver register success, netId=%{public}d", netId);
        return;
    }
    WIFI_LOGI("StartNetObserver failed, netId=%{public}d, ret=%{public}d", netId, ret);
}

void NetStateObserver::StopNetStateObserver(sptr<NetStateObserver> &netStateObserverPtr)
{
    int32_t netId = GetWifiNetId();
    int32_t ret = NetManagerStandard::NetConnClient::GetInstance().UnRegisterNetDetectionCallback(
        netId, netStateObserverPtr);
    if (ret == 0) {
        WIFI_LOGI("StopNetObserver unregister success, netId=%{public}d", netId);
        return;
    }
    WIFI_LOGI("StopNetObserver failed, netId=%{public}d, ret=%{public}d", netId, ret);
}

int32_t NetStateObserver::OnNetDetectionResultChanged(
    NetManagerStandard::NetDetectionResultCode detectionResult, const std::string &urlRedirect)
{
    WIFI_LOGI("OnNetDetectionResultChanged nettype:%{public}d, url:%{public}s", detectionResult, urlRedirect.c_str());
    switch (detectionResult) {
        case NetManagerStandard::NET_DETECTION_CAPTIVE_PORTAL: {
            m_callback(SystemNetWorkState::NETWORK_IS_PORTAL, urlRedirect);
            break;
        }
        case NetManagerStandard::NET_DETECTION_FAIL: {
            WriteWifiAccessIntFailedHiSysEvent(ARP_OPT, StaArpState::ARP_STATE_UNREACHABLE);
            WriteIsInternetHiSysEvent(NO_NETWORK);
            m_callback(SystemNetWorkState::NETWORK_NOTWORKING, "");
            break;
        }
        case NetManagerStandard::NET_DETECTION_SUCCESS: {
            WriteIsInternetHiSysEvent(NETWORK);
            m_callback(SystemNetWorkState::NETWORK_IS_WORKING, "");
            break;
        }
        default:
            // do nothing
            break;
    }
    return 0;
}

sptr<NetHandle> NetStateObserver::GetWifiNetworkHandle()
{
    std::list<sptr<NetHandle>> netList;
    int32_t ret = NetConnClient::GetInstance().GetAllNets(netList);
    if (ret != NETMANAGER_SUCCESS) {
        WIFI_LOGE("GetAllNets failed ret = %{public}d", ret);
        return nullptr;
    }
    for (auto iter : netList) {
        NetManagerStandard::NetAllCapabilities netAllCap;
        NetConnClient::GetInstance().GetNetCapabilities(*iter, netAllCap);
        if (netAllCap.bearerTypes_.count(NetManagerStandard::BEARER_WIFI) > 0) {
            return iter;
        }
    }
    WIFI_LOGE("GetWifiNetworkHandle not find wifi network");
    return nullptr;
}
 
int32_t NetStateObserver::StartWifiDetection()
{
    WIFI_LOGI("StartWifiDetection start");
    sptr<NetHandle> netHandle = GetWifiNetworkHandle();
    if (netHandle == nullptr) {
        WIFI_LOGE("StartWifiDetection failed!");
        return 1;
    }
    int32_t res = NetConnClient::GetInstance().NetDetection(*netHandle);
    if (res != 0) {
        WIFI_LOGE("StartWifiDetection failed %{public}d", res);
        return 1;
    }
    return 0;
}

int32_t NetStateObserver::GetWifiNetId()
{
    sptr<NetHandle> netHandle = GetWifiNetworkHandle();
    if (netHandle != nullptr) {
        return netHandle->GetNetId();
    }
    return 0;
}
}
}
