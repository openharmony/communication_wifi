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
#include "mock_wifi_manager.h"


namespace OHOS {
namespace Wifi {
WifiManager &WifiManager::GetInstance()
{
    static WifiManager gWifiManager;
    return gWifiManager;
}

WifiManager::WifiManager()
{
    InitScanCallback();
}

IScanSerivceCallbacks WifiManager::GetScanCallback(void)
{
    return mScanCallback;
}

void WifiManager::InitScanCallback(void)
{
    using namespace std::placeholders;
    mScanCallback.OnScanStartEvent = std::bind(&WifiManager::DealScanOpenRes, this, _1);
    mScanCallback.OnScanStopEvent = std::bind(&WifiManager::DealScanCloseRes, this, _1);
    mScanCallback.OnScanFinishEvent = std::bind(&WifiManager::DealScanFinished, this, _1, _2);
    mScanCallback.OnScanInfoEvent = std::bind(&WifiManager::DealScanInfoNotify, this, _1, _2);
    mScanCallback.OnStoreScanInfoEvent = std::bind(&WifiManager::DealStoreScanInfoEvent, this, _1, _2);
    return;
}

std::unique_ptr<WifiStaManager>& WifiManager::GetWifiStaManager()
{
    return wifiStaManager;
}
 
std::unique_ptr<WifiScanManager>& WifiManager::GetWifiScanManager()
{
    return wifiScanManager;
}
 
std::unique_ptr<WifiTogglerManager>& WifiManager::GetWifiTogglerManager()
{
    return wifiTogglerManager;
}
 
std::unique_ptr<WifiHotspotManager>& WifiManager::GetWifiHotspotManager()
{
    return wifiHotspotManager;
}
 
std::unique_ptr<WifiEventSubscriberManager>& WifiManager::GetWifiEventSubscriberManager()
{
    return wifiEventSubscriberManager;
}
 
std::unique_ptr<WifiMultiVapManager>& WifiManager::GetWifiMultiVapManager()
{
    return wifiMultiVapManager;
}
 
int WifiManager::Init()
{
    mCloseServiceThread = std::make_unique<WifiEventHandler>("CloseServiceThread");
    wifiEventSubscriberManager = std::make_unique<WifiEventSubscriberManager>();
    wifiMultiVapManager = std::make_unique<WifiMultiVapManager>();
    wifiStaManager = std::make_unique<WifiStaManager>();
    wifiScanManager = std::make_unique<WifiScanManager>();
    wifiTogglerManager = std::make_unique<WifiTogglerManager>();
    wifiHotspotManager = std::make_unique<WifiHotspotManager>();
    return 0;
}
 
void WifiManager::Exit()
{
    if (mCloseServiceThread) {
        mCloseServiceThread.reset();
    }
    if (mStartServiceThread) {
        mStartServiceThread.reset();
    }
    if (wifiStaManager) {
        wifiStaManager.reset();
    }
    if (wifiScanManager) {
        wifiScanManager.reset();
    }
    if (wifiTogglerManager) {
        wifiTogglerManager.reset();
    }
    if (wifiHotspotManager) {
        wifiHotspotManager.reset();
    }
 
    if (wifiEventSubscriberManager) {
        wifiEventSubscriberManager.reset();
    }
    if (wifiMultiVapManager) {
        wifiMultiVapManager.reset();
    }
    return;
}
} // namespace Wifi
} // namespace OHOS