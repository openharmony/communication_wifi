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
#ifndef OHOS_MOCK_WIFI_MANAGER_H
#define OHOS_MOCK_WIFI_MANAGER_H

#include <gmock/gmock.h>
#include "iscan_service_callbacks.h"

namespace OHOS {
namespace Wifi {
class MockWifiManager {
public:
    virtual ~MockWifiManager() = default;
    virtual void DealScanOpenRes(int instId = 0) = 0;
    virtual void DealScanCloseRes(int instId = 0) = 0;
    virtual void DealScanFinished(int state, int instId = 0) = 0;
    virtual void DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId = 0) = 0;
    virtual void DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId = 0) = 0;
};

class WifiManager : public MockWifiManager {
public:
    WifiManager();
    ~WifiManager() = default;
    static WifiManager &GetInstance();
    IScanSerivceCallbacks GetScanCallback();

    MOCK_METHOD1(DealScanOpenRes, void(int));
    MOCK_METHOD1(DealScanCloseRes, void(int));
    MOCK_METHOD2(DealScanFinished, void(int state, int));
    MOCK_METHOD2(DealScanInfoNotify, void(std::vector<InterScanInfo> &results, int));
    MOCK_METHOD2(DealStoreScanInfoEvent, void(std::vector<InterScanInfo> &results, int));

private:
    IScanSerivceCallbacks mScanCallback;
    void InitScanCallback(void);
};
}  // namespace Wifi
}  // namespace OHOS

#endif