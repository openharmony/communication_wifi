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

#ifndef OHOS_MOCK_WIFI_CONFIG_CENTER_H
#define OHOS_MOCK_WIFI_CONFIG_CENTER_H

#include <gmock/gmock.h>
#include "wifi_internal_msg.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
class MockWifiConfigCenter {
public:
    virtual ~MockWifiConfigCenter() = default;
    virtual WifiOprMidState GetScanMidState(int instId = 0) = 0;
    virtual void SetScanMidState(WifiOprMidState state, int instId = 0) = 0;
    virtual bool SetScanMidState(WifiOprMidState expState, WifiOprMidState state, int instId = 0) = 0;
    virtual WifiOprMidState GetWifiMidState(int instId = 0) = 0;
    virtual void SetWifiMidState(WifiOprMidState state, int instId = 0) = 0;
    virtual bool SetWifiMidState(WifiOprMidState expState, WifiOprMidState state, int instId = 0) = 0;
    virtual WifiOprMidState GetP2pMidState() = 0;
    virtual void SetP2pMidState(WifiOprMidState state) = 0;
    virtual bool SetP2pMidState(WifiOprMidState expState, WifiOprMidState state) = 0;
    virtual WifiOprMidState GetWifiScanOnlyMidState(int instId = 0) = 0;
    virtual bool SetWifiScanOnlyMidState(WifiOprMidState expState, WifiOprMidState state, int instId = 0) = 0;
    virtual void SetWifiScanOnlyMidState(WifiOprMidState state, int instId = 0) = 0;
    virtual WifiDetailState GetWifiDetailState(int instId = 0) = 0;
    virtual int SetStaLastRunState(int bRun, int instId) = 0;  // todo
    virtual WifiOprMidState GetApMidState(int id = 0) = 0;
    virtual bool SetApMidState(WifiOprMidState expState, WifiOprMidState state, int id = 0) = 0;
    virtual void SetApMidState(WifiOprMidState state, int id = 0) = 0;
    virtual bool GetWifiFlagOnAirplaneMode(int instId) = 0;  // todo
    virtual int GetAirplaneModeState() const = 0;
    virtual bool SetWifiStateOnAirplaneChanged(const int &state) = 0;
    virtual int SetWifiFlagOnAirplaneMode(bool ifOpen, int instId) = 0;  // todo
    virtual int GetLinkedInfo(WifiLinkedInfo &info, int instId = 0) = 0;
    virtual int GetHotspotState(int id = 0) = 0;
    virtual int GetScanControlInfo(ScanControlInfo &info, int instId = 0) = 0;
    virtual bool IsScanAlwaysActive(int instId) = 0;  // todo
    virtual int GetPowerSavingModeState() const = 0;
};

class WifiConfigCenter : public MockWifiConfigCenter {
public:
    WifiConfigCenter() = default;
    ~WifiConfigCenter() = default;
    static WifiConfigCenter &GetInstance(void);
    MOCK_METHOD1(GetScanMidState, WifiOprMidState(int instId));
    MOCK_METHOD2(SetScanMidState, void(WifiOprMidState state, int instId));
    MOCK_METHOD3(SetScanMidState, bool(WifiOprMidState expState, WifiOprMidState state, int instId));
    MOCK_METHOD1(GetWifiMidState, WifiOprMidState(int instId));
    MOCK_METHOD2(SetWifiMidState, void(WifiOprMidState state, int instId));
    MOCK_METHOD3(SetWifiMidState, bool(WifiOprMidState expState, WifiOprMidState state, int instId));
    MOCK_METHOD0(GetP2pMidState, WifiOprMidState(void));
    MOCK_METHOD1(SetP2pMidState, void(WifiOprMidState state));
    MOCK_METHOD2(SetP2pMidState, bool(WifiOprMidState expState, WifiOprMidState state));
    MOCK_METHOD1(GetWifiScanOnlyMidState, WifiOprMidState(int instId));
    MOCK_METHOD3(SetWifiScanOnlyMidState, bool(WifiOprMidState expState, WifiOprMidState state, int instId));
    MOCK_METHOD2(SetWifiScanOnlyMidState, void(WifiOprMidState state, int instId));
    MOCK_METHOD1(GetWifiDetailState, WifiDetailState(int instId));
    MOCK_METHOD2(SetStaLastRunState, int(int bRun, int instId));  // todo
    MOCK_METHOD1(GetApMidState, WifiOprMidState(int id));
    MOCK_METHOD3(SetApMidState, bool(WifiOprMidState expState, WifiOprMidState state, int id));
    MOCK_METHOD2(SetApMidState, void(WifiOprMidState state, int id));
    MOCK_METHOD1(GetWifiFlagOnAirplaneMode, bool(int instId));
    MOCK_CONST_METHOD0(GetAirplaneModeState, int(void));
    MOCK_METHOD1(SetWifiStateOnAirplaneChanged, bool(const int &state));
    MOCK_METHOD2(SetWifiFlagOnAirplaneMode, int(bool ifOpen, int instId));  //todo
    MOCK_METHOD2(GetLinkedInfo, int(WifiLinkedInfo &info, int instId));
    MOCK_METHOD1(GetHotspotState, int(int id));
    MOCK_METHOD2(GetScanControlInfo, int(ScanControlInfo &info, int instId));
    MOCK_METHOD1(IsScanAlwaysActive, bool(int instId));  // todo
    MOCK_CONST_METHOD0(GetPowerSavingModeState, int(void));
};
}  // namespace Wifi
}  // namespace OHOS
#endif