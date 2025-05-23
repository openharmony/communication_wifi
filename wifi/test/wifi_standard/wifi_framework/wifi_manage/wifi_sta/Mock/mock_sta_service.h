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
#ifndef OHOS_MOCK_WIFISTASERVICE_H
#define OHOS_MOCK_WIFISTASERVICE_H

#include <gmock/gmock.h>
#include "sta_service.h"

namespace OHOS {
namespace Wifi {
class MockWifiStaService : public StaService {
public:
    MockWifiStaService() {}
    virtual ~MockWifiStaService() {}
    MOCK_METHOD1(InitStaService, ErrCode(const std::vector<StaServiceCallback> &callbacks));
    MOCK_METHOD0(EnableStaService, ErrCode());
    MOCK_CONST_METHOD0(DisableStaService, ErrCode());
    MOCK_CONST_METHOD1(ConnectToDevice, ErrCode(const WifiDeviceConfig &config));
    MOCK_CONST_METHOD2(ConnectToNetwork, ErrCode(int networkId, int type));
    MOCK_CONST_METHOD0(ReConnect, ErrCode());
    MOCK_CONST_METHOD0(Disconnect, ErrCode());
    MOCK_CONST_METHOD0(ReAssociate, ErrCode());
    MOCK_CONST_METHOD1(AddDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_CONST_METHOD1(UpdateDeviceConfig, int(const WifiDeviceConfig &config));
    MOCK_CONST_METHOD1(RemoveDevice, ErrCode(int networkId));
    MOCK_CONST_METHOD2(EnableDeviceConfig, ErrCode(int networkId, bool attemptEnable));
    MOCK_CONST_METHOD1(DisableDeviceConfig, ErrCode(int networkId));
    MOCK_CONST_METHOD2(AllowAutoConnect, ErrCode(int32_t networkId, bool isAllowed));
    MOCK_CONST_METHOD1(StartWps, ErrCode(const WpsConfig &config));
    MOCK_CONST_METHOD0(CancelWps, ErrCode());
    MOCK_METHOD1(AutoConnectService, ErrCode(const std::vector<InterScanInfo> &scanInfos));
    MOCK_CONST_METHOD1(RegisterStaServiceCallback, void(const std::vector<StaServiceCallback> &callbacks));
    MOCK_CONST_METHOD1(UnRegisterStaServiceCallback, void(const StaServiceCallback &callbacks));
    MOCK_CONST_METHOD2(ConnectToCandidateConfig, ErrCode(const int uid, const int networkId));
    MOCK_CONST_METHOD2(RemoveCandidateConfig, ErrCode(const int uid, const int networkId));
    MOCK_CONST_METHOD1(RemoveAllCandidateConfig, ErrCode(const int uid));
    MOCK_CONST_METHOD1(SetSuspendMode, ErrCode(bool mode));
    MOCK_CONST_METHOD0(RemoveAllDevice, ErrCode());
    MOCK_CONST_METHOD3(AddCandidateConfig, ErrCode(const int uid, const WifiDeviceConfig &config, int& netWorkId));
    MOCK_METHOD2(RegisterAutoJoinCondition, ErrCode(const std::string&, const std::function<bool()> &));
    MOCK_METHOD1(DeregisterAutoJoinCondition, ErrCode(const std::string&));
    MOCK_METHOD3(RegisterFilterBuilder, ErrCode(const FilterTag &, const std::string &, const FilterBuilder &));
    MOCK_METHOD2(DeregisterFilterBuilder, ErrCode(const FilterTag &, const std::string &));
    MOCK_METHOD0(StartHttpDetect, ErrCode());
    MOCK_CONST_METHOD3(StartConnectToBssid, ErrCode(const int networkId, const std::string bssid, int32_t type));
    MOCK_CONST_METHOD2(StartConnectToUserSelectNetwork, ErrCode(const int networkId, const std::string bssid));
    MOCK_CONST_METHOD1(SetPowerMode, ErrCode(bool mode));
    MOCK_CONST_METHOD1(SetTxPower, ErrCode(int power));
    MOCK_METHOD2(OnSystemAbilityChanged, ErrCode(int systemAbilityid, bool add));
    MOCK_METHOD1(GetDetectNetState, void(OperateResState &state));
    MOCK_CONST_METHOD1(SetWifiRestrictedList, ErrCode(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList));
};
}  // namespace OHOS
}  // namespace OHOS
#endif