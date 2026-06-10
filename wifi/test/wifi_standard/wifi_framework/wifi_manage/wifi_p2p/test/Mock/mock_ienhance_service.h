/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_IENHANCE_SERVICE_H
#define OHOS_MOCK_IENHANCE_SERVICE_H
#include <gmock/gmock.h>
#include "ienhance_service.h"

namespace OHOS {
namespace Wifi {
class MockEnhanceService : public IEnhanceService {
public:
    MOCK_METHOD0(Init, ErrCode());
    MOCK_METHOD0(UnInit, ErrCode());
    MOCK_METHOD0(AllowScanBySchedStrategy, bool());
    MOCK_METHOD1(SetEnhanceParam, ErrCode(int64_t));
    MOCK_METHOD5(InstallFilterProgram, ErrCode(unsigned int, int, const unsigned char *, int, int));
    MOCK_METHOD3(GetWifiCategory, WifiCategory(std::vector<WifiInfoElem>, int, int));
    MOCK_METHOD1(SetLowTxPower, ErrCode(const WifiLowPowerParam));
    MOCK_METHOD1(NotifyInternetState, void(const int));
    MOCK_METHOD2(NotifyWurState, void(const int, const uint16_t));
    MOCK_METHOD1(NotifyAudioSceneChanged, void(const bool));
    MOCK_METHOD2(ProcessWifiNetlinkReportEvent, void(const int, const std::vector<uint8_t> &));
    MOCK_METHOD0(CheckChbaConncted, bool());
    MOCK_METHOD1(StopGetCacResultAndLocalCac, void(int));
    MOCK_METHOD0(GetCacRadarDetectionStatus, IsCACDetectInProgress());
    MOCK_METHOD1(IsScanAllowed, bool(WifiScanDeviceInfo &));
    MOCK_METHOD1(IsItCustNetwork, bool(WifiDeviceConfig &));
    MOCK_METHOD3(DealDhcpOfferResult, ErrCode(const OperationCmd &, const IpInfo &, uint32_t &));
    MOCK_METHOD1(IsGatewayChanged, ErrCode(bool &));
    MOCK_METHOD3(GetStaticIpConfig, ErrCode(const bool &, const bool &, IpInfo &));
    MOCK_METHOD0(IsWideBandwidthSupported, bool());
    MOCK_METHOD2(RegisterP2pEnhanceCallback, ErrCode(const std::string &, P2pEnhanceCallback));
    MOCK_METHOD1(IsCustomNetwork, bool(WifiDeviceConfig &));
    MOCK_METHOD0(CheckEnhanceVapAvailable, bool());
    MOCK_METHOD1(IsSpecificNetwork, bool(WifiDeviceConfig &));
    MOCK_METHOD3(Hid2dGetSelfWifiCfgInfo, ErrCode(SelfCfgType, char[CFG_DATA_MAX_BYTES], int *));
    MOCK_METHOD3(Hid2dSetPeerWifiCfgInfo, ErrCode(PeerCfgType, char[CFG_DATA_MAX_BYTES], int));
    MOCK_METHOD0(OnSettingsWlanEnterReceive, void());
    MOCK_METHOD2(OnSettingsDialogClick, void(bool, Wifi5gFeatureType));
    MOCK_METHOD1(OnNotificationReceive, void(int));
    MOCK_METHOD1(OnDontShowReceive, void(int));
    MOCK_METHOD1(OnDialogClick, void(bool));
    MOCK_METHOD0(ResetNetworkSettingsNotify, void());
    MOCK_METHOD2(FreqEnhance, int(int, bool));
    MOCK_METHOD1(SetEnhanceSignalPollInfo, void(WifiSignalPollInfo &));
    MOCK_METHOD1(NotifyMloSignalPollInfo, void(std::vector<WifiSignalPollInfo> &));
    MOCK_METHOD1(CrowdsourcedDataReportInterface, void(const WifiCrowdsourcedInfo &));
    MOCK_METHOD1(OnWifiLinkTypeChanged, void(const WifiLinkType &));
    MOCK_METHOD0(HandleBeaconLost, void());
    MOCK_METHOD2(CheckPortalNet, std::string(const std::string &, const std::string &));
    MOCK_METHOD0(GetLimitSwitchScenes, LimitSwitchScenes());
    MOCK_METHOD0(GetDfsControlData, DfsControlData());
    MOCK_METHOD0(CloseCAC, void());
    MOCK_METHOD1(RegisterSensorEnhanceCallback, ErrCode(SensorEnhanceCallback));
    MOCK_METHOD2(CheckScanInfo, bool(bool, int));
    MOCK_METHOD1(CheckScanInfoInUnsafeWiFiWhiteList, bool(InterScanInfo &));
    MOCK_METHOD0(GetIpv6ControlData, Ipv6ControlData());
    MOCK_METHOD0(IsInActionListenState, bool());
    MOCK_METHOD2(ReportChrEventData, void(const std::string, const std::string));
    MOCK_METHOD1(GetPackageNum, int32_t(std::string));
    MOCK_METHOD2(ReadNvInfo, ErrCode(int, std::string &));
    MOCK_METHOD1(OnFoldStateChanged, void(const int));
    MOCK_METHOD2(SetChipSetInfos, void(int, int));
    MOCK_METHOD0(IsSupportLpScanAbility, bool());
    MOCK_METHOD2(NotifyWifiDisconnectReason, void(const int, const int));
    MOCK_METHOD0(GrsProbe, bool());
    MOCK_METHOD2(GenelinkInterface, int(int, int));
    MOCK_METHOD1(NotifyGenelinkSelectedConfig, ErrCode(WifiDeviceConfig &));
    MOCK_METHOD1(RegisterStaEnhanceCallback, ErrCode(StaEnhanceCallback));
    MOCK_METHOD2(SetBtCoexistState, ErrCode(CoexistState, CoexistReason));
    MOCK_METHOD2(SetGameLatencyFeatureEnabled, void(bool, const std::string &));
    MOCK_METHOD3(OnWifiDeviceConfigChange, void(int32_t, const WifiDeviceConfig &, bool));
    MOCK_METHOD2(IsSameGateway, bool(const std::string &, const std::string &));
    MOCK_METHOD3(UpdateGatewayRelation, void(std::string &, std::string &, bool));
    MOCK_METHOD0(GetDeviceFeatures, WifiDeviceFeatures());
    MOCK_METHOD3(SetEnhanceP2pSignalPollInfo, void(bool, const WifiSignalPollInfo &, const std::string));
    MOCK_METHOD1(RegisterMovementEnhanceCallback, ErrCode(MovementEnhanceCallback));
    MOCK_METHOD0(UnRegisterMovementEnhanceCallback, ErrCode());
#ifndef OHOS_ARCH_LITE
    MOCK_METHOD1(GetWifiEnhanceConfig, EnhanceConfigVariant(WifiEnhanceConfigType));
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif