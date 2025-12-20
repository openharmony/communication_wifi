/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifiscansa_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <mutex>
#include "securec.h"
#include "define.h"
#include "wifi_logger.h"
#include "iscan_service.h"
#include "wifi_scan_service_impl.h"
#include "wifi_scan_mgr_service_impl.h"
#include "wifi_settings.h"
#include "wifi_toggler_manager.h"
#include "wifi_errcode.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
constexpr int TWO = 2;
constexpr int U32_AT_SIZE_ZERO = 4;
static const int32_t NUM_BYTES = 1;

OHOS::Wifi::WifiScanServiceImpl pWifiScanServiceImpl;
WifiScanMgrServiceImpl pWifiScanMgrServiceImpl;
class IWifiScanCallbackMock : public IWifiScanCallback {
public:
    IWifiScanCallbackMock()
    {
        LOGE("IWifiScanCallbackMock");
    }

    virtual ~IWifiScanCallbackMock()
    {
        LOGE("~IWifiScanCallbackMock");
    }

public:
    void OnWifiScanStateChanged(int state) override
    {
        LOGE("OnWifiScanStateChanged Mock");
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

ErrCode WifiTogglerManager::ScanOnlyToggled(int isOpen)
{
    return WIFI_OPT_SUCCESS;
}

void SetScanControlInfoFuzzTest()
{
    ScanControlInfoParcel parcelInfo;
    pWifiScanServiceImpl.SetScanControlInfo(parcelInfo);
}

void ScanFuzzTest(const uint8_t* data, size_t size)
{
    bool status = (static_cast<int>(data[0]) % TWO) ? true : false;
    pWifiScanServiceImpl.Scan(status);
}

void AdvanceScanFuzzTest()
{
    WifiScanParams params;
    pWifiScanServiceImpl.AdvanceScan(params);
}

void IsWifiScanAllowedFuzzTest(const uint8_t* data, size_t size)
{
    bool status = (static_cast<int>(data[0]) % TWO) ? true : false;
    int scanStyle = SCAN_DEFAULT_TYPE;
    pWifiScanServiceImpl.IsWifiScanAllowed(scanStyle, status);
}

void GetScanInfoListFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<WifiScanInfo> result;
    bool status = (static_cast<int>(data[0]) % TWO) ? true : false;
    pWifiScanServiceImpl.GetScanInfoList(result, status);
}

void SetScanOnlyAvailableFuzzTest(const uint8_t* data, size_t size)
{
    bool status = (static_cast<int>(data[0]) % TWO) ? true : false;
    pWifiScanServiceImpl.SetScanOnlyAvailable(status);
}

void StartWifiPnoScanFuzzTest(const uint8_t* data, size_t size)
{
    bool isStartAction = (static_cast<int>(data[0]) % TWO) ? true : false;
    int periodMs = static_cast<int>(data[0]);
    int suspendReason = static_cast<int>(data[0]);
    pWifiScanServiceImpl.StartWifiPnoScan(isStartAction, periodMs, suspendReason);
}

void GetSupportedFeaturesFuzzTest(const uint8_t* data, size_t size)
{
    long features = static_cast<long>(data[0]);
    int64_t featuresInt64 = static_cast<int64_t>(features);
    pWifiScanServiceImpl.GetSupportedFeatures(featuresInt64);
}

void SaBasicDumpFuzzTest(FuzzedDataProvider& FDP)
{
    std::string result = FDP.ConsumeBytesAsString(NUM_BYTES);
    pWifiScanServiceImpl.SaBasicDump(result);
}

void RegisterCallBackFuzzTest(const uint8_t* data, size_t size)
{
    sptr<IWifiScanCallback> callback = new (std::nothrow)IWifiScanCallbackMock();
    std::vector<std::string> event;
    event.push_back(std::string(reinterpret_cast<const char*>(data), size));
    pWifiScanServiceImpl.RegisterCallBack(callback, event);
}

void WifiScanServiceImplFuzzTest(const uint8_t* data, size_t size)
{
    std::string appId = std::string(reinterpret_cast<const char*>(data), size);
    pWifiScanServiceImpl.IsAllowedThirdPartyRequest(appId);
    pWifiScanServiceImpl.IsRemoteDied();
    pWifiScanServiceImpl.IsInScanMacInfoWhiteList();
}

void WifiScanMgrServiceImplFuzzTest(const uint8_t* data, size_t size)
{
    int32_t fd = static_cast<int32_t>(data[0]);
    std::vector<std::u16string> args;
    pWifiScanMgrServiceImpl.Dump(fd, args);
}

void WifiScanImplFuzzTest(FuzzedDataProvider& FDP)
{
    WifiScanParamsParcel paramsParcel;
    bool compatible = FDP.ConsumeBool();
    bool bOpen = FDP.ConsumeBool();
    std::string bundleName = FDP.ConsumeBytesAsString(NUM_BYTES);
    int32_t scanResultCode = FDP.ConsumeIntegral<int32_t>();
    std::vector<WifiInfoElem> infoElems;
    size_t maxIeLen = FDP.ConsumeIntegral<size_t>();
    size_t ieSize = FDP.ConsumeIntegral<size_t>();
    Parcel outParcel;
    pWifiScanServiceImpl.Scan(compatible, bundleName, scanResultCode);
    pWifiScanServiceImpl.PermissionVerification();
    pWifiScanServiceImpl.AdvanceScan(paramsParcel, bundleName);
    pWifiScanServiceImpl.IsWifiClosedScan(bOpen);
    pWifiScanServiceImpl.WriteInfoElementsToParcel(infoElems, ieSize, maxIeLen, outParcel);
}

void WifiScanSendScanInfoFuzzTest(FuzzedDataProvider& FDP)
{
    int32_t contentSize = FDP.ConsumeIntegral<int32_t>();
    size_t infoCount = FDP.ConsumeIntegral<size_t>();
    if (infoCount == 0) {
        return;
    }

    std::vector<WifiScanInfo> result;

    for (size_t i = 0; i < infoCount; ++i) {
        WifiScanInfo info;

        size_t bssidLen = FDP.ConsumeIntegral<size_t>();
        std::string bssid = FDP.ConsumeBytesAsString(bssidLen);
        info.bssid = bssid;

        size_t ssidLen = FDP.ConsumeIntegral<size_t>();
        std::string ssid = FDP.ConsumeBytesAsString(ssidLen);
        info.ssid = ssid;

        info.bssidType = FDP.ConsumeIntegral<int32_t>();
        info.frequency = FDP.ConsumeIntegral<int32_t>();
        info.band = FDP.ConsumeIntegral<uint8_t>();
        info.channelWidth = static_cast<WifiChannelWidth>(FDP.ConsumeIntegral<uint8_t>());
        info.centerFrequency0 = FDP.ConsumeIntegral<int32_t>();
        info.centerFrequency1 = FDP.ConsumeIntegral<int32_t>();
        info.rssi = FDP.ConsumeIntegral<int32_t>();
        info.securityType = static_cast<WifiSecurity>(FDP.ConsumeIntegral<uint8_t>());
        info.features = FDP.ConsumeIntegral<uint32_t>();
        info.timestamp = FDP.ConsumeIntegral<int64_t>();
        info.wifiStandard = FDP.ConsumeIntegral<uint8_t>();
        info.maxSupportedRxLinkSpeed = FDP.ConsumeIntegral<uint32_t>();
        info.maxSupportedTxLinkSpeed = FDP.ConsumeIntegral<uint32_t>();
        info.disappearCount = FDP.ConsumeIntegral<uint32_t>();
        info.isHiLinkNetwork = FDP.ConsumeBool();
        info.isHiLinkProNetwork = FDP.ConsumeBool();
        info.supportedWifiCategory = static_cast<WifiCategory>(FDP.ConsumeIntegral<uint8_t>());
        info.riskType = static_cast<WifiRiskType>(FDP.ConsumeIntegral<uint8_t>());

        result.push_back(info);
    }

    std::vector<uint32_t> allSizeUint;
    ScanAshmemParcel outAshmemParcel;

    pWifiScanServiceImpl.SendScanInfo(contentSize, result, outAshmemParcel, allSizeUint);
}

void WifiScanGetScanInfoListFuzzTest(FuzzedDataProvider& FDP)
{
    ScanAshmemParcel outAshmemParcel;
    bool compatible = FDP.ConsumeBool();
    std::vector<int32_t> allSize;
    pWifiScanServiceImpl.GetScanInfoList(compatible, outAshmemParcel, allSize);
}

void WifiScanGetScanOnlyAvailableFuzzTest(FuzzedDataProvider& FDP)
{
    bool bScanOnlyAvailable = FDP.ConsumeBool();
    pWifiScanServiceImpl.GetScanOnlyAvailable(bScanOnlyAvailable);
}

void WifiScanRegisterCallBackFuzzTest(FuzzedDataProvider& FDP)
{
    uintptr_t ptrValue = FDP.ConsumeIntegral<uintptr_t>();
    if (ptrValue == 0) {
        ptrValue = 0x1000;
    }

    auto cbParcel = sptr<IRemoteObject>(reinterpret_cast<IRemoteObject*>(ptrValue));

    if (cbParcel == nullptr) {
        return;
    }

    const sptr<IRemoteObject>& cbParcelRef = cbParcel;

    int32_t pid = FDP.ConsumeIntegral<int32_t>();
    int32_t tokenId = FDP.ConsumeIntegral<int32_t>();
    std::vector<std::string> event;
    pWifiScanServiceImpl.RegisterCallBack(cbParcelRef, pid, tokenId, event);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::SaBasicDumpFuzzTest(FDP);
    OHOS::Wifi::SetScanControlInfoFuzzTest();
    OHOS::Wifi::ScanFuzzTest(data, size);
    OHOS::Wifi::AdvanceScanFuzzTest();
    OHOS::Wifi::IsWifiScanAllowedFuzzTest(data, size);
    OHOS::Wifi::GetScanInfoListFuzzTest(data, size);
    OHOS::Wifi::SetScanOnlyAvailableFuzzTest(data, size);
    OHOS::Wifi::StartWifiPnoScanFuzzTest(data, size);
    OHOS::Wifi::GetSupportedFeaturesFuzzTest(data, size);
    OHOS::Wifi::RegisterCallBackFuzzTest(data, size);
    OHOS::Wifi::WifiScanServiceImplFuzzTest(data, size);
    OHOS::Wifi::WifiScanMgrServiceImplFuzzTest(data, size);
    OHOS::Wifi::WifiScanImplFuzzTest(FDP);
    OHOS::Wifi::WifiScanGetScanInfoListFuzzTest(FDP);
    OHOS::Wifi::WifiScanGetScanOnlyAvailableFuzzTest(FDP);
    return 0;
}
}
}
