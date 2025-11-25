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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "securec.h"
#include "wifip2pimpl_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include "src/wifi_p2p_impl.h"
#include "wifi_p2p.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
    static const int32_t NUM_BYTES = 1;
    static std::shared_ptr<WifiP2p> WifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
    void RequestServiceTest(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider FDP (data, size);
        WifiP2pDevice device;
        WifiP2pServiceRequest request;
        if (size >= THREE) {
                std::string deviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
                std::string networkName = FDP.ConsumeBytesAsString(NUM_BYTES);
                std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
                std::string primaryDeviceType = FDP.ConsumeBytesAsString(NUM_BYTES);
                std::string secondaryDeviceType = FDP.ConsumeBytesAsString(NUM_BYTES);
                unsigned int supportWpsConfigMethods = FDP.ConsumeIntegral<int>();
                int deviceCapabilitys = FDP.ConsumeIntegral<int>();
                int groupCapabilitys = FDP.ConsumeIntegral<int>();
                device.SetDeviceName(deviceName);
                device.SetNetworkName(networkName);
                device.SetDeviceAddress(mDeviceAddress);
                device.SetPrimaryDeviceType(primaryDeviceType);
                device.SetSecondaryDeviceType(secondaryDeviceType);
                device.SetWpsConfigMethod(supportWpsConfigMethods);
                device.SetDeviceCapabilitys(deviceCapabilitys);
                device.SetGroupCapabilitys(groupCapabilitys);

                WifiP2pPtr->RequestService(device, request);
            }
        }

    void PutLocalP2pServiceTest(FuzzedDataProvider& FDP)
    {
        WifiP2pServiceInfo srvInfo;
        std::string serviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
        srvInfo.SetServiceName(serviceName);
        srvInfo.SetDeviceAddress(mDeviceAddress);
        WifiP2pPtr->PutLocalP2pService(srvInfo);
    }

    void DeleteLocalP2pServiceTest(FuzzedDataProvider& FDP)
    {
        WifiP2pServiceInfo srvInfo;
        std::string serviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string mDeviceAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
        srvInfo.SetServiceName(serviceName);
        srvInfo.SetDeviceAddress(mDeviceAddress);
        WifiP2pPtr->DeleteLocalP2pService(srvInfo);
    }

    void QueryP2pLinkedInfoTest(const uint8_t* data, size_t size)
    {
        if (size == 0) {
            return;
        }
        WifiP2pLinkedInfo linkedInfo;
        bool isP2pGroupOwner = (static_cast<int>(data[0]) % TWO) ? true : false;
        linkedInfo.SetIsGroupOwner(isP2pGroupOwner);
        WifiP2pPtr->QueryP2pLinkedInfo(linkedInfo);
    }

    void QueryP2pLinkedInfoTest01(const uint8_t* data, size_t size)
    {
        if (size == 0) {
            return;
        }
        WifiP2pLinkedInfo linkedInfo;
        std::string groupOwnerAddress = std::string(reinterpret_cast<const char*>(data), size);
        linkedInfo.SetIsGroupOwnerAddress(groupOwnerAddress);
    }

    void GetP2pDiscoverStatusTest(const uint8_t* data, size_t size)
    {
        if (size == 0) {
            return;
        }
        int status = static_cast<int>(data[0]);
        WifiP2pPtr->GetP2pDiscoverStatus(status);
    }

    void QueryP2pServicesTest(const uint8_t* data, size_t size)
    {
        std::vector<WifiP2pServiceInfo> services;
        WifiP2pPtr->QueryP2pServices(services);
        FuzzedDataProvider fdp(data, size);
        int vectorLength = fdp.ConsumeIntegral<int>();
        for (int i = 0; i < vectorLength; i++) {
            WifiP2pServiceInfo servicetmp;
            services.push_back(servicetmp);
        }
        WifiP2pPtr->QueryP2pServices(services);
    }

    void GetSupportedFeaturesTest(const uint8_t* data, size_t size)
    {
        if (size < FOUR) {
            return;
        }
        long features = static_cast<long>(OHOS::Wifi::U32_AT(data));
        WifiP2pPtr->GetSupportedFeatures(features);
    }

    void IsFeatureSupportedTest(const uint8_t* data, size_t size)
    {
        if (size < FOUR) {
            return;
        }
        long features = static_cast<long>(OHOS::Wifi::U32_AT(data));
        WifiP2pPtr->IsFeatureSupported(features);
    }

    void SetP2pDeviceNameTest(const uint8_t* data, size_t size)
    {
        std::string deviceName = std::string(reinterpret_cast<const char*>(data), size);
        WifiP2pPtr->SetP2pDeviceName(deviceName);
    }

    void SetP2pWfdInfoTest(const uint8_t* data, size_t size)
    {
        FuzzedDataProvider FDP(data, size);
        WifiP2pWfdInfo wfdInfo;
        if (size >= FOUR) {
            bool wfdEnabled = FDP.ConsumeBool();
            int deviceInfo = FDP.ConsumeIntegral<int>();
            int ctrlPort = FDP.ConsumeIntegral<int>();
            int maxThroughput =  FDP.ConsumeIntegral<int>();
            wfdInfo.SetWfdEnabled(wfdEnabled);
            wfdInfo.SetDeviceInfo(deviceInfo);
            wfdInfo.SetCtrlPort(ctrlPort);
            wfdInfo.SetMaxThroughput(maxThroughput);
        }
        WifiP2pPtr->SetP2pWfdInfo(wfdInfo);
    }
    

    bool WifiHotSpotImplFuzzTest(const uint8_t* data, size_t size)
    {
        QueryP2pLinkedInfoTest(data, size);
        QueryP2pLinkedInfoTest01(data, size);
        GetP2pDiscoverStatusTest(data, size);
        QueryP2pServicesTest(data, size);
        GetSupportedFeaturesTest(data, size);
        IsFeatureSupportedTest(data, size);
        SetP2pDeviceNameTest(data, size);
        SetP2pWfdInfoTest(data, size);
        RequestServiceTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP (data, size);
    
    OHOS::Wifi::PutLocalP2pServiceTest(FDP);
    OHOS::Wifi::DeleteLocalP2pServiceTest(FDP);
    OHOS::Wifi::WifiHotSpotImplFuzzTest(data, size);
    return 0;
}