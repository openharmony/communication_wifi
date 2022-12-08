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
#include "../../../../../../frameworks/native/src/wifi_p2p_impl.h"
#include "../../../../../../frameworks/native/include/wifi_p2p.h"

namespace OHOS {
namespace Wifi {
    static std::unique_ptr<WifiP2p> WifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
    void RequestServiceTest(const uint8_t* data, size_t size)
    {
        WifiP2pDevice device;
        WifiP2pServiceRequest request;
        if (size >= THREE) {
            int index = 0;
            std::string deviceName = std::string(reinterpret_cast<const char*>(data), size);
            std::string networkName = std::string(reinterpret_cast<const char*>(data), size);
            std::string mDeviceAddress = std::string(reinterpret_cast<const char*>(data), size);
            std::string primaryDeviceType = std::string(reinterpret_cast<const char*>(data), size);
            std::string secondaryDeviceType = std::string(reinterpret_cast<const char*>(data), size);
            unsigned int supportWpsConfigMethods = static_cast<unsigned int>(data[index++]);
            int deviceCapabilitys = static_cast<int>(data[index++]);
            int groupCapabilitys = static_cast<int>(data[index++]);
            device.SetDeviceName(deviceName);
            device.SetNetworkName(networkName);
            device.SetDeviceAddress(mDeviceAddress);
            device.SetPrimaryDeviceType(primaryDeviceType);
            device.SetSecondaryDeviceType(secondaryDeviceType);
            device.SetWpsConfigMethod(supportWpsConfigMethods);
            device.SetDeviceCapabilitys(deviceCapabilitys);
            device.SetGroupCapabilitys(groupCapabilitys);
        }
        WifiP2pPtr->RequestService(device, request);
    }

    void PutLocalP2pServiceTest(const uint8_t* data, size_t size)
    {
        WifiP2pServiceInfo srvInfo;
        std::string serviceName = std::string(reinterpret_cast<const char*>(data), size);
        std::string mDeviceAddress = std::string(reinterpret_cast<const char*>(data), size);
        srvInfo.SetServiceName(serviceName);
        srvInfo.SetDeviceAddress(mDeviceAddress);
        WifiP2pPtr->PutLocalP2pService(srvInfo);
    }

    void DeleteLocalP2pServiceTest(const uint8_t* data, size_t size)
    {
        WifiP2pServiceInfo srvInfo;
        std::string serviceName = std::string(reinterpret_cast<const char*>(data), size);
        std::string mDeviceAddress = std::string(reinterpret_cast<const char*>(data), size);
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
        std::string groupOwnerAddress = std::string(reinterpret_cast<const char*>(data), size);
        linkedInfo.SetIsGroupOwner(isP2pGroupOwner);
        linkedInfo.SetIsGroupOwnerAddress(groupOwnerAddress);
        WifiP2pPtr->QueryP2pLinkedInfo(linkedInfo);
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
        WifiP2pWfdInfo wfdInfo;
        if (size >= FOUR) {
            int index = 0;
            bool wfdEnabled = (static_cast<int>(data[index++]) % TWO) ? true : false;
            int deviceInfo = static_cast<int>(data[index++]);
            int ctrlPort = static_cast<int>(data[index++]);
            int maxThroughput =  static_cast<int>(data[index++]);
            wfdInfo.SetWfdEnabled(wfdEnabled);
            wfdInfo.SetDeviceInfo(deviceInfo);
            wfdInfo.SetCtrlPort(ctrlPort);
            wfdInfo.SetMaxThroughput(maxThroughput);
        }
        WifiP2pPtr->SetP2pWfdInfo(wfdInfo);
    }
    

    bool WifiHotSpotImplFuzzTest(const uint8_t* data, size_t size)
    {
        RequestServiceTest(data, size);
        PutLocalP2pServiceTest(data, size);
        DeleteLocalP2pServiceTest(data, size);
        QueryP2pLinkedInfoTest(data, size);
        GetP2pDiscoverStatusTest(data, size);
        QueryP2pServicesTest(data, size);
        GetSupportedFeaturesTest(data, size);
        IsFeatureSupportedTest(data, size);
        SetP2pDeviceNameTest(data, size);
        SetP2pWfdInfoTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiHotSpotImplFuzzTest(data, size);
    return 0;
}