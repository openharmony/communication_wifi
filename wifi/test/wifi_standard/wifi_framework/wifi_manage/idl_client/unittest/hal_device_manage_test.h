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
#ifndef OHOS_WIFI_HAL_DEVICE_MANAGE_TEST_H
#define OHOS_WIFI_HAL_DEVICE_MANAGE_TEST_H
#ifdef HDI_CHIP_INTERFACE_SUPPORT

#include <gtest/gtest.h>
#include "hal_device_manage.h"

namespace OHOS {
namespace Wifi {
class WifiHalDeviceManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        HalDeviceManager::GetInstance().StartChipHdi();
    }
    virtual void TearDown()
    {
        HalDeviceManager::GetInstance().StopChipHdi();
    }

    static void DestoryCallback(std::string &destoryIfaceName, int createIfaceType);
    static void OnRssiReportCallback(int index, int antRssi);
    static void OnNetlinkReportCallback(int type, const std::vector<uint8_t>& recvMsg);
};

class IChipIfaceTest : public IChipIface {
public:
    IChipIfaceTest() = default;
    ~IChipIfaceTest() = default;
    virtual int32_t GetIfaceType(IfaceType& type)
    {
        return 0;
    }
    virtual int32_t GetIfaceName(std::string& name)
    {
        return 0;
    }
    virtual int32_t GetIfaceCap(uint32_t& capabilities)
    {
        return 0;
    }
    virtual int32_t GetSupportFreqs(int32_t band, std::vector<uint32_t>& frequencies)
    {
        return 0;
    }
    virtual int32_t SetMacAddress(const std::string& mac)
    {
        return 0;
    }
    virtual int32_t SetCountryCode(const std::string& code)
    {
        return 0;
    }
    virtual int32_t GetPowerMode(int32_t& powerMode)
    {
        return 0;
    }
    virtual int32_t RegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
    {
        return 0;
    }
    virtual int32_t UnRegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback)
    {
        return 0;
    }
    virtual int32_t StartScan(const ScanParams& scanParam)
    {
        return 0;
    }
    virtual int32_t GetScanInfos(std::vector<ScanResultsInfo>& scanResultsInfo)
    {
        return 0;
    }
    virtual int32_t StartPnoScan(const PnoScanParams& pnoParams)
    {
        return 0;
    }
    virtual int32_t StopPnoScan()
    {
        return 0;
    }
    virtual int32_t GetSignalPollInfo(SignalPollResult& signalPollresult)
    {
        return 0;
    }
    virtual int32_t EnablePowerMode(int32_t mode)
    {
        return 0;
    }
    virtual int32_t SetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
    {
        return 0;
    }
    virtual int32_t SetTxPower(int32_t power)
    {
        return 0;
    }
    virtual int32_t SetPowerMode(int32_t powerMode)
    {
        return 0;
    }
    virtual int32_t SetIfaceState(bool state)
    {
        return 0;
    }
    virtual int32_t SendCmdToDriver(const std::string& ifName, int32_t cmdId, const std::vector<int8_t>& paramBuf)
    {
        return 0;
    }
    virtual int32_t SendActionFrame(const std::string& ifName, uint32_t freq, const std::vector<uint8_t>& frameData)
    {
        return 0;
    }
    virtual int32_t RegisterActionFrameReceiver(const std::string& ifName, const std::vector<uint8_t>& match)
    {
        return 0;
    }
    virtual int32_t GetCoexictenceChannelList(const std::string& ifName, std::vector<uint8_t>& paramBuf)
    {
        return 0;
    }
    virtual int32_t SetProjectionScreenParam(const std::string& ifName,
        const OHOS::HDI::Wlan::Chip::V1_0::ProjectionScreenCmdParam& param)
    {
        return 0;
    }
};

class IConcreteChipTest : public IConcreteChip {
public:
    IConcreteChipTest() = default;
    ~IConcreteChipTest() = default;
    virtual int32_t GetChipId(int32_t& id)
    {
        return 0;
    }
    virtual int32_t RegisterChipEventCallback(const sptr<IConcreteChipCallback>& chipEventcallback)
    {
        return 0;
    }
    virtual int32_t GetChipModes(std::vector<UsableMode>& modes)
    {
        return 0;
    }
    virtual int32_t GetChipCaps(uint32_t& capabilities)
    {
        return 0;
    }
    virtual int32_t GetCurrentMode(uint32_t& modeId)
    {
        return 0;
    }
    virtual int32_t CreateApService(sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t GetApServiceIfNames(std::vector<std::string>& ifnames)
    {
        return 0;
    }
    virtual int32_t GetApService(const std::string& ifname, sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t RemoveApService(const std::string& ifname)
    {
        return 0;
    }
    virtual int32_t CreateP2pService(sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t GetP2pServiceIfNames(std::vector<std::string>& ifnames)
    {
        return 0;
    }
    virtual int32_t GetP2pService(const std::string& ifname, sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t RemoveP2pService(const std::string& ifname)
    {
        return 0;
    }
    virtual int32_t CreateStaService(sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t GetStaServiceIfNames(std::vector<std::string>& ifnames)
    {
        return 0;
    }
    virtual int32_t GetStaService(const std::string& ifname, sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t RemoveStaService(const std::string& ifname)
    {
        return 0;
    }
    virtual int32_t SetChipMode(uint32_t modeId)
    {
        return 0;
    }
    virtual int32_t CreateExtService(const std::string& ifName, sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t GetExtService(const std::string& ifName, sptr<IChipIface>& iface)
    {
        return 0;
    }
    virtual int32_t RemoveExtService(const std::string& ifName)
    {
        return 0;
    }
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif
