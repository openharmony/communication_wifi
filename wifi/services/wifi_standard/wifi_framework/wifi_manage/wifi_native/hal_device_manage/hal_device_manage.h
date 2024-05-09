/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_HAL_DEVICE_MANAGE_H
#define OHOS_WIFI_HAL_DEVICE_MANAGE_H

#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include <string>
#include <functional>
#include <mutex>
#include <map>
#include <vector>
#include <algorithm>
#include <chrono>
#include <atomic>
#include "singleton.h"
#include "v1_0/ichip_controller.h"

namespace OHOS {
namespace Wifi {
using OHOS::HDI::Wlan::Chip::V1_0::IChipController;
using OHOS::HDI::Wlan::Chip::V1_0::IChipControllerCallback;
using OHOS::HDI::Wlan::Chip::V1_0::IConcreteChip;
using OHOS::HDI::Wlan::Chip::V1_0::IConcreteChipCallback;
using OHOS::HDI::Wlan::Chip::V1_0::IChipIface;
using OHOS::HDI::Wlan::Chip::V1_0::IChipIfaceCallback;
using OHOS::HDI::Wlan::Chip::V1_0::ErrorCode;
using OHOS::HDI::Wlan::Chip::V1_0::IfaceType;
using OHOS::HDI::Wlan::Chip::V1_0::ComboIface;
using OHOS::HDI::Wlan::Chip::V1_0::UsableMode;
using OHOS::HDI::Wlan::Chip::V1_0::ScanParams;
using OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo;
using OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams;
using OHOS::HDI::Wlan::Chip::V1_0::SignalPollResult;
using IfaceDestoryCallback = std::function<void(std::string&, int)>;

constexpr IfaceType IFACE_TYPE_DEFAULT = (IfaceType)255;
const std::vector<IfaceType> IFACE_TYPES_BY_PRIORITY = {IfaceType::AP, IfaceType::STA, IfaceType::P2P};

struct InterfaceCacheEntry {
    sptr<IConcreteChip> chip;
    uint32_t chipId;
    std::string name;
    IfaceType type;
    uint64_t creationTime;
    std::vector<IfaceDestoryCallback> ifaceDestoryCallback;

    InterfaceCacheEntry()
    {
        chip = nullptr;
        chipId = 0;
        name = "";
        type = IFACE_TYPE_DEFAULT;
        creationTime = 0;
        ifaceDestoryCallback.clear();
    }
};

struct WifiIfaceInfo {
    std::string name;
    sptr<IChipIface> iface;

    WifiIfaceInfo()
    {
        Clear();
    }

    void Clear()
    {
        name = "";
        iface = nullptr;
    }
};

struct WifiChipInfo {
    sptr<IConcreteChip> chip;
    uint32_t chipId;
    bool currentModeIdValid;
    uint32_t currentModeId;
    uint32_t chipCapabilities;
    std::vector<UsableMode> availableModes;
    std::map<IfaceType, std::vector<WifiIfaceInfo>> ifaces;

    WifiChipInfo()
    {
        chip = nullptr;
        chipId = 0;
        currentModeIdValid = false;
        currentModeId = 0;
        chipCapabilities = 0;
        availableModes.clear();
        ifaces.clear();
    }

    WifiChipInfo(const WifiChipInfo &other)
    {
        chip = other.chip;
        chipId = other.chipId;
        currentModeIdValid = other.currentModeIdValid;
        currentModeId = other.currentModeId;
        chipCapabilities = other.chipCapabilities;
        availableModes = other.availableModes;
        ifaces = other.ifaces;
    }

    WifiChipInfo& operator=(const WifiChipInfo &other)
    {
        chip = other.chip;
        chipId = other.chipId;
        currentModeIdValid = other.currentModeIdValid;
        currentModeId = other.currentModeId;
        chipCapabilities = other.chipCapabilities;
        availableModes = other.availableModes;
        ifaces = other.ifaces;
        return *this;
    }
};

struct IfaceCreationData {
    WifiChipInfo chipInfo;
    uint32_t chipModeId;
    std::vector<WifiIfaceInfo> interfacesToBeRemovedFirst;

    IfaceCreationData()
    {
        chipModeId = 0;
        interfacesToBeRemovedFirst.clear();
    }

    bool isEmpty()
    {
        return chipInfo.chip == nullptr;
    }
};

class ChipControllerCallback : public IChipControllerCallback {
public:
    ChipControllerCallback() = default;
    virtual ~ChipControllerCallback() = default;

    virtual int32_t OnVendorHalRestart(ErrorCode code) override { return 0; }
};

class ChipIfaceCallback : public IChipIfaceCallback {
public:
    ChipIfaceCallback() = default;
    virtual ~ChipIfaceCallback() = default;

    virtual int32_t OnScanResultsCallback(uint32_t event) override;
};

class HalDeviceManager {
    DECLARE_DELAYED_SINGLETON(HalDeviceManager)

public:
    /**
     * @Description start chip hdi
     *
     * @param
     * @return bool
     */
    bool StartChipHdi();

    /**
     * @Description stop chip hdi
     *
     * @param
     * @return void
     */
    void StopChipHdi();

    /* ************************ Iface Manager Interface ************************** */
    /**
     * @Description create sta iface
     *
     * @param ifaceDestoryCallback: [in] iface destory callback function
     * @param ifaceName: [out] iface name
     * @return bool
     */
    bool CreateStaIface(const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName);

    /**
     * @Description create ap iface
     *
     * @param ifaceDestoryCallback: [in] iface destory callback function
     * @param ifaceName: [out] iface name
     * @return bool
     */
    bool CreateApIface(const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName);

    /**
     * @Description create p2p iface
     *
     * @param ifaceDestoryCallback: [in] iface destory callback function
     * @param ifaceName: [out] iface name
     * @return bool
     */
    bool CreateP2pIface(const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName);

    /**
     * @Description remove sta iface
     *
     * @param ifaceName: [in] iface name
     * @return bool
     */
    bool RemoveStaIface(const std::string &ifaceName);

    /**
     * @Description remove ap iface
     *
     * @param ifaceName: [in] iface name
     * @return bool
     */
    bool RemoveApIface(const std::string &ifaceName);

    /**
     * @Description remove p2p iface
     *
     * @param ifaceName: [in] iface name
     * @return bool
     */
    bool RemoveP2pIface(const std::string &ifaceName);

    /* ************************ Sta Interface ************************** */
    /**
     * @Description start scan.
     *
     * @param ifaceName: [in] iface name
     * @param scanParams: [in] scan params
     * @return bool
     */
    bool Scan(const std::string &ifaceName, const ScanParams &scanParams);

    /**
     * @Description start pno scan.
     *
     * @param ifaceName: [in] iface name
     * @param scanParams: [in] scan params
     * @return bool
     */
    bool StartPnoScan(const std::string &ifaceName, const PnoScanParams &scanParams);

    /**
     * @Description stop pno scan.
     *
     * @param ifaceName: [in] iface name
     * @return bool
     */
    bool StopPnoScan(const std::string &ifaceName);

    /**
     * @Description get scan infos.
     *
     * @param ifaceName: [in] iface name
     * @param scanResultsInfo: [out] scan results info
     * @return bool
     */
    bool GetScanInfos(const std::string &ifaceName, std::vector<ScanResultsInfo> &scanResultsInfo);

    /**
     * @Description Obtain connection signaling information.
     *
     * @param ifaceName: [in] iface name
     * @param signalPollResult: [out] signal poll result
     * @return bool
     */
    bool GetConnectSignalInfo(const std::string &ifaceName, SignalPollResult &signalPollResult);

    /**
     * @Description set power save mode
     *
     * @param ifaceName: [in] iface name
     * @param mode: [in] power save mode
     * @return bool
     */
    bool SetPmMode(const std::string &ifaceName, int mode);

    /**
     * @Description set data packet identification mark rule
     *
     * @param ifaceName: [in] iface name
     * @return bool
     */
    bool SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable);

    /**
     * @Description set sta mac address.
     *
     * @param ifaceName: [in] iface name
     * @param mac: [in] mac address
     * @return bool
     */
    bool SetStaMacAddress(const std::string &ifaceName, const std::string &mac);

    /**
     * @Description set network updown.
     *
     * @param ifaceName: [in] iface name
     * @param upDown: [in] up or down
     * @return bool
     */
    bool SetNetworkUpDown(const std::string &ifaceName, bool upDown);

    /**
     * @Description get chipset category
     *
     * @param ifaceName: [in] iface name
     * @param chipsetCategory: [out] chipset category
     * @return bool
     */
    bool GetChipsetCategory(const std::string &ifaceName, int &chipsetCategory);

    /**
     * @Description get chipset feature capability
     *
     * @param ifaceName: [in] iface name
     * @param chipsetFeatrureCapability: [out] chipset feature capability
     * @return bool
     */
    bool GetChipsetWifiFeatrureCapability(const std::string &ifaceName, int &chipsetFeatrureCapability);

    /* ************************ Ap Interface ************************** */
    /**
     * @Description Obtains the hotspot frequency supported by a specified frequency band.
     *
     * @param ifaceName: [in] iface name
     * @param band: [in] frequency band
     * @param frequencies: [in] frequency
     * @return bool
     */
    bool GetFrequenciesByBand(const std::string &ifaceName, int32_t band, std::vector<int> &frequencies);

    /**
     * @Description set the power mode.
     *
     * @param ifaceName: [in] iface name
     * @param model: [in] power mode
     * @return bool
     */
    bool SetPowerModel(const std::string &ifaceName, int model);

    /**
     * @Description get the power mode.
     *
     * @param ifaceName: [in] iface name
     * @param model: [in] power mode
     * @return bool
     */
    bool GetPowerModel(const std::string &ifaceName, int &model);

    /**
     * @Description Sets the Wi-Fi country code.
     *
     * @param ifaceName: [in] iface name
     * @param code: [in] country code
     * @return bool
     */
    bool SetWifiCountryCode(const std::string &ifaceName, const std::string &code);

    /**
     * @Description set ap mac address.
     *
     * @param ifaceName: [in] iface name
     * @param mac: [in] mac address
     * @return bool
     */
    bool SetApMacAddress(const std::string &ifaceName, const std::string &mac);

private:
    void ResetHalDeviceManagerInfo();
    bool CheckReloadChipHdiService();
    bool CheckChipHdiStarted();
    bool GetIfaceName(sptr<IChipIface> &iface, std::string &ifaceName);
    bool GetIfaceType(sptr<IChipIface> &iface, IfaceType &ifaceType);
    void GetP2pIfaceInfo(WifiChipInfo &wifiChipInfo);
    void GetApIfaceInfo(WifiChipInfo &wifiChipInfo);
    void GetStaIfaceInfo(WifiChipInfo &wifiChipInfo);
    bool GetIfaceInfo(WifiChipInfo &wifiChipInfo);
    bool GetChipInfo(uint32_t chipId, WifiChipInfo &wifiChipInfo);
    bool GetAllChipInfo(std::vector<WifiChipInfo> &wifiChipInfos);
    bool ValidateInterfaceCache(std::vector<WifiChipInfo> &wifiChipInfos);
    void SelectInterfacesToDelete(int excessInterfaces, IfaceType requestedIfaceType, IfaceType existingIfaceType,
        std::vector<WifiIfaceInfo> &existingIface, std::vector<WifiIfaceInfo> &interfacesToBeRemovedFirst);
    bool AllowedToBeDeleteIfaceTypeForRequestedType(IfaceType requestedIfaceType, IfaceType existingIfaceType);
    bool CreateTheNeedChangeChipModeIfaceData(WifiChipInfo &wifiChipInfo, IfaceType createIfaceType,
        UsableMode &chipMode, IfaceCreationData &ifaceCreationData);
    bool CanIfaceComboSupportRequest(WifiChipInfo &wifiChipInfo, UsableMode &chipMode, std::vector<int> &chipIfaceCombo,
        IfaceType createIfaceType, IfaceCreationData &ifaceCreationData);
    void ExpandIfaceCombos(ComboIface &chipIfaceCombo, std::vector<std::vector<int>> &expandedIfaceCombos);
    bool CompareIfaceCreationData(IfaceCreationData &data1, IfaceCreationData &data2);
    bool ExecuteChipReconfiguration(IfaceCreationData &ifaceCreationData, IfaceType createIfaceType,
        sptr<IChipIface> &iface);
    void FindBestIfaceCreationProposal(std::vector<std::vector<int>> &expandedIfaceCombos, WifiChipInfo &chipInfo,
        UsableMode &chipMode, IfaceType createIfaceType, IfaceCreationData &bestIfaceCreationProposal);
    bool CreateIfaceIfPossible(std::vector<WifiChipInfo> &wifiChipInfos, IfaceType createIfaceType,
        const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName, sptr<IChipIface> &iface);
    bool CreateIface(IfaceType createIfaceType, const IfaceDestoryCallback &ifaceDestoryCallback,
        std::string &ifaceName, sptr<IChipIface> &iface);
    void DispatchIfaceDestoryCallback(std::string &removeIfaceName, IfaceType removeIfaceType, bool isCallback,
        IfaceType createIfaceType);
    bool GetChip(const std::string &removeIfaceName, IfaceType removeIfaceType, sptr<IConcreteChip> &chip);
    bool RemoveIface(sptr<IChipIface> &iface, bool isCallback, IfaceType createIfaceType);

    // death recipient
    static void AddChipHdiDeathRecipient();
    static void RemoveChipHdiDeathRecipient();

private:
    std::map<std::pair<std::string, IfaceType>, InterfaceCacheEntry> mInterfaceInfoCache;
    std::map<std::string, sptr<IChipIface>> mIWifiStaIfaces;
    std::map<std::string, sptr<IChipIface>> mIWifiApIfaces;
    std::map<std::string, sptr<IChipIface>> mIWifiP2pIfaces;
    sptr<IChipController> g_IWifi{nullptr};
    sptr<ChipControllerCallback> g_chipControllerCallback{nullptr};
    sptr<ChipIfaceCallback> g_chipIfaceCallback{nullptr};
    static std::atomic_bool g_chipHdiServiceDied;
    static std::mutex mMutex;
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif