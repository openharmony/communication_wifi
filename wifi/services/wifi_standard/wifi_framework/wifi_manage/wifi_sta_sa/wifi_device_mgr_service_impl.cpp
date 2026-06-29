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

#include "wifi_device_mgr_service_impl.h"
#include "wifi_device_service_impl.h"
#include "wifi_logger.h"
#include "wifi_dumper.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#ifndef OHOS_ARCH_LITE
#include <file_ex.h>
#endif

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiDeviceMgrServiceImpl");

namespace OHOS {
namespace Wifi {
const std::string EXTENSION_BACKUP = "backup";
const std::string EXTENSION_RESTORE = "restore";
std::mutex WifiDeviceMgrServiceImpl::g_instanceLock;
std::mutex WifiDeviceMgrServiceImpl::g_initMutex;
sptr<WifiDeviceMgrServiceImpl> WifiDeviceMgrServiceImpl::g_instance;
static std::map<std::string, WifiSvcCmd> g_SvcCmdMap = {
    {"help", WifiSvcCmd::CMD_HELP},
    {"enable", WifiSvcCmd::CMD_ENABLE},
    {"disable", WifiSvcCmd::CMD_DISABLE},
    {"scan", WifiSvcCmd::CMD_SCAN},
    {"connect", WifiSvcCmd::CMD_CONNECT},
    {"list-scan-result", WifiSvcCmd::CMD_LIST_SCAN_RESULT},
};
static int32_t g_instIdWlan0 = 0;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    WifiDeviceMgrServiceImpl::GetInstance().GetRefPtr());

sptr<WifiDeviceMgrServiceImpl> WifiDeviceMgrServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            sptr<WifiDeviceMgrServiceImpl> service = sptr<WifiDeviceMgrServiceImpl>::MakeSptr();
            g_instance = service;
        }
    }
    return g_instance;
}

WifiDeviceMgrServiceImpl::WifiDeviceMgrServiceImpl()
    : SystemAbility(WIFI_DEVICE_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiDeviceMgrServiceImpl::~WifiDeviceMgrServiceImpl()
{}

void WifiDeviceMgrServiceImpl::OnStart()
{
    WIFI_LOGI("Start sta service!");
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }
    if (WifiManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiManager init failed!");
        return;
    }
    if (!Init()) {
        WIFI_LOGE("Failed to init service");
        OnStop();
        return;
    }
    mState = ServiceRunningState::STATE_RUNNING;
    auto &pWifiStaManager = WifiManager::GetInstance().GetWifiStaManager();
    if (pWifiStaManager) {
        pWifiStaManager->StartUnloadStaSaTimer();
    }
}

void WifiDeviceMgrServiceImpl::OnStop()
{
    std::lock_guard<std::mutex> lock(g_initMutex);
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop sta service!");
}

bool WifiDeviceMgrServiceImpl::Init()
{
    std::lock_guard<std::mutex> lock(g_initMutex);
    if (!mPublishFlag) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; i++) {
            sptr<WifiDeviceServiceImpl> wifi = new WifiDeviceServiceImpl(i);
            if (wifi == nullptr) {
                WIFI_LOGE("create sta service id %{public}d failed!", i);
                return false;
            }
            mWifiService[i] = wifi->AsObject();
        }

        bool ret = Publish(WifiDeviceMgrServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish sta service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

sptr<IRemoteObject> WifiDeviceMgrServiceImpl::GetWifiRemote(int instId)
{
    if (instId < 0) {
        WIFI_LOGE("Invalid instId");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_initMutex);
    auto iter = mWifiService.find(instId);
    if (iter != mWifiService.end()) {
        return mWifiService[instId];
    }
    return nullptr;
}

std::map<int, sptr<IRemoteObject>>& WifiDeviceMgrServiceImpl::GetDeviceServiceMgr()
{
    return mWifiService;
}

#ifndef OHOS_ARCH_LITE
int32_t WifiDeviceMgrServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter sta dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.DeviceDump(WifiDeviceServiceImpl::SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi device save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}

int32_t WifiDeviceMgrServiceImpl::OnExtension(const std::string& extension, MessageParcel& data, MessageParcel& reply)
{
    WIFI_LOGI("extension is %{public}s.", extension.c_str());
    if (extension == EXTENSION_BACKUP) {
        return WifiDeviceServiceImpl::OnBackup(data, reply);
    } else if (extension == EXTENSION_RESTORE) {
        return WifiDeviceServiceImpl::OnRestore(data, reply);
    }
    return 0;
}
 
static WifiSvcCmd ParseCmd(const std::u16string& arg)
{
    std::string cmd = Str16ToStr8(arg);
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    WIFI_LOGI("svc command is %{public}s.", cmd.c_str());
    
    auto it = g_SvcCmdMap.find(cmd);
    return (it != g_SvcCmdMap.end()) ? it->second : WifiSvcCmd::CMD_UNKNOWN;
}
 
int32_t WifiDeviceMgrServiceImpl::HandleHelpCmd(int32_t fd, std::string& info)
{
    return 0;
}
 
int32_t WifiDeviceMgrServiceImpl::HandleEnableCmd(int32_t fd, std::string& info)
{
    sptr<IWifiDevice> wifiDevice = nullptr;
    if (mWifiService.find(g_instIdWlan0) != mWifiService.end() && mWifiService[g_instIdWlan0] != nullptr) {
        wifiDevice = iface_cast<IWifiDevice>(mWifiService[g_instIdWlan0]);
    }
    if (!wifiDevice) {
        info = "wifi service in invalid state\n" + info;
        return -1;
    }
    if (wifiDevice->EnableWifi() == WIFI_OPT_SUCCESS) {
        info = "wifi enable success\n";
        return 0;
    } else {
        info = "wifi enable fail\n";
        return -1;
    }
}
 
int32_t WifiDeviceMgrServiceImpl::HandleDisableCmd(int32_t fd, std::string& info)
{
    sptr<IWifiDevice> wifiDevice = nullptr;
    if (mWifiService.find(g_instIdWlan0) != mWifiService.end() && mWifiService[g_instIdWlan0] != nullptr) {
        wifiDevice = iface_cast<IWifiDevice>(mWifiService[g_instIdWlan0]);
    }
    if (!wifiDevice) {
        info = "wifi service in invalid state\n" + info;
        return -1;
    }
    if (wifiDevice->DisableWifi() == WIFI_OPT_SUCCESS) {
        info = "wifi disable success\n";
        return 0;
    } else {
        info = "wifi disable fail\n";
        return -1;
    }
}
 
int32_t WifiDeviceMgrServiceImpl::HandleScanCmd(int32_t fd, std::string& info)
{
    if (!WifiConfigCenter::GetInstance().CheckScanOnlyAvailable(g_instIdWlan0)) {
        info = "scan only is not available, can not start scan.\n";
        return -1;
    }

    IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(g_instIdWlan0);
    if (pScanService == nullptr) {
        info = "TryStartScan, pService is nullptr.\n";
        return -1;
    }
    if (pScanService->Scan(false) == WIFI_OPT_SUCCESS) {
        info = "wifi scan success\n";
        return 0;
    } else {
        info = "wifi scan fail\n";
        return -1;
    }
}
 
WifiDeviceConfig WifiDeviceMgrServiceImpl::SvcMakeConfig(const std::vector<std::u16string>& args)
{
    WifiDeviceConfig config;
    WifiDeviceConfig outConfig;
    int ssidNum = 1;
    int keyMgmtNum = 2;
    int preSharedKeyNum = 3;
    
    config.ssid = Str16ToStr8(args[ssidNum]);
    std::string keyMgmt = Str16ToStr8(args[keyMgmtNum]);
    if (keyMgmt == "wpa3") {
        config.keyMgmt = KEY_MGMT_SAE;
        config.preSharedKey = Str16ToStr8(args[preSharedKeyNum]);
    } else if (keyMgmt == "wpa2") {
        config.keyMgmt = KEY_MGMT_WPA_PSK;
        config.preSharedKey = Str16ToStr8(args[preSharedKeyNum]);
    } else if (keyMgmt == "open") {
        config.keyMgmt = KEY_MGMT_NONE;
    }

    int ret = WifiSettings::GetInstance().GetDeviceConfig(config.ssid, config.keyMgmt, outConfig, g_instIdWlan0);
    if (ret == 0) {
        WIFI_LOGE("find existed config.");
        return outConfig;
    }
    return config;
}

int32_t WifiDeviceMgrServiceImpl::HandleConnectCmd(int32_t fd, std::string& info,
    const std::vector<std::u16string>& args)
{
    sptr<IWifiDevice> wifiDevice = nullptr;
    if (mWifiService.find(g_instIdWlan0) != mWifiService.end() && mWifiService[g_instIdWlan0] != nullptr) {
        wifiDevice = iface_cast<IWifiDevice>(mWifiService[g_instIdWlan0]);
    }
    if (!wifiDevice) {
        info = "wifi service in invalid state\n" + info;
        return -1;
    }
    size_t argsNum = 3;
    if (args.size() < argsNum) {
        return -1;
    }
    WifiDeviceConfig config = SvcMakeConfig(args);
    if (wifiDevice->ConnectToDevice(config) == WIFI_OPT_SUCCESS) {
        info = "wifi connect success\n";
        return 0;
    } else {
        info = "wifi connect fail\n";
        return -1;
    }
}

int32_t WifiDeviceMgrServiceImpl::HandleScanListCmd(int32_t fd, std::string& info)
{
    std::vector<WifiScanInfo> results;
    info = "";
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(results);
    std::sort(results.begin(), results.end(), [](const WifiScanInfo& a, const WifiScanInfo& b) {
        if (a.ssid.empty() && !b.ssid.empty()) {
            return false;
        }
        if (!a.ssid.empty() && b.ssid.empty()) {
            return true;
        }
        return a.ssid < b.ssid;
    });
    for (const auto& scanInfo : results) {
        std::string singleInfo =  "SSID:" + scanInfo.ssid + ";BSSID:" + MacAnonymize(scanInfo.bssid) +
            "; Frequency:" + std::to_string(scanInfo.frequency) + "; Rssi:" +
            std::to_string(scanInfo.rssi) + "; Flags:" + scanInfo.capabilities + "\n";
        if (!info.empty()) {
            info += "\n";
        }
        info += singleInfo;
    }
    return 0;
}

int32_t WifiDeviceMgrServiceImpl::OnSvcCmd(int32_t fd, const std::vector<std::u16string>& args)
{
    int32_t svcResult = -1;
    std::string info = "svc wifi help:\n"
                " svc wifi enable: enable wifi device\n"
                " svc wifi disable: disable wifi device\n"
                " svc wifi scan: start wifi scan\n"
                " svc wifi connect <ssid> <type> <password>: connect to network\n"
                " svc wifi list-scan-result: list scan result\n";
    std::lock_guard<std::mutex> lock(g_initMutex);
    if (args.size() == 0) {
        info = "wrong parameter size\n" + info;
        if (!SaveStringToFd(fd, info)) {
            WIFI_LOGE("WiFi device save string to fd failed.");
        }
        return svcResult;
    }
    WifiSvcCmd cmd = ParseCmd(args[0]);
    switch (cmd) {
        case WifiSvcCmd::CMD_HELP:
            svcResult = HandleHelpCmd(fd, info);
            break;
        case WifiSvcCmd::CMD_ENABLE:
            svcResult = HandleEnableCmd(fd, info);
            break;
        case WifiSvcCmd::CMD_DISABLE:
            svcResult = HandleDisableCmd(fd, info);
            break;
        case WifiSvcCmd::CMD_SCAN:
            svcResult = HandleScanCmd(fd, info);
            break;
        case WifiSvcCmd::CMD_CONNECT:
            svcResult = HandleConnectCmd(fd, info, args);
            break;
        case WifiSvcCmd::CMD_LIST_SCAN_RESULT:
            svcResult = HandleScanListCmd(fd, info);
            break;
        default:
            break;
    }
    if (!SaveStringToFd(fd, info)) {
        WIFI_LOGE("WiFi device save string to fd failed.");
    }
    return svcResult;
}
#endif
}  // namespace Wifi
}  // namespace OHOS