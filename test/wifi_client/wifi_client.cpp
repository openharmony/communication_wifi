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

#include <cstdarg>
#include <cstring>
#include <iostream>
#include <securec.h>
#include <sstream>
#include <vector>

#include "wifi_device.h"
#include "wifi_scan.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

using namespace std;

namespace OHOS {
namespace Wifi {
std::unique_ptr<WifiDevice> ptrWifiDevice = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::unique_ptr<WifiScan> ptrWifiScan = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);

const int MAX_ARGS = 16;
const int BAND_2GHZ = 1;
const int BAND_5GHZ = 2;
const int CMD_IDX = 1;
const int ARG_IDX = 2;
const int MIN_WPA_LENGTH = 8;

struct sta_cli_cmd {
    const char *cmd;
    void (*handler)(int argc, const char* argv[]);
    const char *usage;
};

static void Log(const char *fmt, ...)
{
    va_list list;
    va_start(list, fmt);
    (void)vfprintf(stdout, fmt, list);
    va_end(list);
    fflush(stdout);
}

#define Logd(fmt, ...) Log(fmt"\n", ##__VA_ARGS__)

static void PrintLinkedInfo(const WifiLinkedInfo &linkedInfo)
{
    std::stringstream ss;
    ss << "Linked info details:" << endl;
    ss << "  ssid:" << linkedInfo.ssid << endl;
    ss << "  bssid:" << linkedInfo.bssid << endl;
    ss << "  rssi:" << linkedInfo.rssi << endl;
    ss << "  band:" << linkedInfo.band << endl;
    ss << "  frequency:" << linkedInfo.frequency << endl;
    ss << "  linkSpeed:" << linkedInfo.linkSpeed << endl;
    ss << "  macAddress:" << linkedInfo.macAddress << endl;
    ss << "  ipAddress:" << linkedInfo.ipAddress << endl;
    ss << "  connState:" << static_cast<int>(linkedInfo.connState) << endl;
    ss << "  ifHiddenSSID:" << linkedInfo.ifHiddenSSID << endl;
    Logd("%s", ss.str().c_str());
}

static void PrintIpInfo(IpInfo &ipInfo)
{
    std::stringstream ss;
    ss << "IP information:" << endl;
    ss << " ipAddress:" << ipInfo.ipAddress << endl;
    ss << " gateway:" << ipInfo.gateway << endl;
    ss << " netmask:" << ipInfo.netmask << endl;
    ss << " primaryDns:" << ipInfo.primaryDns << endl;
    ss << " secondDns:" << ipInfo.secondDns << endl;
    Logd("%s", ss.str().c_str());
}

static void PrintfDeviceConfigs(vector<WifiDeviceConfig> &configs)
{
    int idx = 0;
    std::stringstream ss;
    for (WifiDeviceConfig &config : configs) {
        ss << "No. " << idx << "  network id:" << config.networkId << endl;
        ss << " ssid:" << config.ssid << endl;
        ss << " bssid:" << config.bssid << endl;
        ss << " keyMgmt:" << config.keyMgmt << endl;
        ss << " status:" << config.status << endl;
        idx++;
    }
    Logd("%s", ss.str().c_str());
}

static void PrintfScanResults(vector<WifiScanInfo> &scanInfos)
{
    Logd("%s total size:%u", __func__, scanInfos.size());
    int idx = 0;
    std::stringstream ss;
    for (WifiScanInfo &scanInfo : scanInfos) {
        ss << "No. " << idx << "  ssid:" << scanInfo.ssid << endl;
        ss << " bssid:" << scanInfo.bssid << endl;
        ss << " frequency:" << scanInfo.frequency << endl;
        ss << " rssi:" << scanInfo.rssi << endl;
        ss << " securityType:" << static_cast<int>(scanInfo.securityType) << endl;
        idx++;
    }
    Logd("%s", ss.str().c_str());
}

class WifiDeviceEventCallback : public IWifiDeviceCallBack {
public:
    WifiDeviceEventCallback()
    {
    }

    virtual ~WifiDeviceEventCallback()
    {
    }

    void OnWifiStateChanged(int state) override
    {
        Logd("receive %s event, state:%d", __func__, state);
    }

    void OnWifiConnectionChanged(int state, const WifiLinkedInfo &info) override
    {
        Logd("receive %s event, state:%d", __func__, state);
        PrintLinkedInfo(info);
    }

    void OnWifiRssiChanged(int rssi) override
    {
        Logd("receive %s event, rssi:%d", __func__, rssi);
    }

    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override
    {
        Logd("receive %s event, state:%d, pinCode:%s", __func__, state, pinCode.c_str());
    }

    void OnStreamChanged(int direction) override
    {
        Logd("receive %s event, direction:%d", __func__, direction);
    }

#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
#endif
};

class WifiScanEventCallback : public IWifiScanCallback {
public:
    WifiScanEventCallback()
    {
    }

    virtual ~WifiScanEventCallback()
    {
    }

    void OnWifiScanStateChanged(int state) override
    {
        Logd("receive %s event, state:%d", __func__, state);
    }

#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
#endif
};

#ifdef OHOS_ARCH_LITE
static std::shared_ptr<WifiDeviceEventCallback> deviceCallback = std::make_shared<WifiDeviceEventCallback>();
static std::shared_ptr<WifiScanEventCallback> scanCallback = std::make_shared<WifiScanEventCallback>();
#else
static sptr<WifiDeviceEventCallback> deviceCallback =
    sptr<WifiDeviceEventCallback>(new (std::nothrow)WifiDeviceEventCallback());
static sptr<WifiScanEventCallback> scanCallback =
    sptr<WifiScanEventCallback>(new (std::nothrow)WifiScanEventCallback());
#endif

static void RegisterDeviceEvents(void)
{
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->RegisterCallBack(deviceCallback);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void RegisterScanEvents(void)
{
    if (ptrWifiScan != nullptr) {
        ErrCode ret = ptrWifiScan->RegisterCallBack(scanCallback);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HelpCommand(const char *command);
static bool GetNetworkId(int argc, const char *argv[], int &nid)
{
    nid = -1;
    for (int i = ARG_IDX; i < argc; i++) {
        if (strncmp(argv[i], "nid=", strlen("nid=")) == 0) {
            (void)sscanf_s(argv[i], "nid=%d", &nid);
        }
    }
    if (nid < 0) {
        HelpCommand(argv[CMD_IDX]);
        return false;
    }
    return true;
}

static bool GetDeviceConfig(int argc, const char *argv[], WifiDeviceConfig &config)
{
    string keyMgmt = "";
    config.ssid = "";
    config.preSharedKey = "";

    for (int i = ARG_IDX; i < argc; i++) {
        if (strncmp(argv[i], "ssid=", strlen("ssid=")) == 0) {
            config.ssid = argv[i] + strlen("ssid=");
        } else if (strncmp(argv[i], "pwd=", strlen("pwd=")) == 0) {
            config.preSharedKey = argv[i] + strlen("pwd=");
        } else if (strncmp(argv[i], "key_mgmt=", strlen("key_mgmt=")) == 0) {
            keyMgmt = argv[i] + strlen("key_mgmt=");
        }
    }
    if (config.ssid == "" || keyMgmt == "") {
        HelpCommand(argv[CMD_IDX]);
        return false;
    }
    if (keyMgmt != "open" && keyMgmt != "wpa" && keyMgmt != "wpa2") {
        Logd("key_mgmt should be one of {open, wpa, wpa2}");
        return false;
    }
    if (keyMgmt != "open" && config.preSharedKey.length() < MIN_WPA_LENGTH) {
        Logd("password length should be >= %d", MIN_WPA_LENGTH);
        return false;
    }
    if (keyMgmt == "open") {
        config.keyMgmt = "NONE";
    } else {
        config.keyMgmt = "WPA-PSK";
    }
    return true;
}

static void HandleEnable(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->EnableWifi();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleDisable(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->DisableWifi();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleScan(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiScan != nullptr) {
        ErrCode ret = ptrWifiScan->Scan();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleDisconnect(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->Disconnect();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleGetStatus(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice == nullptr) {
        return;
    }

    bool active;
    ErrCode ret = ptrWifiDevice->IsWifiActive(active);
    if (ret != WIFI_OPT_SUCCESS) {
        Logd("IsWifiActive failed");
        return;
    }
    if (!active) {
        Logd("wifi is disabled");
        return;
    }
    Logd("wifi is enabled");
#ifndef OHOS_ARCH_LITE
    bool connected = ptrWifiDevice->IsConnected();
    if (!connected) {
        Logd("wifi is disconnected");
        return;
    }
    Logd("wifi is connected");
#endif
    WifiLinkedInfo linkedInfo;
    ret = ptrWifiDevice->GetLinkedInfo(linkedInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        Logd("GetLinkedInfo failed");
        return;
    }
    PrintLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        return;
    }

#ifdef OHOS_VERSION_31
    IpInfo ipInfo;
    ret = ptrWifiDevice->GetIpInfo(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        Logd("GetIpInfo failed");
        return;
    }
    PrintIpInfo(ipInfo);
#endif
}

static void HandleGetConfigList(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        vector<WifiDeviceConfig> configs;
        ErrCode ret = ptrWifiDevice->GetDeviceConfigs(configs);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
            PrintfDeviceConfigs(configs);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleGetScanResults(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiScan != nullptr) {
        vector<WifiScanInfo> result;
        ErrCode ret = ptrWifiScan->GetScanInfoList(result);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
            PrintfScanResults(result);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleUpdateConfig(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    int nid;
    WifiDeviceConfig config;
    if (!GetDeviceConfig(argc, argv, config) || !GetNetworkId(argc, argv, nid)) {
        return;
    }
    if (ptrWifiDevice != nullptr) {
#ifdef OHOS_VERSION_31
        int updatedId;
        ErrCode ret = ptrWifiDevice->UpdateDeviceConfig(config, updatedId);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, nid=%d", __func__, updatedId);
        } else {
            Logd("%s failed", __func__);
        }
#else
        Logd("%s unsupported in current version", __func__);
#endif
    }
}

static void HandleAddConfig(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    WifiDeviceConfig config;
    if (!GetDeviceConfig(argc, argv, config)) {
        return;
    }
    if (ptrWifiDevice != nullptr) {
        int nid;
        ErrCode ret = ptrWifiDevice->AddDeviceConfig(config, nid);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, nid=%d", __func__, nid);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleRemoveConfigs(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->RemoveAllDevice();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleRemoveConfig(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    int nid;
    if (!GetNetworkId(argc, argv, nid)) {
        return;
    }
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->RemoveDevice(nid);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, nid=%d", __func__, nid);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleConnectNetwork(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    int nid;
    if (!GetNetworkId(argc, argv, nid)) {
        return;
    }
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->ConnectToNetwork(nid);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, nid=%d", __func__, nid);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleConnectDevice(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    WifiDeviceConfig config;
    if (!GetDeviceConfig(argc, argv, config)) {
        return;
    }
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->ConnectToDevice(config);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleGetWifiState(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        int state;
        ErrCode ret = ptrWifiDevice->GetWifiState(state);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, wifi state:%d", __func__, state);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleGetCountry(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        string countryCode;
        ErrCode ret = ptrWifiDevice->GetCountryCode(countryCode);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, countryCode: %s", __func__, countryCode.c_str());
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleSetCountry(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    string code = "";
    for (int i = ARG_IDX; i < argc; i++) {
        if (strncmp(argv[i], "code=", strlen("code=")) == 0) {
            code = argv[i] + strlen("code=");
        }
    }
    if (code == "") {
        HelpCommand(argv[CMD_IDX]);
        return;
    }
    if (ptrWifiDevice != nullptr) {
        ErrCode ret = ptrWifiDevice->SetCountryCode(code);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, code=%s", __func__, code.c_str());
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleGetSignalLevel(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    int rssi = 0;
    string band = "";
    for (int i = ARG_IDX; i < argc; i++) {
        if (strncmp(argv[i], "rssi=", strlen("rssi=")) == 0) {
            (void)sscanf_s(argv[i], "rssi=%d", &rssi);
        } else if (strncmp(argv[i], "band=", strlen("band=")) == 0) {
            band = argv[i] + strlen("band=");
        }
    }
    if (rssi >= 0 || (band != "2g" && band != "5g")) {
        HelpCommand(argv[CMD_IDX]);
        return;
    }
    if (ptrWifiDevice != nullptr) {
        int level;
        int bandType = (band == "2g" ? BAND_2GHZ : BAND_5GHZ);
        ErrCode ret = ptrWifiDevice->GetSignalLevel(rssi, bandType, level);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, level=%d", __func__, level);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleGetSupportedFeatures(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        long features = 0L;
        ErrCode ret = ptrWifiDevice->GetSupportedFeatures(features);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, features=0x%lx", __func__, features);
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void HandleIsFeatureSupported(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    long feature = 0L;
    for (int i = ARG_IDX; i < argc; i++) {
        if (strncmp(argv[i], "feature=0x", strlen("feature=0x")) == 0) {
            (void)sscanf_s(argv[i], "feature=0x%lx", &feature);
        }
    }
    if (feature == 0) {
        HelpCommand(argv[CMD_IDX]);
        return;
    }
    if (ptrWifiDevice != nullptr) {
        bool supported = ptrWifiDevice->IsFeatureSupported(feature);
        Logd("%s feature:0x%lx, supported:%d", __func__, feature, supported);
    }
}

static void HandleEnableConfig(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    int nid = -1;
    string disableOthers = "";
    for (int i = ARG_IDX; i < argc; i++) {
        if (strncmp(argv[i], "nid=", strlen("nid=")) == 0) {
            (void)sscanf_s(argv[i], "nid=%d", &nid);
        } else if (strncmp(argv[i], "disableothers=", strlen("disableothers=")) == 0) {
            disableOthers = argv[i] + strlen("disableothers=");
        }
    }
    if (nid < 0 || (disableOthers != "true" && disableOthers != "false")) {
        HelpCommand(argv[CMD_IDX]);
        return;
    }
    if (ptrWifiDevice != nullptr) {
#ifdef OHOS_VERSION_31
        ErrCode ret = ptrWifiDevice->EnableDeviceConfig(nid, disableOthers == "true");
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, nid=%d", __func__, nid);
        } else {
            Logd("%s failed", __func__);
        }
#else
        Logd("%s unsupported in current version", __func__);
#endif
    }
}

static void HandleDisableConfig(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    int nid;
    if (!GetNetworkId(argc, argv, nid)) {
        return;
    }
    if (ptrWifiDevice != nullptr) {
#ifdef OHOS_VERSION_31
        ErrCode ret = ptrWifiDevice->DisableDeviceConfig(nid);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, nid=%d", __func__, nid);
        } else {
            Logd("%s failed", __func__);
        }
#else
        Logd("%s unsupported in current version", __func__);
#endif
    }
}

static void HandleReconnect(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
#ifdef OHOS_VERSION_31
        ErrCode ret = ptrWifiDevice->ReConnect();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
#else
        Logd("%s unsupported in current version", __func__);
#endif
    }
}

static void HandleReassociate(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
#ifdef OHOS_VERSION_31
        ErrCode ret = ptrWifiDevice->ReAssociate();
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success", __func__);
        } else {
            Logd("%s failed", __func__);
        }
#else
        Logd("%s unsupported in current version", __func__);
#endif
    }
}

static void HandleGetDeviceMac(int argc, const char* argv[])
{
    Logd("enter command handler:%s", argv[CMD_IDX]);
    if (ptrWifiDevice != nullptr) {
        string mac;
        ErrCode ret = ptrWifiDevice->GetDeviceMacAddress(mac);
        if (ret == WIFI_OPT_SUCCESS) {
            Logd("%s success, mac is %s:", __func__, mac.c_str());
        } else {
            Logd("%s failed", __func__);
        }
    }
}

static void ParseUserInput(std::string command);
static void HandleInteractive(int argc, const char* argv[])
{
    string inputLine;
    Logd("enter interactive mode! input quit to exit this mode");
    Logd("please input command:");
    RegisterDeviceEvents();
    RegisterScanEvents();

    do {
        getline(cin, inputLine);
        if (inputLine == "quit") {
            break;
        } else {
            ParseUserInput(inputLine);
            Logd("please input command:");
        }
    } while (true);
}

static const struct sta_cli_cmd g_sta_cli_cmds[] = {
    {"enable", HandleEnable, "enable"},
    {"disable", HandleDisable, "disable"},
    {"scan", HandleScan, "scan"},
    {"disconnect", HandleDisconnect, "disconnect nid=%d"},
    {"get_status", HandleGetStatus, "get_status"},
    {"get_config_list", HandleGetConfigList, "get_config_list"},
    {"get_scan_results", HandleGetScanResults, "get_scan_results"},
    {"update_config", HandleUpdateConfig, "update_config nid=%d ssid=%s pwd=%s key_mgmt=open/wpa/wpa2"},
    {"add_config", HandleAddConfig, "add_config ssid=%s pwd=%s key_mgmt=open/wpa/wpa2"},
    {"remove_configs", HandleRemoveConfigs, "remove_configs"},
    {"remove_config", HandleRemoveConfig, "remove_config nid=%d"},
    {"connect_network", HandleConnectNetwork, "connect_network nid=%d"},
    {"connect_device", HandleConnectDevice, "connect_device ssid=%s pwd=%s key_mgmt=open/wpa/wpa2"},
    {"get_wifi_state", HandleGetWifiState, "get_wifi_state"},
    {"set_country", HandleSetCountry, "set_country code=%s"},
    {"get_country", HandleGetCountry, "get_country"},
    {"get_signal_level", HandleGetSignalLevel, "get_signal_level rssi=%d band=2g/5g"},
    {"get_supported_features", HandleGetSupportedFeatures, "get_supported_features"},
    {"is_feature_supported", HandleIsFeatureSupported, "is_feature_supported feature=0x%x"},
    {"enable_config", HandleEnableConfig, "enable_config nid=%d disableothers=true/false"},
    {"disable_config", HandleDisableConfig, "disable_config nid=%d"},
    {"reconnect", HandleReconnect, "reconnect"},
    {"reassociate", HandleReassociate, "reassociate"},
    {"get_device_mac", HandleGetDeviceMac, "get_device_mac"},
    {"interactive", HandleInteractive, "interactive"}
};

static void HelpCommand(const char *command)
{
    int count = ARRAY_SIZE(g_sta_cli_cmds);
    for (int i = 0; i < count; i++) {
        if (strcmp(command, g_sta_cli_cmds[i].cmd) == 0) {
            Logd("%s", g_sta_cli_cmds[i].usage);
            return;
        }
    }
    Logd("can not find command %s", command);
}

static void Help(void)
{
    Logd("%s", "support command as follows:");
    int count = ARRAY_SIZE(g_sta_cli_cmds);
    for (int i = 0; i < count; i++) {
        Logd("%s", g_sta_cli_cmds[i].usage);
    }
}

static void HandleUserCommand(int argc, const char *argv[])
{
    if (argc < ARG_IDX) {
        Help();
        return;
    }

    int count = ARRAY_SIZE(g_sta_cli_cmds);
    for (int i = 0; i < count; i++) {
        if (strcmp(g_sta_cli_cmds[i].cmd, argv[CMD_IDX]) == 0) {
            if (g_sta_cli_cmds[i].handler != nullptr) {
                g_sta_cli_cmds[i].handler(argc, argv);
            } else {
                Logd("no handler for command:%s", g_sta_cli_cmds[i].cmd);
            }
            return;
        }
    }
    Help();
}

static void ParseUserInput(std::string command)
{
    int argc = 0;
    const char* argv[MAX_ARGS] = { nullptr };
    vector<string> cmdArgs;

    std::istringstream istr(command);
    for (std::string s; istr >> s;) {
        cmdArgs.push_back(s);
    }

    argc = cmdArgs.size() + CMD_IDX;
    if (argc > MAX_ARGS) {
        argc = MAX_ARGS;
    }
    for (int i = CMD_IDX; i < argc; i++) {
        argv[i] = cmdArgs[i - CMD_IDX].c_str();
    }
    HandleUserCommand(argc, argv);
    cmdArgs.clear();
}
}
}

int main(int argc, char *argv[])
{
    OHOS::Wifi::HandleUserCommand(argc, const_cast<const char **>(argv));
    return 0;
}
