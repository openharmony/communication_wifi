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
#include "wifi_hal_sta_interface.h"
#include "securec.h"
#include "wifi_hal_adapter.h"
#include "wifi_hal_module_manage.h"
#include "wifi_log.h"
#include "wifi_supplicant_hal.h"

#undef LOG_TAG
#define LOG_TAG "WifHalStaInterface"
#define BUFF_SIZE 1024
#define WPA_CMD_STOP_LENG 64
#define WPA_TRY_CONNECT_SLEEP_TIME (100 * 1000) /* 100ms */

static const char *g_serviceName = "wpa_supplicant";
static const char *g_startCmd = "wpa_supplicant -iwlan0 -c/data/misc/wifi/wpa_supplicant/wpa_supplicant.conf";

static int ExcuteStaCmd(const char *szCmd)
{
    int ret = system(szCmd);
    if (ret == -1) {
        LOGE("system cmd %{public}s failed!", szCmd);
    } else {
        if (WIFEXITED(ret)) {
            if (WEXITSTATUS(ret) == 0) {
                return 0;
            }
            LOGE("system cmd %{public}s failed, return status %{public}d", szCmd, WEXITSTATUS(ret));
        } else {
            LOGE("system cmd %{public}s failed", szCmd);
        }
    }

    return -1;
}

WifiErrorNo Start(void)
{
    LOGD("Ready to start wifi");
    int ret = StartSupplicant();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("wpa_supplicant start failed!");
        return WIFI_HAL_OPEN_SUPPLICANT_FAILED;
    }
    LOGD("wpa_supplicant start successfully!");

    ret = ConnectSupplicant();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("SupplicantHal connect wpa_supplicant failed!");
        StopSupplicant();
        return WIFI_HAL_CONN_SUPPLICANT_FAILED;
    }
    LOGD("SupplicantHal connect wpa_supplicant successfully!");
    LOGD("Start wifi successfully");
    return WIFI_HAL_SUCCESS;
}

static WifiErrorNo StopWpaAndWpaHal(void)
{
    int ret = DisconnectSupplicant();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("wpa_s hal already stop!");
    }

    ret = StopSupplicant();
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("wpa_supplicant stop failed!");
        return WIFI_HAL_FAILED;
    }
    LOGD("wpa_supplicant stop successfully");
    ReleaseWpaHalDev();
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Stop(void)
{
    LOGD("Ready to Stop wifi");
    ModuleManageRetCode ret = StopModule(g_serviceName);
    if (ret == MM_FAILED) {
        LOGE("Stop wpa_supplicant failed!");
        return WIFI_HAL_FAILED;
    }
    if (ret == MM_SUCCESS) {
        WifiErrorNo err = StopWpaAndWpaHal();
        if (err == WIFI_HAL_FAILED) {
            return WIFI_HAL_FAILED;
        }
        LOGD("Wifi stop successfully!");
    }
    LOGD("Stop wifi success");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ForceStop(void)
{
    LOGD("Ready force Stop wifi");
    WifiErrorNo ret = StopWpaAndWpaHal();
    if (ret == WIFI_HAL_FAILED) {
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartSupplicant(void)
{
    const char *wpaConf = "/data/misc/wifi/wpa_supplicant/wpa_supplicant.conf";
    if ((access(wpaConf, F_OK)) != -1) {
        printf("wpa configure file %s is exist.\n", wpaConf);
    } else {
        char szcpCmd[BUFF_SIZE] = {0};
        const char *cpWpaConfCmd = "cp /system/etc/wifi/wpa_supplicant.conf /data/misc/wifi/wpa_supplicant";
        int iRet = snprintf_s(szcpCmd, sizeof(szcpCmd), sizeof(szcpCmd) - 1, "%s", cpWpaConfCmd);
        if (iRet < 0) {
            return -1;
        }

        ExcuteStaCmd(szcpCmd);
    }

    ModuleManageRetCode ret = StartModule(g_serviceName, g_startCmd);
    if (ret == MM_SUCCESS) {
        return WIFI_HAL_SUCCESS;
    }
    LOGE("start wpa_supplicant failed!");
    return WIFI_HAL_FAILED;
}

WifiErrorNo StopSupplicant(void)
{
    ModuleManageRetCode ret = MM_FAILED;
    do {
        ret = StopModule(g_serviceName);
        if (ret == MM_FAILED) {
            LOGE("stop wpa_supplicant failed!");
            return WIFI_HAL_FAILED;
        }
    } while (ret == MM_REDUCE_REFERENCE);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ConnectSupplicant(void)
{
    LOGD("Ready to connect wpa_supplicant.");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int count = 20; /* wait at most 2 seconds for completion */
    while (count-- > 0) {
        int ret = wpaHalDevice->WifiWpaCliConnectWpa();
        if (ret == 0) {
            LOGD("ConnectSupplicant successfully!");
            return WIFI_HAL_SUCCESS;
        }
        usleep(WPA_TRY_CONNECT_SLEEP_TIME); /* wait 100ms */
    }
    LOGE("ConnectSupplicant failed!");
    return WIFI_HAL_FAILED;
}

WifiErrorNo DisconnectSupplicant(void)
{
    LOGD("Ready to disconnect wpa_supplicant.");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    wpaHalDevice->WifiWpaCliWpaCtrlClose();
    LOGD("Disconnect wpa_supplicant finish!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo RequestToSupplicant(const unsigned char *buf, int32_t bufSize)
{
    LOGD("RequestToSupplicant:buf:%s, buf_size:%{public}d", buf, bufSize);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartScan(const ScanSettings *settings)
{
    LOGD("Ready to start scan with param.");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdScan(settings);
    if (ret < 0) {
        LOGE("StartScan failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    if (ret == WIFI_HAL_SCAN_BUSY) {
        LOGD("StartScan return scan busy");
        return WIFI_HAL_SCAN_BUSY;
    }
    LOGD("StartScan successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetScanResults(ScanResult *results, int *size)
{
    LOGD("Ready to get scan result.");
    if (results == NULL || size == NULL || *size == 0) {
        return WIFI_HAL_SUCCESS;
    }
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdScanResult(results, size);
    if (ret < 0) {
        LOGE("GetScanResults failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    LOGD("Get scan result successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetNetworkList(NetworkList *networkList, int *size)
{
    LOGD("GetNetworkList()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    if (networkList == NULL || size == NULL || *size == 0) {
        return WIFI_HAL_FAILED;
    }
    int ret = wpaHalDevice->WpaCliCmdListNetworks(networkList, size);
    if (ret < 0) {
        LOGE("WpaCliCmdSelectNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartPnoScan(const PnoScanSettings *settings)
{
    LOGD("Ready to start pnoscan with param.");
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo StopPnoScan(void)
{
    LOGD("Ready to stop pnoscan.");
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo Connect(int networkId)
{
    LOGD("Connect() networkid %{public}d", networkId);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdSelectNetwork(networkId);
    if (ret < 0) {
        LOGE("WpaCliCmdSelectNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo WpaAutoConnect(int enable)
{
    LOGD("WpaAutoConnect() enable= %{public}d", enable);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdSetAutoConnect(enable);
    if (ret < 0) {
        LOGE("WpaCliCmdSetAutoConnect failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    LOGD("WpaAutoConnect set success");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Reconnect(void)
{
    LOGD("Reconnect()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdReconnect();
    if (ret < 0) {
        LOGE("WpaCliCmdReconnect failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Reassociate(void)
{
    LOGD("Reassociate()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdReassociate();
    if (ret < 0) {
        LOGE("WpaCliCmdReassociate failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Disconnect(void)
{
    LOGD("Disconnect()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdDisconnect();
    if (ret < 0) {
        LOGE("WpaCliCmdDisconnect failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetPowerSave(BOOL enable)
{
    LOGD("SetPowerSave() %{public}d", enable);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdPowerSave(enable);
    if (ret < 0) {
        LOGE("WpaCliCmdPowerSave failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetExternalSim(int useExternalSim)
{
    LOGD("SetExternalSim() %{public}d", useExternalSim);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetBluetoothCoexistenceScanMode(int mode)
{
    LOGD("SetBluetoothCoexistenceScanMode() %{public}d", mode);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopFilteringMulticastV4Packets(void)
{
    LOGD("StopFilteringMulticastV4Packets()");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopFilteringMulticastV6Packets(void)
{
    LOGD("StopFilteringMulticastV6Packets()");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo EnableStaAutoReconnect(int enable)
{
    LOGD("EnableStaAutoReconnect() %{public}d", enable);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetConcurrencyPriority(int isStaHigherPriority)
{
    LOGD("SetConcurrencyPriority() %{public}d", isStaHigherPriority);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetSuspendModeEnabled(int enable)
{
    LOGD("SetSuspendModeEnabled() %{public}d", enable);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetStaCapabilities(int32_t *capabilities)
{
    LOGD("GetStaCapabilities: This function is not supported currently.");
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    long feature = 0;
    HalVendorError err = pInterface->func.wifiGetSupportedFeature(&feature);
    if (ConvertErrorCode(err) != WIFI_HAL_SUCCESS) {
        return ConvertErrorCode(err);
    }
    /* convert supported feature to capabilities */
    *capabilities = (int32_t)feature;
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetDeviceMacAddress(unsigned char *mac, int *lenMac)
{
    /* wificond need iface name, temporary use wpa_supplicant get mac address */
    if (mac == NULL || lenMac == NULL) {
        return WIFI_HAL_FAILED;
    }
    LOGD("GetDeviceMacAddress lenMac %{public}d", *lenMac);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    struct WpaHalCmdStatus status;
    if (memset_s(&status, sizeof(status), 0, sizeof(status)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    int ret = wpaHalDevice->WpaCliCmdStatus(&status);
    if (ret < 0) {
        LOGE("WpaCliCmdStatus failed!");
        return WIFI_HAL_FAILED;
    }
    int length = strlen(status.address);
    if (*lenMac <= length) {
        LOGE("Input mac length %{public}d is little than mac address length %{public}d", *lenMac, length);
        return WIFI_HAL_BUFFER_TOO_LITTLE;
    }
    if (strncpy_s((char *)mac, *lenMac, status.address, length) != EOK) {
        return WIFI_HAL_FAILED;
    }
    *lenMac = length;
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetFrequencies(int32_t band, int *frequencies, int32_t *size)
{
    LOGD("GetFrequencies");
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo SetAssocMacAddr(const unsigned char *mac, int lenMac)
{
    LOGD("SetAssocMacAddr() mac length %{public}d", lenMac);
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo SetScanningMacAddress(const unsigned char *mac, int lenMac)
{
    LOGD("SetScanningMacAddress mac length: %{public}d", lenMac);
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiSetScanningMacAddress((const char *)mac, lenMac);
    return ConvertErrorCode(err);
}

WifiErrorNo DeauthLastRoamingBssid(const unsigned char *mac, int lenMac)
{
    LOGD("DeauthLastRoamingBssid() mac length: %{public}d", lenMac);
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiDeauthLastRoamingBssid((const char *)mac, lenMac);
    return ConvertErrorCode(err);
}

WifiErrorNo GetSupportFeature(long *feature)
{
    LOGD("GetFeatureSupport()");
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiGetSupportedFeature(feature);
    return ConvertErrorCode(err);
}

WifiErrorNo RunCmd(const char *ifname, int32_t cmdid, const unsigned char *buf, int32_t bufSize)
{
    LOGD("ifname: %s, cmdid: %{public}d, buf: %s", ifname, cmdid, buf);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetWifiTxPower(int32_t power)
{
    LOGD("SetWifiTxPower() power: %{public}d", power);
    WifiHalVendorInterface *pInterface = GetWifiHalVendorInterface();
    if (pInterface == NULL) {
        return WIFI_HAL_GET_VENDOR_HAL_FAILED;
    }
    HalVendorError err = pInterface->func.wifiSetWifiTxPower(power);
    return ConvertErrorCode(err);
}

WifiErrorNo RemoveNetwork(int networkId)
{
    LOGD("RemoveNetwork() networkid: %{public}d", networkId);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdRemoveNetwork(networkId);
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("WpaCliCmdRemoveNetwork remove network failed! ret = %{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo AddNetwork(int *networkId)
{
    LOGD("AddNetwork()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    if (networkId == NULL) {
        return WIFI_HAL_FAILED;
    }
    int ret = wpaHalDevice->WpaCliCmdAddNetworks();
    if (ret < 0) {
        LOGE("WpaCliCmdAddNetworks failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    *networkId = ret;
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo EnableNetwork(int networkId)
{
    LOGD("EnableNetwork() networkid [%{public}d]", networkId);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdEnableNetwork(networkId);
    if (ret < 0) {
        LOGE("WpaCliCmdEnableNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DisableNetwork(int networkId)
{
    LOGD("DisableNetwork() networkid [%{public}d]", networkId);
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdDisableNetwork(networkId);
    if (ret < 0) {
        LOGE("WpaCliCmdDisableNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetNetwork(int networkId, const NetWorkConfig *confs, int size)
{
    LOGD("SetNetwork()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    struct WpaSetNetworkArgv conf;
    if (memset_s(&conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    for (int i = 0; i < size; ++i) {
        conf.id = networkId;
        conf.param = confs[i].cfgParam;
        if (strncpy_s(conf.value, sizeof(conf.value), confs[i].cfgValue, strlen(confs[i].cfgValue)) != EOK) {
            return WIFI_HAL_FAILED;
        }
        int ret = wpaHalDevice->WpaCliCmdSetNetwork(&conf);
        if (ret < 0) {
            return WIFI_HAL_FAILED;
        }
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SaveNetworkConfig(void)
{
    LOGD("SaveNetworkConfig()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdSaveConfig();
    if (ret < 0) {
        LOGE("WpaCliCmdSaveConfig failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartWpsPbcMode(const WifiWpsParam *param)
{
    LOGD("StartWpsPbcMode()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret;
    if (param == NULL || (param->anyFlag < 0 && param->multiAp <= 0 && strlen(param->bssid) == 0)) {
        ret = wpaHalDevice->WpaCliCmdWpsPbc(NULL);
    } else {
        struct WpaWpsPbcArgv config = {0};
        config.anyflag = param->anyFlag;
        config.multi_ap = param->multiAp;
        if (strncpy_s(config.bssid, sizeof(config.bssid), param->bssid, strlen(param->bssid)) != EOK) {
            return WIFI_HAL_FAILED;
        }
        ret = wpaHalDevice->WpaCliCmdWpsPbc(&config);
    }
    if (ret < 0) {
        LOGE("StartWpsPbcMode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    } else if (ret == WIFI_HAL_PBC_OVERLAP) {
        LOGD("StartWpsPbcMode: failed-PBC-OVERLAP");
        return WIFI_HAL_PBC_OVERLAP;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartWpsPinMode(const WifiWpsParam *param, int *pinCode)
{
    LOGD("StartWpsPinMode()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    if (param == NULL || pinCode == NULL) {
        return WIFI_HAL_FAILED;
    }
    struct WpaWpsPinArgv config = {0};
    if (strncpy_s(config.bssid, sizeof(config.bssid), param->bssid, strlen(param->bssid)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    int ret = wpaHalDevice->WpaCliCmdWpsPin(&config, pinCode);
    if (ret < 0) {
        LOGE("StartWpsPinMode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopWps(void)
{
    LOGD("StopWps()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdWpsCancel();
    if (ret < 0) {
        LOGE("StopWps failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetRoamingCapabilities(WifiRoamCapability *capability)
{
    LOGD("GetRoamingCapabilities");
    if (capability == NULL) {
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetRoamConfig(char **blocklist, int blocksize, char **trustlist, int size)
{
    LOGD("SetRoamConfig block size %{public}d, size %{public}d", blocksize, size);
    if (blocklist == NULL || trustlist == NULL) {
        return WIFI_HAL_SUCCESS;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo WpaSetCountryCode(const char *countryCode)
{
    LOGD("WpaSetCountryCode ");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdSetCountryCode(countryCode);
    if (ret < 0) {
        LOGE("WpaSetCountryCode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}
WifiErrorNo WpaGetCountryCode(char *countryCode, int codeSize)
{
    LOGD("WpaGetCountryCode ");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdGetCountryCode(countryCode, codeSize);
    if (ret < 0) {
        LOGE("WpaSetCountryCode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}
WifiErrorNo WpaGetNetWork(GetNetWorkConfig *conf)
{
    LOGD("WpaGetNetWork()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    struct WpaGetNetworkArgv argv = {0};
    argv.id = conf->networkId;
    if (strncpy_s(argv.parame, sizeof(argv.parame), conf->param, strlen(conf->param)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    int ret = wpaHalDevice->WpaCliCmdGetNetwork(&argv, conf->value, sizeof(conf->value));
    if (ret < 0) {
        LOGE("WpaGetNetWork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}
WifiErrorNo WpaReconfigure(void)
{
    LOGD("WpaReconfigure()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdReconfigure();
    if (ret < 0) {
        LOGE("WpaReconfigure failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo WpaBlocklistClear(void)
{
    LOGD("WpaBlocklistClear()");
    WifiHalDevice *wpaHalDevice = GetWifiHalDev();
    if (wpaHalDevice == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = wpaHalDevice->WpaCliCmdWpaBlockListClear();
    if (ret < 0) {
        LOGE("WpaBlocklistClear failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}