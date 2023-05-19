/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "wifi_common_def.h"
#include "wifi_hal_adapter.h"
#include "wifi_hal_module_manage.h"
#ifdef HDI_INTERFACE_SUPPORT
#include "wifi_hdi_proxy.h"
#endif
#include "wifi_log.h"
#include "wifi_supplicant_hal.h"
#include "wifi_wpa_hal.h"

#undef LOG_TAG
#define LOG_TAG "WifiHalStaInterface"

#ifdef NON_SEPERATE_P2P
#ifdef WPA_CTRL_IFACE_UNIX
#define START_CMD "wpa_supplicant -c"CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf"\
    " -g@abstract:"CONFIG_ROOR_DIR"/sockets/wpa/wlan0"
#else
#define START_CMD "wpa_supplicant -iglan0 -g"CONFIG_ROOR_DIR"/sockets/wpa"\
    " -m"CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf"
#endif // WPA_CTRL_IFACE_UNIX

#else // NON_SEPERATE_P2P
#ifdef WPA_CTRL_IFACE_UNIX
#define START_CMD "wpa_supplicant -c"CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf"\
    " -g@abstract:"CONFIG_ROOR_DIR"/sockets/wpa/wlan0"
#else
#define START_CMD "wpa_supplicant -iglan0 -g"CONFIG_ROOR_DIR"/sockets/wpa"
#endif // WPA_CTRL_IFACE_UNIX
#endif // NON_SEPERATE_P2P

static WifiErrorNo AddWpaIface(int staNo)
{
    WifiWpaInterface *pWpaInterface = GetWifiWapGlobalInterface();
    if (pWpaInterface == NULL) {
        LOGE("Get wpa interface failed!");
        return WIFI_HAL_FAILED;
    }
    if (pWpaInterface->wpaCliConnect(pWpaInterface) < 0) {
        LOGE("Failed to connect to wpa!");
        return WIFI_HAL_FAILED;
    }
    AddInterfaceArgv argv;
    if (staNo == 0) {
        if (strcpy_s(argv.name, sizeof(argv.name), "wlan0") != EOK || strcpy_s(argv.confName, sizeof(argv.confName),
            CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != EOK) {
            return WIFI_HAL_FAILED;
        }
    } else {
        if (strcpy_s(argv.name, sizeof(argv.name), "wlan2") != EOK || strcpy_s(argv.confName, sizeof(argv.confName),
            CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != EOK) {
            return WIFI_HAL_FAILED;
        }
    }
    if (pWpaInterface->wpaCliAddIface(pWpaInterface, &argv, true) < 0) {
        LOGE("Failed to add wpa iface!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

static WifiErrorNo RemoveWpaIface(int staNo)
{
    int ret = -1;
    WifiWpaInterface *pWpaInterface = GetWifiWapGlobalInterface();
    if (pWpaInterface == NULL) {
        LOGE("Get wpa interface failed!");
        return WIFI_HAL_FAILED;
    }
    if (staNo == 0) {
        ret = pWpaInterface->wpaCliRemoveIface(pWpaInterface, "wlan0");
    } else {
        ret = pWpaInterface->wpaCliRemoveIface(pWpaInterface, "wlan2");
    }
    return (ret == 0 ? WIFI_HAL_SUCCESS : WIFI_HAL_FAILED);
}

static WifiErrorNo StopWpaAndWpaHal(int staNo)
{
    if (DisconnectSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("wpa_s hal already stop!");
    }

    if (RemoveWpaIface(staNo) != WIFI_HAL_SUCCESS) {
        LOGE("RemoveWpaIface return fail!");
    }

    if (StopSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("wpa_supplicant stop failed!");
        return WIFI_HAL_FAILED;
    }
    ReleaseWifiStaInterface(staNo);
    LOGI("wpa_supplicant stop successfully");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Start(void)
{
    LOGI("Ready to start wifi");
    if (StartSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("wpa_supplicant start failed!");
        return WIFI_HAL_OPEN_SUPPLICANT_FAILED;
    }
    LOGI("wpa_supplicant start successfully!");

    if (AddWpaIface(0) != WIFI_HAL_SUCCESS) {
        LOGE("Failed to add wpa interface!");
        StopWpaAndWpaHal(0);
        return WIFI_HAL_CONN_SUPPLICANT_FAILED;
    }

    if (ConnectSupplicant() != WIFI_HAL_SUCCESS) {
        LOGE("SupplicantHal connect wpa_supplicant failed!");
        StopWpaAndWpaHal(0);
        return WIFI_HAL_CONN_SUPPLICANT_FAILED;
    }
#ifdef HDI_INTERFACE_SUPPORT
    if (HdiStart() != WIFI_HAL_SUCCESS) {
        LOGE("[STA] Start hdi failed!");
        return WIFI_HAL_FAILED;
    }
#endif
    LOGI("Start wifi successfully");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Stop(void)
{
    LOGI("Ready to Stop wifi");
#ifdef HDI_INTERFACE_SUPPORT
    if (HdiStop() != WIFI_HAL_SUCCESS) {
        LOGE("[Ap] Stop hdi failed!");
        return WIFI_HAL_FAILED;
    }
#endif
    WifiErrorNo err = StopWpaAndWpaHal(0);
    if (err == WIFI_HAL_FAILED) {
        LOGE("Wifi stop failed!");
        return WIFI_HAL_FAILED;
    }
    LOGI("Wifi stop successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ForceStop(void)
{
    LOGI("Ready force Stop wifi");
#ifdef HDI_INTERFACE_SUPPORT
    if (HdiStop() != WIFI_HAL_SUCCESS) {
        LOGE("[Ap] Stop hdi failed!");
        return WIFI_HAL_FAILED;
    }
#endif
    WifiWpaStaInterface *p = TraversalWifiStaInterface();
    while (p != NULL) {
        StopWpaAndWpaHal(p->staNo);
        p = TraversalWifiStaInterface();
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartSupplicant(void)
{
    LOGI("Start supplicant");
    if (CopyConfigFile("wpa_supplicant.conf") != 0) {
        return WIFI_HAL_FAILED;
    }
#ifdef NON_SEPERATE_P2P
    if (CopyConfigFile("p2p_supplicant.conf") != 0) {
        return WIFI_HAL_FAILED;
    }
#endif
    ModuleManageRetCode ret = StartModule(WPA_SUPPLICANT_NAME, START_CMD);
    if (ret != MM_SUCCESS) {
        LOGE("start wpa_supplicant failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopSupplicant(void)
{
    LOGI("Stop supplicant");
    ModuleManageRetCode ret = StopModule(WPA_SUPPLICANT_NAME, false);
    if (ret == MM_FAILED) {
        LOGE("stop wpa_supplicant failed!");
        return WIFI_HAL_FAILED;
    }

    if (ret == MM_SUCCESS) {
        ReleaseWpaGlobalInterface();
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo ConnectSupplicant(void)
{
    LOGD("Ready to connect wpa_supplicant.");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DisconnectSupplicant(void)
{
    LOGD("Ready to disconnect wpa_supplicant.");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    LOGD("Disconnect wpa_supplicant finish!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo RequestToSupplicant(const unsigned char *buf, int32_t bufSize)
{
    if (buf == NULL) {
        LOGE("RequestToSupplicant buf id NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("RequestToSupplicant:buf:%{private}s, buf_size:%{public}d", buf, bufSize);
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartScan(const ScanSettings *settings)
{
    LOGD("Ready to start scan with param.");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdScan(pStaIfc, settings);
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

WifiErrorNo GetScanInfos(ScanInfo *results, int *size)
{
    LOGD("Ready to get scan result.");
    if (results == NULL || size == NULL || *size == 0) {
        return WIFI_HAL_SUCCESS;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdScanInfo(pStaIfc, results, size);
    if (ret < 0) {
        LOGE("GetScanInfos failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    LOGD("Get scan result successfully!");
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetNetworkList(WifiNetworkInfo *infos, int *size)
{
    LOGD("GetNetworkList()");
    if (infos == NULL || size == NULL || *size == 0) {
        return WIFI_HAL_FAILED;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdListNetworks(pStaIfc, infos, size);
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdSelectNetwork(pStaIfc, networkId);
    if (ret < 0) {
        LOGE("WpaCliCmdSelectNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo WpaAutoConnect(int enable)
{
    LOGD("WpaAutoConnect() enable= %{public}d", enable);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdSetAutoConnect(pStaIfc, enable);
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdReconnect(pStaIfc);
    if (ret < 0) {
        LOGE("WpaCliCmdReconnect failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Reassociate(void)
{
    LOGD("Reassociate()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdReassociate(pStaIfc);
    if (ret < 0) {
        LOGE("WpaCliCmdReassociate failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo Disconnect(void)
{
    LOGD("Disconnect()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdDisconnect(pStaIfc);
    if (ret < 0) {
        LOGE("WpaCliCmdDisconnect failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetPowerSave(int enable)
{
    LOGD("SetPowerSave() %{public}d", enable);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdPowerSave(pStaIfc, enable);
    if (ret < 0) {
        LOGE("WpaCliCmdPowerSave failed!");
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetStaCapabilities(int32_t *capabilities)
{
    if (capabilities == NULL) {
        LOGE("input param is NULL");
        return WIFI_HAL_FAILED;
    }
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
        LOGE("GetDeviceMacAddress mac or lenMac is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("GetDeviceMacAddress lenMac %{public}d", *lenMac);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    struct WpaHalCmdStatus status;
    if (memset_s(&status, sizeof(status), 0, sizeof(status)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    int ret = pStaIfc->wpaCliCmdStatus(pStaIfc, &status);
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
    if (frequencies == NULL || size == NULL) {
        LOGE("GetFrequencies frequencies or size is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("GetFrequencies");
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo SetAssocMacAddr(const unsigned char *mac, int lenMac)
{
    if (mac == NULL) {
        LOGE("SetAssocMacAddr() mac is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("SetAssocMacAddr() mac length %{public}d", lenMac);
    return WIFI_HAL_NOT_SUPPORT;
}

WifiErrorNo SetScanningMacAddress(const unsigned char *mac, int lenMac)
{
    if (mac == NULL) {
        LOGE("SetScanningMacAddress() mac is NULL");
        return WIFI_HAL_FAILED;
    }
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
    if (mac == NULL) {
        LOGE("DeauthLastRoamingBssid() mac is NULL");
        return WIFI_HAL_FAILED;
    }
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
    if (feature == NULL) {
        LOGE("GetSupportFeature() feature is NULL");
        return WIFI_HAL_FAILED;
    }
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
    if (ifname == NULL|| buf == NULL) {
        LOGE("RunCmd() ifname or buf is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("ifname: %{public}s, cmdid: %{public}d, buf: %{public}s", ifname, cmdid, buf);
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdRemoveNetwork(pStaIfc, networkId);
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("WpaCliCmdRemoveNetwork remove network failed! ret = %{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo AddNetwork(int *networkId)
{
    if (networkId == NULL) {
        LOGE("AddNetwork() networkId is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("AddNetwork()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdAddNetworks(pStaIfc);
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdEnableNetwork(pStaIfc, networkId);
    if (ret < 0) {
        LOGE("WpaCliCmdEnableNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo DisableNetwork(int networkId)
{
    LOGD("DisableNetwork() networkid [%{public}d]", networkId);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdDisableNetwork(pStaIfc, networkId);
    if (ret < 0) {
        LOGE("WpaCliCmdDisableNetwork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetNetwork(int networkId, const SetNetworkConfig *confs, int size)
{
    if (confs == NULL) {
        LOGE("SetNetwork() confs is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("SetNetwork()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    struct WpaSetNetworkArgv conf;
    for (int i = 0; i < size; ++i) {
        if (memset_s(&conf, sizeof(conf), 0, sizeof(conf)) != EOK) {
            return WIFI_HAL_FAILED;
        }
        conf.id = networkId;
        conf.param = confs[i].cfgParam;
        if (strncpy_s(conf.value, sizeof(conf.value), confs[i].cfgValue, strlen(confs[i].cfgValue)) != EOK) {
            return WIFI_HAL_FAILED;
        }
        int ret = pStaIfc->wpaCliCmdSetNetwork(pStaIfc, &conf);
        if (ret < 0) {
            return WIFI_HAL_FAILED;
        }
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SaveNetworkConfig(void)
{
    LOGD("SaveNetworkConfig()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdSaveConfig(pStaIfc);
    if (ret < 0) {
        LOGE("WpaCliCmdSaveConfig failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StartWpsPbcMode(const WifiWpsParam *param)
{
    LOGD("StartWpsPbcMode()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret;
    if (param == NULL || (param->anyFlag < 0 && param->multiAp <= 0 && strlen(param->bssid) == 0)) {
        ret = pStaIfc->wpaCliCmdWpsPbc(pStaIfc, NULL);
    } else {
        struct WpaWpsPbcArgv config = {0};
        config.anyFlag = param->anyFlag;
        config.multiAp = param->multiAp;
        if (strncpy_s(config.bssid, sizeof(config.bssid), param->bssid, strlen(param->bssid)) != EOK) {
            return WIFI_HAL_FAILED;
        }
        ret = pStaIfc->wpaCliCmdWpsPbc(pStaIfc, &config);
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    if (param == NULL || pinCode == NULL) {
        return WIFI_HAL_FAILED;
    }
    struct WpaWpsPinArgv config = {{0}, {0}};
    if (strncpy_s(config.bssid, sizeof(config.bssid), param->bssid, strlen(param->bssid)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    int ret = pStaIfc->wpaCliCmdWpsPin(pStaIfc, &config, pinCode);
    if (ret < 0) {
        LOGE("StartWpsPinMode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo StopWps(void)
{
    LOGD("StopWps()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdWpsCancel(pStaIfc);
    if (ret < 0) {
        LOGE("StopWps failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetRoamingCapabilities(WifiRoamCapability *capability)
{
    LOGI("GetRoamingCapabilities");
    if (capability == NULL) {
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetRoamConfig(char **blocklist, int blocksize, char **trustlist, int trustsize)
{
    LOGI("SetRoamConfig, blocksize:%{public}d, trustsize:%{public}d", blocksize, trustsize);
    if (trustlist != NULL && trustsize > 0) {
        WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
        if (pStaIfc == NULL) {
            return WIFI_HAL_SUPPLICANT_NOT_INIT;
        }
        for (int i = 0; i < trustsize; i++) {
            int ret = pStaIfc->wpaCliCmdSetRoamConfig(pStaIfc, trustlist[i]);
            if (ret < 0) {
                LOGE("wpaCliCmdSetRoamConfig failed! ret=%{public}d", ret);
                return WIFI_HAL_FAILED;
            }
        }
    }

    if (blocklist == NULL || blocksize <= 0) {
        return WIFI_HAL_SUCCESS;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo WpaSetCountryCode(const char *countryCode)
{
    if (countryCode == NULL) {
        LOGE("WpaSetCountryCode countryCode is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("WpaSetCountryCode ");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdSetCountryCode(pStaIfc, countryCode);
    if (ret < 0) {
        LOGE("WpaSetCountryCode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}
WifiErrorNo WpaGetCountryCode(char *countryCode, int codeSize)
{
    if (countryCode == NULL) {
        LOGE("WpaGetCountryCode countryCode is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("WpaGetCountryCode ");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdGetCountryCode(pStaIfc, countryCode, codeSize);
    if (ret < 0) {
        LOGE("WpaSetCountryCode failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}
WifiErrorNo WpaGetNetWork(GetNetworkConfig *conf)
{
    if (conf == NULL) {
        LOGE("WpaGetNetWork conf is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("WpaGetNetWork()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    struct WpaGetNetworkArgv argv = {0};
    argv.id = conf->networkId;
    if (strncpy_s(argv.param, sizeof(argv.param), conf->param, strlen(conf->param)) != EOK) {
        return WIFI_HAL_FAILED;
    }
    int ret = pStaIfc->wpaCliCmdGetNetwork(pStaIfc, &argv, conf->value, sizeof(conf->value));
    if (ret < 0) {
        LOGE("WpaGetNetWork failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo WpaBlocklistClear(void)
{
    LOGD("WpaBlocklistClear()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdWpaBlockListClear(pStaIfc);
    if (ret < 0) {
        LOGE("WpaBlocklistClear failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo GetConnectSignalInfo(const char *endBssid, WpaSignalInfo *info)
{
    if (endBssid == NULL || info == NULL) {
        LOGE("GetConnectSignalInfo endBssid or info is NULL");
        return WIFI_HAL_FAILED;
    }
    LOGD("GetConnectSignalInfo()");
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdGetSignalInfo(pStaIfc, info);
    if (ret < 0) {
        LOGE("WpaCliCmdGetSignalInfo failed! ret=%{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}

WifiErrorNo SetSuspendMode(bool mode)
{
    LOGI("SetSuspendMode() mode: %{public}d", mode);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(0);
    if (pStaIfc == NULL) {
        LOGE("GetWifiStaInterface return failed");
        return WIFI_HAL_SUPPLICANT_NOT_INIT;
    }
    int ret = pStaIfc->wpaCliCmdWpaSetSuspendMode(pStaIfc, mode);
    if (ret != WIFI_HAL_SUCCESS) {
        LOGE("wpaCliCmdWpaSetSuspendMode return failed! ret = %{public}d", ret);
        return WIFI_HAL_FAILED;
    }
    return WIFI_HAL_SUCCESS;
}
