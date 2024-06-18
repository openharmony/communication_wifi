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

#include "wifi_scan_stub.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_scan_callback_proxy.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_scan_death_recipient.h"
#include "wifi_common_def.h"
#include "wifi_config_center.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanStub");

namespace OHOS {
namespace Wifi {
WifiScanStub::WifiScanStub() : mSingleCallback(false)
{
    InitHandleMap();
}

WifiScanStub::WifiScanStub(int instId) : mSingleCallback(false), m_instId(instId)
{
    InitHandleMap();
}

WifiScanStub::~WifiScanStub()
{}

void WifiScanStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO)] =
        &WifiScanStub::OnSetScanControlInfo;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN)] = &WifiScanStub::OnScan;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN)] =
        &WifiScanStub::OnScanByParams;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE)] =
        &WifiScanStub::OnIsWifiClosedScan;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_SCAN_INFO_LIST)] =
        &WifiScanStub::OnGetScanInfoList;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK)] =
        &WifiScanStub::OnRegisterCallBack;
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES)] =
        &WifiScanStub::OnGetSupportedFeatures;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_WIFI_SCAN_ONLY)] =
        &WifiScanStub::OnSetScanOnlyAvailable;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_WIFI_SCAN_ONLY)] =
        &WifiScanStub::OnGetScanOnlyAvailable;
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_START_PNO_SCAN)] =
        &WifiScanStub::OnStartWifiPnoScan;
}

int WifiScanStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("WifiScanStub::OnRemoteRequest,code:%{public}u", code);

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Scan stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        WIFI_LOGI("not find function to deal, code %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        int exception = data.ReadInt32();
        if (exception) {
            return WIFI_OPT_FAILED;
        }
        (this->*(iter->second))(code, data, reply, option);
    }
    return 0;
}

int WifiScanStub::OnSetScanControlInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run OnSetScanControlInfo code %{public}u, datasize %{public}zu", code, data.GetRawDataSize());
    constexpr int MAX_SIZE = 1024;
    ScanControlInfo info;
    int forbidListSize = data.ReadInt32();
    if (forbidListSize > MAX_SIZE) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < forbidListSize; i++) {
        ScanForbidMode scanForbidMode;
        scanForbidMode.scanScene = data.ReadInt32();
        scanForbidMode.scanMode = static_cast<ScanMode>(data.ReadInt32());
        scanForbidMode.forbidTime = data.ReadInt32();
        scanForbidMode.forbidCount = data.ReadInt32();
        info.scanForbidList.push_back(scanForbidMode);
    }

    int intervalSize = data.ReadInt32();
    if (intervalSize > MAX_SIZE) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < intervalSize; i++) {
        ScanIntervalMode scanIntervalMode;
        scanIntervalMode.scanScene = data.ReadInt32();
        scanIntervalMode.scanMode = static_cast<ScanMode>(data.ReadInt32());
        scanIntervalMode.isSingle = data.ReadBool();
        scanIntervalMode.intervalMode = static_cast<IntervalMode>(data.ReadInt32());
        scanIntervalMode.interval = data.ReadInt32();
        scanIntervalMode.count = data.ReadInt32();
        info.scanIntervalList.push_back(scanIntervalMode);
    }

    ErrCode ret = SetScanControlInfo(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return ret;
}

int WifiScanStub::OnScan(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    bool compatible = data.ReadBool();
    std::string name = data.ReadString();
    WIFI_LOGD("run OnScan code %{public}u, datasize %{public}zu, compatible:%{public}d",
        code, data.GetRawDataSize(), compatible);
    WifiSettings::GetInstance().SetAppPackageName(name);
    ErrCode ret = Scan(compatible);
    WifiSettings::GetInstance().SetAppPackageName("");
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return ret;
}

int WifiScanStub::OnScanByParams(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run OnScanByParams code %{public}u, datasize %{public}zu", code, data.GetRawDataSize());
    const char *readStr = nullptr;
    constexpr int MAX_FREQS_SIZE = 512;
    WifiScanParams params;
    readStr = data.ReadCString();
    params.ssid = (readStr != nullptr) ? readStr : "";
    readStr = data.ReadCString();
    params.bssid = (readStr != nullptr) ? readStr : "";
    int size = data.ReadInt32();
    if (size > MAX_FREQS_SIZE) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return WIFI_OPT_INVALID_PARAM;
    }
    for (int i = 0; i < size; i++) {
        int tmp = data.ReadInt32();
        params.freqs.push_back(tmp);
    }
    params.band = static_cast<uint32_t>(data.ReadInt32());
    std::string name = data.ReadString();

    WifiSettings::GetInstance().SetAppPackageName(name);
    ErrCode ret = AdvanceScan(params);
    WifiSettings::GetInstance().SetAppPackageName("");
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return ret;
}

int WifiScanStub::OnIsWifiClosedScan(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run OnIsWifiClosedScan code %{public}u, datasize %{public}zu", code, data.GetRawDataSize());
    bool bOpen = false;
    ErrCode ret = IsWifiClosedScan(bOpen);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(bOpen);
    }
    return ret;
}

constexpr int ASH_MEM_SIZE = 1024 * 200;
void WifiScanStub::SendScanInfo(int32_t contentSize, std::vector<WifiScanInfo> &result, MessageParcel &reply)
{
    WIFI_LOGI("WifiScanStub SendScanInfo");
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem("scaninfo", ASH_MEM_SIZE);
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        reply.WriteInt32(WIFI_OPT_FAILED);
        if (ashmem != nullptr) {
            ashmem->UnmapAshmem();
            ashmem->CloseAshmem();
        }
        return;
    }
    std::vector<uint32_t> scanInfoSize;
    int offset = 0;
    for (int i = 0; i < contentSize; ++i) {
        std::stringstream scanInfoStream;
        scanInfoStream << result[i].bssid << ";";
        scanInfoStream << result[i].ssid << ";";
        scanInfoStream << result[i].bssidType << ";";
        scanInfoStream << result[i].capabilities << ";";
        scanInfoStream << result[i].frequency << ";";
        scanInfoStream << result[i].band << ";";
        scanInfoStream << static_cast<int>(result[i].channelWidth) << ";";
        scanInfoStream << result[i].centerFrequency0 << ";";
        scanInfoStream << result[i].centerFrequency1 << ";";
        scanInfoStream << result[i].rssi << ";";
        scanInfoStream << static_cast<int>(result[i].securityType) << ";";
        scanInfoStream << result[i].infoElems.size() << ";";
        for (const auto& elem : result[i].infoElems) {
            scanInfoStream << elem.id << ";";
            scanInfoStream << elem.content.size() << ";";
            for (const auto& byte : elem.content) {
                scanInfoStream << static_cast<int>(byte) << ";";
            }
        }
        scanInfoStream << result[i].features << ";";
        scanInfoStream << result[i].timestamp << ";";
        scanInfoStream << result[i].wifiStandard << ";";
        scanInfoStream << result[i].maxSupportedRxLinkSpeed << ";";
        scanInfoStream << result[i].maxSupportedTxLinkSpeed << ";";
        scanInfoStream << result[i].disappearCount << ";";
        scanInfoStream << result[i].isHiLinkNetwork << ";";
        scanInfoStream << static_cast<int>(result[i].supportedWifiCategory) << ";";
        scanInfoSize.push_back(scanInfoStream.str().length());
        ashmem->WriteToAshmem(scanInfoStream.str().c_str(), scanInfoStream.str().length(), offset);
        offset += scanInfoSize[i];
    }
    reply.WriteInt32(WIFI_OPT_SUCCESS);
    reply.WriteInt32(contentSize);
    reply.WriteUInt32Vector(scanInfoSize);
    reply.WriteAshmem(ashmem);
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
}

void WifiScanStub::SendScanInfoSmall(int32_t contentSize, std::vector<WifiScanInfo> &result, MessageParcel &reply)
{
    reply.WriteInt32(WIFI_OPT_SUCCESS);
    reply.WriteInt32(contentSize);
    for (unsigned int i = 0; i < contentSize; i++) {
        reply.WriteString(result[i].bssid);
        reply.WriteString(result[i].ssid);
        reply.WriteInt32(result[i].bssidType);
        reply.WriteString(result[i].capabilities);
        reply.WriteInt32(result[i].frequency);
        reply.WriteInt32(result[i].band);
        reply.WriteInt32(static_cast<int>(result[i].channelWidth));
        reply.WriteInt32(result[i].centerFrequency0);
        reply.WriteInt32(result[i].centerFrequency1);
        reply.WriteInt32(result[i].rssi);
        reply.WriteInt32(static_cast<int>(result[i].securityType));
        reply.WriteUint32(result[i].infoElems.size());
        for (const auto& elem : result[i].infoElems) {
            reply.WriteInt32(elem.id);
            reply.WriteUint32(elem.content.size());
            for (const auto& byte : elem.content) {
                reply.WriteInt32(static_cast<int>(byte));
            }
        }
        reply.WriteInt64(result[i].features);
        reply.WriteInt64(result[i].timestamp);
        reply.WriteInt32(result[i].wifiStandard);
        reply.WriteInt32(result[i].maxSupportedRxLinkSpeed);
        reply.WriteInt32(result[i].maxSupportedTxLinkSpeed);
        reply.WriteInt32(result[i].disappearCount);
        reply.WriteBool(result[i].isHiLinkNetwork);
        reply.WriteInt32(static_cast<int>(result[i].supportedWifiCategory));
    }
}

int WifiScanStub::OnGetScanInfoList(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    bool compatible = data.ReadBool();
    WIFI_LOGD("run OnGetScanInfoList code %{public}u, datasize %{public}zu, compatible:%{public}d",
        code, data.GetRawDataSize(), compatible);
    std::vector<WifiScanInfo> result;
    ErrCode ret = GetScanInfoList(result, compatible);
    reply.WriteInt32(0);
    if (ret != WIFI_OPT_SUCCESS) {
        reply.WriteInt32(ret);
        return ret;
    }
    unsigned int size = result.size();
    constexpr int maxSize = 200;
    constexpr int bigSize = 150;
    if (size > maxSize) {
        size = maxSize;
    }
    if (size > bigSize) {
        SendScanInfo(size, result, reply);
    } else {
        SendScanInfoSmall(size, result, reply);
    }
    return ret;
}

int WifiScanStub::OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    do {
        sptr<IRemoteObject> remote = data.ReadRemoteObject();
        if (remote == nullptr) {
            WIFI_LOGE("Failed to readRemoteObject!");
            break;
        }

        sptr<IWifiScanCallback> callback_ = iface_cast<IWifiScanCallback>(remote);
        if (callback_ == nullptr) {
            callback_ = new (std::nothrow) WifiScanCallbackProxy(remote);
            WIFI_LOGI("create new `WifiScanCallbackProxy`!");
        }

        int pid = data.ReadInt32();
        int tokenId = data.ReadInt32();
        int eventNum = data.ReadInt32();
        std::vector<std::string> event;
        if (eventNum > 0 && eventNum <= MAX_READ_EVENT_SIZE) {
            for (int i = 0; i < eventNum; ++i) {
                event.emplace_back(data.ReadString());
            }
        }
        WIFI_LOGD("%{public}s, get pid: %{public}d, tokenId: %{private}d", __func__, pid, tokenId);
        
        if (mSingleCallback) {
            ret = RegisterCallBack(callback_, event);
        } else {
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = new (std::nothrow) WifiScanDeathRecipient();
            }
            if ((remote->IsProxyObject()) && (!remote->AddDeathRecipient(deathRecipient_))) {
                WIFI_LOGD("AddDeathRecipient!");
            }
            if (callback_ != nullptr) {
                for (const auto &eventName : event) {
                    ret = WifiInternalEventDispatcher::GetInstance().AddScanCallback(remote, callback_, pid, eventName,
                        tokenId, m_instId);
                }
            }
        }
    } while (0);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}

int WifiScanStub::OnGetSupportedFeatures(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    long features = 0;
    int ret = GetSupportedFeatures(features);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt64(features);
    }

    return ret;
}

bool WifiScanStub::IsSingleCallback() const
{
    return mSingleCallback;
}

void WifiScanStub::SetSingleCallback(const bool isSingleCallback)
{
    mSingleCallback = true;
}

int WifiScanStub::OnSetScanOnlyAvailable(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    bool enabled = data.ReadBool();
    WIFI_LOGI("In WifiScanStub::OnSetScanOnlyAvailable enabled is %{public}d", enabled);
    reply.WriteInt32(0);
    reply.WriteInt32(SetScanOnlyAvailable(enabled));
    return 0;
}

int WifiScanStub::OnGetScanOnlyAvailable(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("In WifiScanStub::OnGetScanOnlyAvailable");
    bool state = false;
    ErrCode ret = GetScanOnlyAvailable(state);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteBool(state);
    }
    return 0;
}

int WifiScanStub::OnStartWifiPnoScan(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("In WifiScanStub::OnStartWifiPnoScan");
    bool isStart = data.ReadBool();
    int periodMs = data.ReadInt32();
    int suspendReason = data.ReadInt32();
    ErrCode ret = StartWifiPnoScan(isStart, periodMs, suspendReason);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
