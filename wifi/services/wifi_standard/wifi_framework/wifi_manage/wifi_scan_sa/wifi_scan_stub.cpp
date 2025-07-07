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
#include "wifi_watchdog_utils.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanStub");

namespace OHOS {
namespace Wifi {
static std::map<int, std::string> g_HicollieScanMap = {
    { static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_START_PNO_SCAN), "WIFI_SVR_CMD_START_PNO_SCAN" },
};
WifiScanStub::WifiScanStub() : mSingleCallback(false)
{
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiScanStub::WifiScanStub(int instId) : mSingleCallback(false), m_instId(instId)
{
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiScanStub::~WifiScanStub()
{
    deathRecipient_ = nullptr;
}

void WifiScanStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnSetScanControlInfo(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { return OnScan(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnScanByParams(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnIsWifiClosedScan(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_SCAN_INFO_LIST)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnGetScanInfoList(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnRegisterCallBack(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnGetSupportedFeatures(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_WIFI_SCAN_ONLY)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnSetScanOnlyAvailable(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_WIFI_SCAN_ONLY)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnGetScanOnlyAvailable(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_START_PNO_SCAN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { return OnStartWifiPnoScan(code, data, reply, option); };
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
        std::map<int, std::string>::const_iterator itCollieId = g_HicollieScanMap.find(code);
        if (itCollieId != g_HicollieScanMap.end()) {
            int idTimer = 0;
            idTimer = WifiWatchDogUtils::GetInstance()->StartWatchDogForFunc(itCollieId->second);
            WIFI_LOGI("SetTimer id: %{public}d, name: %{public}s.", idTimer, itCollieId->second.c_str());
            (iter->second)(code, data, reply, option);
            WifiWatchDogUtils::GetInstance()->StopWatchDogForFunc(itCollieId->second, idTimer);
        } else {
            (iter->second)(code, data, reply, option);
        }
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
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName(name);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(GetCallingUid());
    ErrCode ret = Scan(compatible);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName("");
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(-1);
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

    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName(name);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(GetCallingUid());
    ErrCode ret = AdvanceScan(params);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName("");
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(-1);
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

constexpr int32_t ASH_MEM_SIZE = 1024 * 300;
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
    int offset = 0;
    size_t maxIeSize = 256;
    size_t maxIeLen = 1024;
    std::vector<uint32_t> allSize;
    for (int32_t i = 0; i < contentSize; ++i) {
        MessageParcel outParcel;
        outParcel.WriteString(result[i].bssid);
        outParcel.WriteString(result[i].ssid);
        outParcel.WriteInt32(result[i].bssidType);
        outParcel.WriteString(result[i].capabilities);
        outParcel.WriteInt32(result[i].frequency);
        outParcel.WriteInt32(result[i].band);
        outParcel.WriteInt32(static_cast<int>(result[i].channelWidth));
        outParcel.WriteInt32(result[i].centerFrequency0);
        outParcel.WriteInt32(result[i].centerFrequency1);
        outParcel.WriteInt32(result[i].rssi);
        outParcel.WriteInt32(static_cast<int>(result[i].securityType));
        size_t ieSize = result[i].infoElems.size() < maxIeSize ? result[i].infoElems.size() : maxIeSize;
        outParcel.WriteUint32(ieSize);
        for (size_t j = 0; j < ieSize; j++) {
            auto elem = result[i].infoElems[j];
            outParcel.WriteUint32(elem.id);
            size_t ieLen = elem.content.size() < maxIeLen ? elem.content.size() : maxIeLen;
            outParcel.WriteUint32(ieLen);
            for (size_t k = 0; k < ieLen; k++) {
                auto byte = elem.content[k];
                outParcel.WriteInt32(static_cast<int>(byte));
            }
        }
        outParcel.WriteInt64(result[i].features);
        outParcel.WriteInt64(result[i].timestamp);
        outParcel.WriteInt32(result[i].wifiStandard);
        outParcel.WriteInt32(result[i].maxSupportedRxLinkSpeed);
        outParcel.WriteInt32(result[i].maxSupportedTxLinkSpeed);
        outParcel.WriteInt32(result[i].disappearCount);
        outParcel.WriteInt32(result[i].isHiLinkNetwork);
        outParcel.WriteInt32(static_cast<int>(result[i].supportedWifiCategory));

        int dataSize = static_cast<int>(outParcel.GetDataSize());
        if (offset + dataSize > ASH_MEM_SIZE) {
            break;
        }
        allSize.emplace_back(dataSize);
        ashmem->WriteToAshmem(reinterpret_cast<void*>(outParcel.GetData()), dataSize, offset);
        offset += dataSize;
    }
    reply.WriteInt32(WIFI_OPT_SUCCESS);
    reply.WriteUInt32Vector(allSize);
    reply.WriteAshmem(ashmem);
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
}

int WifiScanStub::OnGetScanInfoList(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    bool compatible = data.ReadBool();
    WIFI_LOGD("run OnGetScanInfoList code %{public}u, datasize %{public}zu, compatible:%{public}d", code,
        data.GetRawDataSize(), compatible);
    std::vector<WifiScanInfo> result;
    ErrCode ret = GetScanInfoList(result, compatible);
    reply.WriteInt32(0);
    if (ret != WIFI_OPT_SUCCESS) {
        reply.WriteInt32(ret);
        return ret;
    }
    // Sort scan results by RSSI in descending order
    std::sort(result.begin(), result.end(), [](const WifiScanInfo& a, const WifiScanInfo& b) {
        return a.rssi > b.rssi;
    });
    int32_t size = static_cast<int>(result.size());
    constexpr int maxSize = 200;
    if (size > maxSize) {
        size = maxSize;
    }
    SendScanInfo(size, result, reply);
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
            callback_ = sptr<WifiScanCallbackProxy>::MakeSptr(remote);
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
            std::unique_lock<std::mutex> lock(deathRecipientMutex);
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = sptr<WifiScanDeathRecipient>::MakeSptr();
            }
            // Add death recipient to remote object if this is the first time to register callback.
            if ((remote->IsProxyObject()) &&
                !WifiInternalEventDispatcher::GetInstance().HasScanRemote(remote, m_instId)) {
                remote->AddDeathRecipient(deathRecipient_);
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

int WifiScanStub::OnGetSupportedFeatures(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
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

int WifiScanStub::OnSetScanOnlyAvailable(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    bool enabled = data.ReadBool();
    WIFI_LOGI("In WifiScanStub::OnSetScanOnlyAvailable enabled is %{public}d", enabled);
    reply.WriteInt32(0);
    reply.WriteInt32(SetScanOnlyAvailable(enabled));
    return 0;
}

int WifiScanStub::OnGetScanOnlyAvailable(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
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

int WifiScanStub::OnStartWifiPnoScan(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
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
} // namespace Wifi
} // namespace OHOS
