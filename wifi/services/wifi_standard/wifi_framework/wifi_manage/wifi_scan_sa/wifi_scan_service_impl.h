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

#ifndef OHOS_WIFI_SCAN_SERVICE_H
#define OHOS_WIFI_SCAN_SERVICE_H

#ifdef OHOS_ARCH_LITE
#include "wifi_scan_stub_lite.h"
#else
#include "system_ability.h"
#include "wifi_scan_stub.h"
#include "iremote_object.h"
#include "wifi_scan_death_recipient.h"
#endif

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
enum ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
#endif

class WifiScanServiceImpl : public WifiScanStub {
public:
    WifiScanServiceImpl();
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiScanServiceImpl> GetInstance();
    void OnStart();
    void OnStop();
#else
    explicit WifiScanServiceImpl(int instId);
#endif
    virtual ~WifiScanServiceImpl();
 
#ifdef OHOS_ARCH_LITE
    ErrCode SetScanControlInfo(const ScanControlInfo &info) override;
    ErrCode Scan(bool compatible) override;
    ErrCode PermissionVerification();
    ErrCode AdvanceScan(const WifiScanParams &params) override;
    ErrCode IsWifiClosedScan(bool &bOpen) override;
    ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible) override;
    ErrCode SetScanOnlyAvailable(bool bScanOnlyAvailable) override;
    ErrCode GetScanOnlyAvailable(bool &bScanOnlyAvailable) override;
    ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason) override;
    ErrCode RegisterCallBack(
        const std::shared_ptr<IWifiScanCallback> &callback, const std::vector<std::string> &event) override;
    ErrCode GetSupportedFeatures(long &features) override;
    ErrCode ProcessScanInfoRequest();
    ErrCode IsAllowedThirdPartyRequest(std::string appId);
    ErrCode HandleScanIdlRet(ErrCode originRet);
#else
    ErrCode SetScanControlInfo(const ScanControlInfoParcel &info) override;
    ErrCode Scan(bool compatible, const std::string& bundleName, int32_t &scanResultCode) override;
    ErrCode AdvanceScan(const WifiScanParamsParcel &paramsParcel, const std::string& bundleName) override;
    ErrCode IsWifiClosedScan(bool &bOpen) override;
    ErrCode GetScanInfoList(bool compatible, ScanAshmemParcel &outAshmemParcel, std::vector<int32_t> &allSize) override;
    ErrCode SetScanOnlyAvailable(bool bScanOnlyAvailable) override;
    ErrCode GetScanOnlyAvailable(bool &bScanOnlyAvailable) override;
    ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason) override;
    ErrCode RegisterCallBack(const sptr<IRemoteObject> &cbParcel, int32_t pid, int32_t tokenId,
    const std::vector<std::string> &event) override;
    ErrCode GetSupportedFeatures(int64_t &features) override;
 
    int32_t SetScanControlInfo(const ScanControlInfo &info);
    int32_t Scan(bool compatible);
    int32_t PermissionVerification();
    int32_t AdvanceScan(const WifiScanParams &params);
    int32_t GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible);
    int32_t RegisterCallBack(const sptr<IWifiScanCallback> &callback, const std::vector<std::string> &event);
    int32_t ProcessScanInfoRequest();
    int32_t IsAllowedThirdPartyRequest(std::string appId);
    int32_t HandleScanIdlRet(int32_t originRet);
#endif
    bool IsRemoteDied(void);
    static void SaBasicDump(std::string& result);

private:
    bool Init();
    bool IsScanServiceRunning();
#ifdef SUPPORT_LP_SCAN
    bool IsWifiScanAllowed(int &scanStyle, bool externFlag = true);
#else
    bool IsWifiScanAllowed(bool externFlag = true);
#endif
    bool IsInScanMacInfoWhiteList();
    void UpdateScanInfoListNotInWhiteList(std::vector<WifiScanInfo> &result);
#ifndef OHOS_ARCH_LITE
    void UpdateScanMode();
    void WriteBasicInfoToParcel(MessageParcel &outParcel, WifiScanInfo &result);
    void SendScanInfo(int32_t contentSize, std::vector<WifiScanInfo> &result,
                     ScanAshmemParcel &outAshmemParcel, std::vector<uint32_t> &allSizeUint);
    void WriteInfoElementsToParcel(
        const std::vector<WifiInfoElem> &infoElems, size_t ieSize, size_t maxIeLen, Parcel &outParcel);
#endif

private:

#ifdef OHOS_ARCH_LITE
    static std::mutex g_instanceLock;
    static std::shared_ptr<WifiScanServiceImpl> g_instance;
    ServiceRunningState mState;
#else
    int m_instId{0};
    bool mSingleCallback;
    std::mutex deathRecipientMutex;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
#endif
    int64_t queryScanMacInfoWhiteListTimeStamp_ = 0;
    std::string scanMacInfoWhiteListStr_;
    std::mutex wifiWhiteListMutex_;
    std::mutex mThirdPartyScanLimitMutex_;
    std::map<std::string, std::vector<int64_t>> callTimestampsMap_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
