/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_AP_INFO_HELPER_H
#define OHOS_AP_INFO_HELPER_H

#include "wifi_msg.h"
#include "wifi_scan_msg.h"
#include "wifi_internal_msg.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include "cell_information.h"
#include "wifi_rdb_manager.h"

namespace OHOS {
namespace Wifi {

namespace BssidInfoTable {
    const std::string TABLE_NAME = "bssid_info_table";
    const std::string BSSID = "bssid";
    const std::string SSID = "ssid";
    const std::string TIME = "time";
    const std::string IN_BLACK_LIST = "inBlacklist";
    const std::string AUTH_TYPE = "authType";
    const std::string FREQUENCY = "frequency";
    const std::string IS_HOME_AP = "isHomeAp";
}

namespace CellIdInfoTable {
    const std::string TABLE_NAME = "cellid_info_table";
    const std::string BSSID = "bssid";
    const std::string CELL_ID = "cellId";
    const std::string RSSI = "rssi";
}

namespace NearByApInfoTable {
    const std::string TABLE_NAME = "nearby_ap_info_table";
    const std::string BSSID = "bssid";
    const std::string NEAR_BY_BSSID = "nearbyBssid";
}

struct CellInfoData {
    std::string cellId;
    int32_t rssi;
};

struct ApInfoData {
    std::string bssid;
    std::string ssid;
    long time;
    std::string authType;
    int32_t isHomeAp;
    int32_t frequency;
    int32_t inBlacklist;
    std::vector<CellInfoData> cellInfos;
    std::vector<std::string> nearbyApInfos;
};

struct LinkedCellInfo {
    int32_t cellId;
    std::string mcc;  // Physical Cell Id
    std::string mnc;  // Tracking Area Code
    int32_t rssi;
    int32_t rat;
};

enum RatType { GSM_TYPE = 1, WCDMA_TYPE = 2, LTE_TYPE = 3, NR_TYPE = 4 };

class ApInfoHelper {
public:
    ~ApInfoHelper();
    static ApInfoHelper &GetInstance();
    int32_t Init();
    bool IsCellIdExit(std::string cellId);
    bool IsCellIdExitByData(ApInfoData info, std::string cellId);
    std::vector<ApInfoData> GetMonitorDatas(std::string cellId);
    bool GetAllApInfos();
    void DelApInfos(const std::string &bssid);
    void AddApInfo(std::string cellId, int32_t networkId);
    void AddNewApInfo(const std::string &cellId, const WifiDeviceConfig &config);
    int32_t GetOldestApInfoData(ApInfoData &data);
    int32_t GetApInfoByBssid(const std::string &bssid, ApInfoData &data);
    int32_t QueryCellIdInfoByParam(const std::map<std::string, std::string> &queryParams,
        std::vector<CellInfoData> &cellInfoVector);
    bool SaveBssidInfo(ApInfoData &apInfoData);
    int32_t QueryNearbyInfoByParam(const std::map<std::string, std::string> &queryParams,
        std::vector<std::string> &nearbyInfoVector);
    int32_t QueryBssidInfoByParam(const std::map<std::string, std::string> &queryParams,
        std::vector<ApInfoData> &apInfoVector);
    int32_t DelBssidInfo(std::string bssid);
    void AddCellInfo(std::string bssid, std::string cellId);
    int32_t DelCellInfoByBssid(std::string bssid);
    int32_t AddNearbyApInfo(std::string bssid);
    int32_t DelNearbyApInfo(std::string bssid);
    void DeleteApInfoBySsidForPortal(WifiLinkedInfo linkedInfo);
    void UpdateBssidIsBlacklist(std::string bssid, int32_t inBlacklist);
    void SetBlackListBySsid(std::string ssid, std::string authType, int32_t isBlacklist);
    void ResetBlacklist(std::vector<WifiScanInfo> scanInfoList, int32_t isBlacklist);
    void ResetAllBalcklist();
    std::string GetCurrentCellIdInfo();
private:
    explicit ApInfoHelper();
    void GetLteCellInfo(sptr<Telephony::CellInformation> infoItem, LinkedCellInfo &currentCell);
    void GetNrCellInfo(sptr<Telephony::CellInformation> infoItem, LinkedCellInfo &currentCell);
    std::mutex mutex_;
    std::vector<ApInfoData> apInfos_;
    std::shared_ptr<WifiRdbManager> wifiDataBaseUtils_;
};
}
}
#endif