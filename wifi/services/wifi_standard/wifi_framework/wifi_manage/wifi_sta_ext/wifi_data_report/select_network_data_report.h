/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_SELECT_NETWORK_DATA_REPORT_H
#define OHOS_SELECT_NETWORK_DATA_REPORT_H
#include <vector>
#include <mutex>
#include <map>
#include "wifi_log.h"
#include "wifi_crowdsourced_data.h"
#include "ienhance_service.h"
#include "sta_sm_ext.h"

namespace OHOS {
namespace Wifi {

class StaStateMachine;

/* wifi 数据上报类 */
class WifiDataReportService : public StaSMExt {
private:
    ConnectEventTimeInfo connEventTimepInfo_;
    bool disConnFlag_ = false;
    std::map<std::string, time_t> lastPushTime_; // 存储每个bssid的最后推送时间
    std::vector<WifiCrowdsourcedQoeInfo> historyData_; // 存储历史数据
    std::mutex historyMutex_; // 用于保护历史记录
public:

    explicit WifiDataReportService(StaStateMachine& staStateMachine, int instId);
    ~ WifiDataReportService() override;

    /**
     * @Description : 初始化成员变量
     *
     */
    void InitReportApAllInfo();

    /**
     * @Description : 事件上报
     *
     * @param reportReason - 上报原因
     */
    void ReportApConnEventInfo(ConnReportReason reportReason, int targetNetworkId);

    /**
     * @Description : 周期上报
     *
     * @param qoeInfo - WifiSignalPollInfo 信息
     * @param reportReason - 上报原因
     */
    void ReportQoeInfo(const WifiSignalPollInfo& qoeInfo, ConnReportReason reportReason, int targetNetworkId);

private:

    /**
     * @Description : 4 × 8位 -> 32位
     *
     * @param ext - signalpoll.ext
     * @param index - signalpoll.ext 特定元素的索引
     */
    uint32_t GetUint32FromExt(const std::vector<uint8_t>& ext, size_t index);

    /**
     * @Description : 2 × 8位 -> 16位
     *
     * @param uint8Vec - uint8 vector
     */
    std::vector<uint16_t> ConvertUint8ToUint16(const std::vector<uint8_t>& uint8Vec);

    /**
     * @Description : BE, BK, VI, VO 四个队列合并
     *
     * @param uint8Vec - uint8 vector
     */
    std::vector<uint16_t> SequenceMerge(const std::vector<uint16_t>& sequence);

    /**
     * @Description : 更新 AP 连接事件时间戳
     *
     * @param timeType - 上报时间类型(连接开始，连接成功，断开连接)
     */
    void UpdateApConnEventTimepInfo(ConnTimeType timeType);

    /**
     * @Description : 获取 AP Device 信息
     *
     * @param networkId - linkedinfo->networkId
     * @param instId - linkedinfo->instId
     * @param apDeviceInfo - AP Device info
     */
    void GetApDeviceInfo(const int& networkId, int instId, WifiDeviceConfig& apDeviceInfo); // 获取并更新 AP Device 信息

    /**
     * @Description : 判断是否为邻频 ap
     *
     * @param apFrequency - 扫描 ap 的频率
     * @param targetApFrequency - 目标 ap 的频率
     * @param wifiBand - 目标 ap 的频段
     * @return true - 是邻频 ap, false - 不是邻频 ap
     */
    bool IsAdjacentChannel(int apFrequency, int targetApFrequency, char wifiBand);

    /**
     * @Description : 更新目标 ap 邻频和同频 ap 数
     *
     * @param apDetailInfo - ap 详细信息
     * @param targetBssid - 目标 ap 的 bssid
     * @param freq - 目标 ap 的频率
     * @param band - 目标 ap 的频段
     */
    void UpdateSameAdjaFreqCount(WifiCrowdsourcedDetailInfo& apDetailInfo, const std::string targetBssid,
        const int freq, const int band);

    /**
     * @Description : 更新前台应用包名
     *
     * @param apDetailInfo - ap 详细信息
     */
    void UpdateForegroundBundleName(WifiCrowdsourcedDetailInfo& apDetailInfo);

    /**
     * @Description : 更新众包数据的 ap 详细信息
     *
     * @param apDetailInfo - ap详细信息
     * @param linkedInfo - ap linked 信息
     * @param apDeviceInfo - ap device 信息
     */
    void UpdateCrowdsourcedDetailInfo(WifiCrowdsourcedDetailInfo& apDetailInfo,
        const WifiLinkedInfo& linkedInfo, const WifiDeviceConfig& apDeviceInfo);

    /**
     * @Description : 更新众包数据的 ap Qoe 信息
     *
     * @param apDetailInfo - ap详细信息
     * @param historyData - ap 历史若干条 qoe 信息
     */
    void UpdateCrowdsourcedQoeInfo(WifiCrowdsourcedQoeInfo& apQoeInfo,
        const std::vector<WifiCrowdsourcedQoeInfo>& historyData);

    /**
     * @Description : 解析 WifiSignalPollInfo 信息
     *
     * @param parseInfo - 解析后存放的 Info
     * @param signalPollInfo - signalPoll Info
     */
    void ParseSignalPollInfo(WifiCrowdsourcedQoeInfo& parseInfo, const WifiSignalPollInfo& signalPollInfo);

    /**
     * @Description : 解析 WifiSignalPollInfo 信息 EX
     *
     * @param parseInfo - 解析后存放的 Info
     * @param signalPollInfo - signalPoll Info
     */
    void ParseSignalPollInfoEx(WifiCrowdsourcedQoeInfo& parseInfo, const WifiSignalPollInfo& signalPollInfo);
};
} // namespace Wifi
} // namespace OHOS
#endif