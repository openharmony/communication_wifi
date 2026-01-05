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
#include "scan_control_info_parcel.h"

namespace OHOS {
namespace Wifi {
#define MAX_SIZE 1024

ScanControlInfoParcel::ScanControlInfoParcel(const ScanControlInfo &info)
{
    for (const auto &forbidMode : info.scanForbidList) {
        ScanForbidMode parcelForbid;
        parcelForbid.scanScene = forbidMode.scanScene;
        parcelForbid.forbidTime = forbidMode.forbidTime;
        parcelForbid.forbidCount = forbidMode.forbidCount;
        parcelForbid.scanMode = forbidMode.scanMode;
        scanForbidList.push_back(parcelForbid);
    }
    for (const auto &intervalMode : info.scanIntervalList) {
        ScanIntervalMode parcelInterval;
        parcelInterval.scanScene = intervalMode.scanScene;
        parcelInterval.scanMode = intervalMode.scanMode;
        parcelInterval.isSingle = intervalMode.isSingle;
        parcelInterval.intervalMode = intervalMode.intervalMode;
        parcelInterval.interval = intervalMode.interval;
        parcelInterval.count = intervalMode.count;
        scanIntervalList.push_back(parcelInterval);
    }
}

ScanControlInfo ScanControlInfoParcel::ToScanControlInfo() const
{
    ScanControlInfo info;

    for (const auto &parcelForbid : this->scanForbidList) {
        ScanForbidMode forbidMode;
        forbidMode.scanScene = parcelForbid.scanScene;
        forbidMode.forbidTime = parcelForbid.forbidTime;
        forbidMode.forbidCount = parcelForbid.forbidCount;
        forbidMode.scanMode = parcelForbid.scanMode;
        info.scanForbidList.push_back(forbidMode);
    }

    for (const auto &parcelInterval : this->scanIntervalList) {
        ScanIntervalMode intervalMode;
        intervalMode.scanScene = parcelInterval.scanScene;
        intervalMode.scanMode = parcelInterval.scanMode;
        intervalMode.isSingle = parcelInterval.isSingle;
        intervalMode.intervalMode = parcelInterval.intervalMode;
        intervalMode.interval = parcelInterval.interval;
        intervalMode.count = parcelInterval.count;
        info.scanIntervalList.push_back(intervalMode);
    }

    return info;
}

bool ScanControlInfoParcel::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(scanForbidList.size()))
        return false;
    for (const auto &item : scanForbidList) {
        if (!parcel.WriteInt32(item.scanScene) ||
            !parcel.WriteInt32(item.forbidTime) ||
            !parcel.WriteInt32(item.forbidCount) ||
            !parcel.WriteInt32(static_cast<int32_t>(item.scanMode))) {
            return false;
        }
    }

    if (!parcel.WriteUint32(scanIntervalList.size()))
        return false;
    for (const auto &item : scanIntervalList) {
        if (!parcel.WriteInt32(item.scanScene) ||
            !parcel.WriteBool(item.isSingle) ||
            !parcel.WriteInt32(item.interval) ||
            !parcel.WriteInt32(item.count) ||
            !parcel.WriteInt32(static_cast<int32_t>(item.scanMode)) ||
            !parcel.WriteInt32(static_cast<int32_t>(item.intervalMode))) {
            return false;
        }
    }
    return true;
}

ScanControlInfoParcel *ScanControlInfoParcel::Unmarshalling(Parcel &parcel)
{
    auto info = std::make_unique<ScanControlInfoParcel>();
    uint32_t size = 0;
    int32_t tempValue = 0;

    if (!parcel.ReadUint32(size))
        return nullptr;

    if (size < 0 || size > MAX_SIZE) {
        return nullptr;
    }
    info->scanForbidList.reserve(size);

    for (uint32_t i = 0; i < size; i++) {
        ScanForbidMode forbid;
        
        if (!parcel.ReadInt32(forbid.scanScene) ||
            !parcel.ReadInt32(forbid.forbidTime) ||
            !parcel.ReadInt32(forbid.forbidCount)) {
            return nullptr;
        }
        
        if (!parcel.ReadInt32(tempValue)) {
            return nullptr;
        }
        forbid.scanMode = static_cast<ScanMode>(tempValue);
        
        info->scanForbidList.push_back(forbid);
    }

    if (!parcel.ReadUint32(size))
        return nullptr;

    if (size < 0 || size > MAX_SIZE) {
        return nullptr;
    }
    info->scanIntervalList.reserve(size);

    for (uint32_t i = 0; i < size; i++) {
        ScanIntervalMode interval;
        
        if (!parcel.ReadInt32(interval.scanScene) ||
            !parcel.ReadBool(interval.isSingle) ||
            !parcel.ReadInt32(interval.interval) ||
            !parcel.ReadInt32(interval.count)) {
            return nullptr;
        }
        
        if (!parcel.ReadInt32(tempValue)) {
            return nullptr;
        }
        interval.scanMode = static_cast<ScanMode>(tempValue);
        
        if (!parcel.ReadInt32(tempValue)) {
            return nullptr;
        }
        interval.intervalMode = static_cast<IntervalMode>(tempValue);
        
        info->scanIntervalList.push_back(interval);
    }

    return info.release();
}

}  // namespace Wifi
}  // namespace OHOS