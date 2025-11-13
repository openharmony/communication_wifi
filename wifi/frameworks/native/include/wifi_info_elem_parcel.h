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
#ifndef WIFI_INFO_ELEM_PARCEL_H
#define WIFI_INFO_ELEM_PARCEL_H

#include "parcel.h"
#include <vector>
#include "scan_control_info_parcel.h"
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {

struct WifiInfoElemParcel : public Parcelable {
    unsigned int id;
    std::vector<char> content;

    static WifiInfoElemParcel FromWifiInfoElem(const WifiInfoElem &elem);
    WifiInfoElem ToWifiInfoElem() const;

    bool Marshalling(Parcel &parcel) const override;
    static WifiInfoElemParcel *Unmarshalling(Parcel &parcel);
};
}  // namespace Wifi
}  // namespace OHOS

#endif  // WIFI_INFO_ELEM_PARCEL_H