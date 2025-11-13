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
#include "wifi_info_elem_parcel.h"

namespace OHOS {
namespace Wifi {

WifiInfoElemParcel WifiInfoElemParcel::FromWifiInfoElem(const WifiInfoElem& elem)
{
    WifiInfoElemParcel parcel;
    parcel.id = elem.id;
    parcel.content = elem.content;
    return parcel;
}

WifiInfoElem WifiInfoElemParcel::ToWifiInfoElem() const
{
    WifiInfoElem elem;
    elem.id = this->id;
    elem.content = this->content;
    return elem;
}

bool WifiInfoElemParcel::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(id))
        return false;

    if (!parcel.WriteUint32(content.size()))
        return false;
    for (char c : content) {
        if (!parcel.WriteInt8(c))
            return false;
    }
    return true;
}

WifiInfoElemParcel *WifiInfoElemParcel::Unmarshalling(Parcel &parcel)
{
    auto elem = std::make_unique<WifiInfoElemParcel>();
    if (!parcel.ReadUint32(elem->id)) {
        return nullptr;
    }

    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        return nullptr;
    }
    elem->content.reserve(size);

    for (uint32_t i = 0; i < size; i++) {
        int8_t c = 0;
        if (!parcel.ReadInt8(c)) {
            return nullptr;
        }
        elem->content.push_back(static_cast<char>(c));
    }

    return elem.release();
}

}  // namespace Wifi
}  // namespace OHOS