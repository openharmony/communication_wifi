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
#ifndef OHOS_WIFI_ASHMEM_PARCEL_H
#define OHOS_WIFI_ASHMEM_PARCEL_H

#include <parcel.h>
#include <message_parcel.h>
#include <ashmem.h>

namespace OHOS {
namespace Wifi {

class ScanAshmemParcel : public Parcelable {
public:
    ScanAshmemParcel() = default;

    explicit ScanAshmemParcel(sptr<Ashmem> ashmem) : ashmem_(ashmem)
    {}

    ~ScanAshmemParcel() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ScanAshmemParcel *Unmarshalling(Parcel &parcel);
    sptr<Ashmem> GetAshmem() const
    {
        return ashmem_;
    }

private:
    sptr<Ashmem> ashmem_;
};
}  // namespace Wifi
}  // namespace OHOS

#endif  // OHOS_WIFI_ASHMEM_PARCEL_H

