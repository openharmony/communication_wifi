/*
  * Copyright (c) 2021 Huawei Device Co., Ltd.
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
 
 #include "net_supplier_info.h"
 namespace OHOS {
 namespace NetManagerStandard {
 bool NetSupplierInfo::Marshalling(Parcel &parcel) const
 {
     return true;
 }
 
 sptr<NetSupplierInfo> NetSupplierInfo::Unmarshalling(Parcel &parcel)
 {
     sptr<NetSupplierInfo> ptr = new (std::nothrow) NetSupplierInfo();
     if (ptr == nullptr) {
         return nullptr;
     }
     return ptr;
 }
 
 bool NetSupplierInfo::Marshalling(Parcel &parcel, const sptr<NetSupplierInfo> &object)
 {
     if (object == nullptr) {
         return false;
     }
     return true;
 }
 
 std::string NetSupplierInfo::ToString(const std::string &tab) const
 {
     std::string str;
     return str;
 }
 } // namespace NetManagerStandard
 } // namespace OHOS