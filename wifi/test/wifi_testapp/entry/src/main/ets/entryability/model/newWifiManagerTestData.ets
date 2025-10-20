/**
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

/**
 * 新接口测试下的wifiManager测试数据 - 只包含几个主要的测试用例
 */

import { TestApi , CaseCategory } from './testData'
import { 
  testIsWifiActiveManager,
  testEnableWifiManager,
  testDisableWifiManager,
} from './wifiManagerInterface'

interface WifiTest {
  name: string,
  detail: string,
  method: string,
  api: Function,
  result: string,
  category: CaseCategory
}

export const NewWifiManagerTestCase: WifiTest[] = [
  {
    'name' : '是否已使能' ,
    'detail' : '是否已使能' ,
    'method' : 'isWifiActive' ,
    'api' : testIsWifiActiveManager ,
    'result' : 'None' ,
    'category' : CaseCategory.WifiManager
  },
  {
    'name' : '开Wifi' ,
    'detail' : '使能Wifi' ,
    'method' : 'enableWifi' ,
    'api' : testEnableWifiManager ,
    'result' : 'None' ,
    'category' : CaseCategory.WifiManager
  },
  {
    'name' : '关wifi' ,
    'detail' : '去使能wifi' ,
    'method' : 'disableWifi' ,
    'api' : testDisableWifiManager ,
    'result' : 'None' ,
    'category' : CaseCategory.WifiManager
  },
]

export function initNewWifiManagerApiData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  NewWifiManagerTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestApiArray;
}

