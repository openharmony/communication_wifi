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

export enum Category  {
  All,
  API,
  Scenario,
  AutoTest,
  BenchMark
}

let NextId = 0;
export class TestData {
  id: string;
  name: string;
  detail: string;
  url: string;
  image: Resource
  category: Category;

  constructor(name: string, detail: string, url: string, image: Resource, category: Category) {
    this.id = `${ NextId++ }`;
    this.name = name;
    this.url = url;
    this.detail = detail;
    this.image = image;
    this.category = category;
  }
}

export enum CaseCategory  {
  Wifi,
  WifiManger,
  Hotspot,
  HotspotManager,
  P2p,
  P2pManager
}

export class TestApi {
  id: string;
  name: string;
  detail: string;
  method: string;
  api: any;
  result: string;
  category: CaseCategory;

  constructor(name: string, detail: string, method: string, api: any, result: string, category: CaseCategory) {
    this.id = `${ NextId++ }`;
    this.name = name;
    this.detail = detail;
    this.method = method;
    this.api = api;
    this.result = result;
    this.category = category;
  }
}

export enum AutoCategory {
  WifiAuto,
  HotspotAuto,
  P2pAuto
}

export class TestAuto{
  id: string;
  name: string;
  detail: string;
  method: string;
  api: any;
  image: Resource;
  result: string;
  category: AutoCategory;

  constructor(name: string, detail: string, method: string , api:any ,result: string, category: AutoCategory) {
    this.id = `${ NextId++ }`;
    this.name = name;
    this.detail = detail;
    this.method = method;
    this.api = api;
    this.result = result;
    this.category = category;
  }
}

export enum ScenarioCategory {
  WifiFoundScenario,
  HotspotFoundScenario,
  P2pConnectScenario,
}

export class TestScenario{
  id: string;
  name: string;
  detail: string;
  method: string;
  api: any;
  image: Resource;
  result: string;
  category: ScenarioCategory;

  constructor(name: string, detail: string, method: string , api:any ,result: string, category: ScenarioCategory) {
    this.id = `${ NextId++ }`;
    this.name = name;
    this.detail = detail;
    this.method = method;
    this.api = api;
    this.result = result;
    this.category = category;
  }
}

export enum BenchmarkCategory {
  WifiBenchmark,
  HotspotBenchmark,
  P2pBenchmark,
}

export class TestBenchmark{
  id: string;
  name: string;
  detail: string;
  method: string;
  api: any;
  image: Resource;
  result: string;
  category: BenchmarkCategory;

  constructor(name: string, detail: string, method: string , api:any ,result: string, category: BenchmarkCategory) {
    this.id = `${ NextId++ }`;
    this.name = name;
    this.detail = detail;
    this.method = method;
    this.api = api;
    this.result = result;
    this.category = category;
  }
}