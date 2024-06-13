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

import prompt from '@ohos.prompt';

export class WebObject {
  controller: WebController;
  isRegistered: boolean;

  constructor(controller: WebController , isRegistered: boolean) {
    this.controller = controller
    this.isRegistered = isRegistered
  }
}

@Observed
export class WebKey {
  key: number;
  timestamp: number;

  constructor(key: number , timestamp: number) {
    this.key = key
    this.timestamp = timestamp
  }
}

export enum LoadingStatus {
  LOADING ,
  END
}

const TAG: string = '[browser]'

export class Browser {
  inputValue: string = ""
  tabArrayIndex: number = 0
  progress: number = 0
  hideProgress: boolean = true
  loadingStatus: LoadingStatus = LoadingStatus.END
  webArray: Array<WebKey> = [ new WebKey(0 , new Date().getTime()) ]
  tabsController: TabsController = new TabsController()
  webControllerArray: Array<WebObject> = [ new WebObject(new WebController() , false) ]

  deleteTab(index: number) {
    console.log(TAG , `delete before tab index= ${ index } controller length ${ this.webControllerArray.length } tabArrayIndex= ${ this.tabArrayIndex }`)
    this.webArray.splice(index , 1)
    this.webControllerArray.splice(index , 1)
    if ( this.tabArrayIndex > index || this.tabArrayIndex === this.webArray.length ) {
      this.tabArrayIndex -= 1
    }
    for ( let i = index ;i < this.webArray.length ; ++i ) {
      this.webArray[ i ].key -= 1
    }
    for ( let i = 0 ;i < this.webArray.length ; ++i ) {
      console.log(TAG , `key ${ this.webArray[ i ].key }, time=${ this.webArray[ i ].timestamp }`)
    }
    console.log(`delete after tab index=${ index }, controller length=${ this.webControllerArray.length }, tabArrayIndex=${ this.tabArrayIndex }`)
    this.tabsController.changeIndex(this.tabArrayIndex)
  }

  getWebArray() {
    return this.webArray
  }

  addTab() {
    if ( this.webArray.length > 10 ) {
      prompt.showToast({
        message : '页签数量已满'
      })
      return;
    }
    let webController: WebController = new WebController();
    let object = new WebObject(webController , false)
    this.webControllerArray.push(object)
    this.webArray.push(new WebKey(this.webArray.length , new Date().getTime()))
    this.tabArrayIndex = this.webArray.length - 1
    console.log(TAG , `add tab index= ${ this.tabArrayIndex }`)
    setTimeout(() => {
      this.tabsController.changeIndex(this.tabArrayIndex)
    } , 50)
  }

  setTabArrayIndex(tabArrayIndex: number) {
    this.tabArrayIndex = tabArrayIndex
  }

  getTabArrayIndex() {
    return this.tabArrayIndex
  }

  setInputVal(inputValue: string) {
    this.inputValue = inputValue
  }

  getInputVal() {
    return this.inputValue
  }

  loadUrl(addr: Resource | string) {
    addr = "https://" + addr;
    this.webControllerArray[ this.tabArrayIndex ].controller.loadUrl({ url : addr })
  }

  Back() {
    if ( this.webControllerArray[ this.tabArrayIndex ].controller.accessBackward() ) {
      this.webControllerArray[ this.tabArrayIndex ].controller.backward()
    }
  }

  Forward() {
    if ( this.webControllerArray[ this.tabArrayIndex ].controller.accessForward() ) {
      this.webControllerArray[ this.tabArrayIndex ].controller.forward()
    }
  }

  Refresh() {
    this.webControllerArray[ this.tabArrayIndex ].controller.refresh()
  }
}
