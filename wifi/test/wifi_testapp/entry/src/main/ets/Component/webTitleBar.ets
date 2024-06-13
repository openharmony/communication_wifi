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

import { Browser , LoadingStatus , WebObject , WebKey } from '../entryability/model/bowser'
import fs from '@ohos.file.fs';
import ConfigData from '../Utils/ConfigData'

const TAG: string = '[webTitleBar]'
const BUTTON_WIDTH: number = 22
const BUTTON_RADIUS: number = 4
const DOWN_COLOR: string = '#e4e4e4'
const UP_COLOR: string = '#00000000'
const PAD_USER_AGENT: string = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTMl, like Gecko) Chrome/92.0.4515.105 Safari/537.36'
const PHONE_USER_AGENT: string = 'Mozilla/5.0 (Linux; VRD-AL10; HMSCore 6.3.0.331) AppleWebKit/537.36 (KHTMl, like Gecko) Chrome/92.0.4515.105 HuaweiBrowser/12.0.4.1 Mobile Safari/537.36'

interface TestObject {
  test: (addr: string) => void;
  searchWord: (word: string) => void;
}

interface ImageSrcId {
  imageSrc: Resource,
  id: number
}

interface EventOnProgress {
  newProgress: number;
}

interface EventOnPage {
  url: string
}

@Component
export struct TabletTitle {
  @Link browser: Browser;
  @State inputValue: string = ''
  @State arrayIndex: number = 0
  @State addr: string = 'www.baidu.com'
  private navigationButton: Array<ImageSrcId> = [
    {
      imageSrc : $r('app.media.ic_public_back') ,
      id : 1
    },
    {
      imageSrc : $r('app.media.ic_public_advance') ,
      id : 2
    },
    {
      imageSrc : $r('app.media.ic_public_refresh') ,
      id : 3
    },
    {
      imageSrc : $r('app.media.ic_public_home') ,
      id : 4
    },
  ]
  private actionButton: Array<ImageSrcId> = [
    {
      imageSrc : $r('app.media.submit') ,
      id : 5
    },
    {
      imageSrc : $r('app.media.ic_public_add') ,
      id : 6
    },
  ]

  build() {
    Row() {
      ForEach(this.navigationButton , (item: ImageSrcId , index: number) => {
        Button({ type : ButtonType.Normal }) {
          Image(item.imageSrc)
        }
        .margin(8)
        .id(`navigationButton${ index }`)
        .width(BUTTON_WIDTH)
        .height(BUTTON_WIDTH)
        .backgroundColor(this.arrayIndex === item.id ? DOWN_COLOR : UP_COLOR)
        .borderRadius(BUTTON_RADIUS)
        .flexShrink(0)
        .onTouch((event: TouchEvent) => {
          if ( event.type === TouchType.Down ) {
            this.arrayIndex = item.id
          } else if ( event.type === TouchType.Up ) {
            this.arrayIndex = 0
          }
        })
        .onClick((event: ClickEvent) => {
          switch ( item.id ) {
            case 1:
              this.browser.Back()
              break;
            case 2:
              this.browser.Forward()
              break;
            case 3:
              this.browser.Refresh()
              break;
            case 4:
              this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.loadUrl({
                url : $rawfile('phone.html') // pad.html
              })
              break;
          }
        })
      } , (item: ImageSrcId) => item.id.toString())

      TextInput({ placeholder : '默认网址:www.baidu.com' , text : this.browser.inputValue })
        .placeholderFont({ size : 18 , weight : ConfigData.WH_50_100 })
        .fontSize(18)
        .margin(2)
        .id('inputUrl')
        .width(ConfigData.WH_50_100)
        .layoutWeight(1)
        .onChange((value: string) => {
          this.addr = value
          AppStorage.setOrCreate("addr" , this.addr)
        })
        .onSubmit((enterKey: EnterKeyType) => {
          console.log(TAG , `onSubmit`)
          if ( this.addr.length !== 0 ) {
            this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.loadUrl({
              url : `https://${ this.addr }`
            })
            this.addr = ''
          }
        })

      ForEach(this.actionButton , (item: ImageSrcId , index: number) => {
        Button({ type : ButtonType.Normal }) {
          Image(item.imageSrc)
        }
        .margin(8)
        .id(`actionButton${ index }`)
        .width(BUTTON_WIDTH)
        .height(BUTTON_WIDTH)
        .backgroundColor(this.arrayIndex === item.id ? DOWN_COLOR : UP_COLOR)
        .borderRadius(BUTTON_RADIUS)
        .flexShrink(0)
        .onTouch((event: TouchEvent) => {
          if ( event.type === TouchType.Down ) {
            this.arrayIndex = item.id
          } else if ( event.type === TouchType.Up ) {
            this.arrayIndex = 0
          }
        })
        .onClick((event: ClickEvent) => {
          if ( item.id === 5 ) {
            this.browser.loadUrl(this.addr)
            this.addr = ''
          } else if ( item.id === 6 ) {
            console.log(TAG , `add tab index = ` + this.arrayIndex)
            this.browser.addTab()
          }
        })
      } , (item: ImageSrcId) => item.id.toString())
    }
    .width(ConfigData.WH_100_100)
    .padding({ right : 5 })
  }
}

@Component
export struct BrowserTabs {
  @Link browser!: Browser;
  @State tabButtonIndex: number = - 1;

  build() {
    Flex({ direction : FlexDirection.Row , alignItems : ItemAlign.Start }) {
      ForEach(this.browser.webArray , (item: WebKey) => {
        Row() {
          Row() {
            Text("网页")
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.WH_100_100)
          .flexShrink(1)
          .justifyContent(FlexAlign.Center)

          Button({ type : ButtonType.Normal }) {
            Image($r('app.media.ic_public_cancel_filled')).width(24).height(24)
          }
          .backgroundColor(this.tabButtonIndex == item.key ? DOWN_COLOR : '#00000000')
          .id('cancelBtn')
          .margin({ right : 2 })
          .width(33)
          .height(33)
          .borderRadius(5)
          .onTouch((event: TouchEvent) => {
            if ( event.type === TouchType.Down ) {
              this.tabButtonIndex = item.key
            } else if ( event.type == TouchType.Up ) {
              this.tabButtonIndex = - 1
            }
          })
          .onClick((event: ClickEvent) => {
            if ( this.browser.webArray.length > 1 ) {
              this.browser.deleteTab(item.key)
            }
          })
        }
        .width(180)
        .height(ConfigData.WH_100_100)
        .backgroundColor(this.browser.tabArrayIndex == item.key ? '#ffffff' : '#ececec')
        .onClick((event: ClickEvent) => {
          console.log(TAG , `key= ${ item.key }`)
          this.browser.setTabArrayIndex(item.key)
          this.browser.tabsController.changeIndex(item.key)
        })

        Divider().vertical(true).color('#c6c6c6')
      } , (item: WebKey) => item.timestamp.toString())
    }.height(33).flexShrink(0).backgroundColor('#ececec')
  }
}

@Component
export struct WebTab {
  @Link browser: Browser;
  @Link isPhone: boolean;
  @State progressStartTime: number = 0;
  @State progressEndTime: number = 0;
  @State progressCostTime: number = 0;
  @State pageStartTime: number = 0;
  @State pageEndTime: number = 0;
  @State pageCostTime: number = 0;
  @State Time: number = 11
  @State fileData: string = "";
  @State onPageBeginNumber: number = 0
  @State onPageEndNumber: number = 0
  @State onProgressChangeNumber: number = 0
  @StorageLink("openWebNumbers") openWebNumbers: number = 0
  @StorageLink("fsFile") file: fs.File | null = null
  isRegistered: boolean = false
  testObj: TestObject = {
    test : (addr: string) => {
      console.log(TAG , `addr= ${ this.browser.tabArrayIndex }`)
      this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.loadUrl({ url : `https://${ addr }` })
    } ,
    searchWord : (word: string) => {
      console.log(`search word= ${ word }`)
      let code = encodeURI(word)
      this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.loadUrl({
        url : `https://www.bing.com/search?q=${ code }`
      })
    }
  }

  build() {
    Tabs({ barPosition : BarPosition.Start , controller : this.browser.tabsController }) {
      ForEach(this.browser.webArray , (item: WebKey) => {
        TabContent() {
          Web({
            src : this.isPhone ? $rawfile('phone.html') : $rawfile('pad.html') ,
            controller : this.browser.webControllerArray[ item.key ] !== undefined ?
            this.browser.webControllerArray[ item.key ].controller : undefined
          })
            .javaScriptAccess(true)
            .fileAccess(true)
            .domStorageAccess(true)
            .userAgent(this.isPhone ? PHONE_USER_AGENT : PAD_USER_AGENT)
            .onPageBegin((event: EventOnPage) => {
              console.log(TAG , `onPageBegin= ${ JSON.stringify(event) }`)
              this.pageStartTime = new Date().getTime()
              console.log(TAG , "onPageBegin,开始加载页面,开始时间：" + this.pageStartTime)
              this.browser.loadingStatus = LoadingStatus.LOADING
            })
            .onPageEnd((event: EventOnPage) => {
              console.log(TAG , `onPageEnd= ${ JSON.stringify(event) }`)
              this.pageEndTime = new Date().getTime()
              console.log(TAG , "onPageEnd,结束加载页面,开始时间：" + this.pageEndTime)
              this.pageCostTime = this.pageEndTime - this.pageStartTime
              console.log(TAG , "onPageEnd,加载页面耗时：" + this.pageCostTime)

              if ( item.key < this.browser.webControllerArray.length && this.browser.webControllerArray[ item.key ].controller ) {
                this.browser.webControllerArray[ item.key ].controller.runJavaScript({ script : 'adapterDevice()' })
                this.browser.loadingStatus = LoadingStatus.END
                this.registerFunc(this.browser.webControllerArray[ item.key ])
                if ( event.url.startsWith('http') ) {
                  this.browser.inputValue = event.url
                } else {
                  this.browser.inputValue = ''
                }
              }
            })
            .onProgressChange((event: EventOnProgress) => {
              this.openWebNumbers = AppStorage.get("openWebNumbers") ! //非空断言操作符
              console.log(TAG , `onProgressChange`)
              this.browser.progress = event.newProgress
              console.log(TAG , `onProgressChange,progress:` + this.browser.progress)
              if ( this.browser.progress === 10 ) {
                this.progressStartTime = new Date().getTime()
                console.log(TAG , "onProgressChange,开始加载页面,开始时间：" + timestampToDate(this.progressStartTime))
                let currentTime3: string = timestampToDateFormat(this.progressStartTime)
                this.fileData = currentTime3 + " 第" + (this.openWebNumbers + 1) + "次onProgressChange,开始加载页面,时间：" + timestampToDate(this.progressStartTime) + "\n"
                this.fileData += currentTime3 + " onProgressChange: loading website: " + this.browser.progress + "%" + "\n"
                fs.writeSync(this.file!.fd , this.fileData);
              } else if ( this.browser.progress === 100 ) {
                this.progressEndTime = new Date().getTime()
                this.browser.hideProgress = true
                this.progressCostTime = this.progressEndTime - this.progressStartTime
                let currentTime4: string = timestampToDateFormat(this.progressEndTime)
                this.openWebNumbers = AppStorage.get("openWebNumbers") ! //非空断言操作符
                this.fileData = currentTime4 + " onProgressChange: loading website: " + this.browser.progress + "%" + "\n"
                this.fileData += currentTime4 + " onPageFinished loadUrl finish" + "\n"
                this.fileData += currentTime4 + " 第" + (this.openWebNumbers + 1) + "次onProgressChange,结束加载页面,时间：" + timestampToDate(this.progressEndTime) + "\n"
                this.fileData += currentTime4 + " 第" + (this.openWebNumbers + 1) + "次onProgressChange,加载页面耗时：" + this.progressCostTime + "ms" + "\n"
                fs.writeSync(this.file!.fd , this.fileData);
                console.log(TAG , "onProgressChange,结束加载页面,时间：" + this.progressEndTime)
                console.log(TAG , "onProgressChange,加载页面耗时：" + this.progressCostTime)
              } else {
                let time5: number = new Date().getTime()
                let currentTime5: string = timestampToDateFormat(time5)
                this.fileData = currentTime5 + " onProgressChange: loading website: " + this.browser.progress + "%" + "\n"
                fs.writeSync(this.file!.fd , this.fileData);
                this.browser.hideProgress = false
              }
            })
        }
      } , (item: WebKey) => item.timestamp.toString())
    }
    .barHeight(0)
    .scrollable(false)
  }

  registerFunc(webObject: WebObject) {
    if ( !webObject.isRegistered ) {
      console.log(TAG , `registerFunc`)
      webObject.controller.registerJavaScriptProxy({
        object : this.testObj , name : 'etsObj' , methodList : [ 'test', 'searchWord' ]
      })
      webObject.isRegistered = true
      webObject.controller.refresh()
    }
  }
}

export function timestampToDate(timestamp: number): string {
  const date = new Date(timestamp);
  let hours: string | number = date.getHours();
  hours = hours >= 10 ? hours : ('0' + hours);
  let minutes: string | number = date.getMinutes();
  minutes = minutes >= 10 ? minutes : ('0' + minutes);
  let seconds: string | number = date.getSeconds();
  seconds = seconds >= 10 ? seconds : ('0' + seconds);
  let milliSeconds: string | number = date.getMilliseconds();
  milliSeconds = milliSeconds >= 10 ? (milliSeconds >= 100 ? milliSeconds : ('0' + milliSeconds)) : ('00' + milliSeconds);
  return `${ hours }:${ minutes }:${ seconds }.${ milliSeconds }`;
}

export function timestampToDateFormat(timestamp: number): string {
  const date = new Date(timestamp);
  let year = date.getFullYear();
  let month: string | number = date.getMonth() + 1;
  month = month >= 10 ? month : ('0' + month);
  let day: string | number = date.getDate();
  day = day >= 10 ? day : ('0' + day);
  let hours: string | number = date.getHours();
  hours = hours >= 10 ? hours : ('0' + hours);
  let minutes: string | number = date.getMinutes();
  minutes = minutes >= 10 ? minutes : ('0' + minutes);
  let seconds: string | number = date.getSeconds();
  seconds = seconds >= 10 ? seconds : ('0' + seconds);
  let milliSeconds: string | number = date.getMilliseconds();
  milliSeconds = milliSeconds >= 10 ? (milliSeconds >= 100 ? milliSeconds : ('0' + milliSeconds)) : ('00' + milliSeconds);
  return `${ year }-${ month }-${ day }·${ hours }:${ minutes }:${ seconds }.${ milliSeconds }·`;
}