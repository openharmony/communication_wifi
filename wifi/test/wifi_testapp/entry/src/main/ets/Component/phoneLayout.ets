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
import { Browser } from '../entryability/model/bowser';
import { WebTab } from './webTitleBar';
import ConfigData from '../Utils/ConfigData'

const TAG: string = '[PhoneLayout]';
const BUTTON_WIDTH: number = 22;
const BUTTON_RADIUS: number = 4;
const DOWN_COLOR: string = '#e4e4e4';
const UP_COLOR: string = '#00000000';

interface ImageSrcId {
  imageSrc: Resource,
  id: number
}

@Component
export struct PhoneLayout {
  @Link browser: Browser;
  @State isPhone: boolean = true;
  @State hasDown: boolean = false;
  @State pageCount: string = '1';
  @State arrayIndex: number = 0;
  private addr: string = '';
  private toolPoneArray: Array<ImageSrcId> = [
    {
      imageSrc : $r('app.media.ic_public_back') ,
      id : 1
    },
    {
      imageSrc : $r('app.media.ic_public_advance') ,
      id : 2
    },
    {
      imageSrc : $r('app.media.ic_public_home') ,
      id : 5
    },
    {
      imageSrc : $r('app.media.ic_public_refresh') ,
      id : 3
    }
  ];

  @Builder ToolBar() {
    Column() {
      if ( !this.browser.hideProgress ) {
        Progress({ value : this.browser.progress , total : 100 })
          .color('#0000ff')
      }
      Row() {
        ForEach(this.toolPoneArray , (item: ImageSrcId , index: number) => {
          Column() {
            Divider().color('#e9eaec')
            Button({ type : ButtonType.Normal }) {
              Column() {
                if ( item.id !== 4 ) {
                  Image(item.imageSrc)
                } else {
                  Column() {
                    Text(this.pageCount)
                      .fontSize(16)
                  }
                  .border({ width : 2 })
                  .width(22)
                  .height(22)
                  .borderRadius(5)
                  .justifyContent(FlexAlign.Center)
                }
              }
              .width(BUTTON_WIDTH)
              .height(BUTTON_WIDTH)
              .justifyContent(FlexAlign.Center)
            }
            .height(ConfigData.WH_100_100)
            .width(ConfigData.WH_100_100)
            .backgroundColor(this.arrayIndex === item.id ? DOWN_COLOR : UP_COLOR)
            .borderRadius(BUTTON_RADIUS)
            .flexShrink(0)
            .onTouch((event: TouchEvent) => {
              if ( event.type === TouchType.Down ) {
                this.arrayIndex = item.id;
              } else if ( event.type === TouchType.Up ) {
                this.arrayIndex = 0;
              }
            })
            .onClick((event: ClickEvent) => {
              switch ( item.id ) {
                case 1:
                  this.browser.Back();
                  break;
                case 2:
                  this.browser.Forward();
                  break;
                case 3:
                  this.browser.Refresh();
                  break;
                case 5:
                  this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.loadUrl({
                    url : $rawfile('phone.html')
                  });
                  break;
                default:
                  break;
              }
            })
          }
          .width(ConfigData.WH_20_100)
          .id(`navigationButton${ index }`)
        })
      }
      .justifyContent(FlexAlign.SpaceAround)
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_100_100)
      .backgroundColor('#fdfdfd')
    }
    .height(ConfigData.WH_100_100)
  }

  @Builder TitleBar() {
    Flex({ justifyContent : FlexAlign.SpaceBetween , alignItems : ItemAlign.Center }) {
      Column() {
        TextInput({ placeholder : $r('app.string.Input_url') , text : this.browser.inputValue })
          .placeholderFont({ size : 16 , weight : 500 })
          .fontSize(16)
          .height(34)
          .margin({ left : 6 })
          .id('inputUrl')
          .onChange((value: string) => {
            console.log(TAG , `onChange`);
            this.addr = value;
          })
          .onSubmit((enterKey: EnterKeyType) => {
            console.log(TAG , `onSubmit`);
            this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.loadUrl({
              url : `https://${ this.addr }`
            });
            this.addr = '';
          })
      }

      Column() {
        Button({ type : ButtonType.Normal }) {
          Image($r('app.media.submit'))
        }
        .width(BUTTON_WIDTH)
        .height(BUTTON_WIDTH)
        .backgroundColor(this.hasDown ? DOWN_COLOR : UP_COLOR)
        .margin({ top : 6 })
        .id(`actionButton0`)
      }
      .width(ConfigData.WH_10_100)
      .height(34)
      .flexShrink(0)
      .backgroundColor(this.hasDown ? DOWN_COLOR : UP_COLOR)
      .borderRadius(BUTTON_RADIUS)
      .margin({ left : 6 , right : 6 })
      .onTouch((event: TouchEvent) => {
        if ( event.type === TouchType.Down ) {
          this.hasDown = true;
        } else if ( event.type === TouchType.Up ) {
          this.hasDown = false;
        }
      })
      .onClick((event: ClickEvent) => {
        this.browser.loadUrl(this.addr);
        this.addr = '';
      })
    }
    .position({ x : 0 , y : 3 })
  }

  build() {
    Column() {
      Navigation() {
        WebTab({ browser : $browser , isPhone : $isPhone }).height(ConfigData.WH_100_100)
      }
      // .title({ builder: this.TitleBar, height: 40 })
      .toolBar(this.ToolBar)
      .hideBackButton(true)
    }
    .height(ConfigData.WH_100_100)
  }
}