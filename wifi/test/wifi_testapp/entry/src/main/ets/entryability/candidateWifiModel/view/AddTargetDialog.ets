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

import wifiManager from '@ohos.wifiManager';
import ConfigData from '../../../utils/ConfigData';
import { CommonConstants } from '../common/constant/CommonConstant';

@CustomDialog
export default struct AddTargetDialog {
  @State wifiCandidateConfig: wifiManager.WifiDeviceConfig = {
    ssid : "TP-LINK_6365" ,
    bssid : "6C:B1:58:75:63:65" ,
    preSharedKey : "12345678" ,
    isHiddenSsid : false ,
    securityType : 3
  }
  private controller: CustomDialogController;
  onClickOk!: (value: Object) => void;

  build() {
    Column() {
      Text($r('app.string.input_candidate_wifi'))
        .width(CommonConstants.FULL_WIDTH)
        .fontSize($r('app.float.secondary_title'))
        .fontWeight(CommonConstants.FONT_WEIGHT)
        .fontColor($r('app.color.title_black_color'))
        .textAlign(TextAlign.Start)
      Scroll() {
        Column() {
          Row() {
            Text("ssid").fontSize($r('app.float.font_18')).width("18%")
            TextInput({ placeholder : $r('app.string.input_candidate_wifi_ssid') })
              .placeholderColor(Color.Grey)
              .placeholderFont({ size : $r('app.float.font_16') })
              .caretColor(Color.Blue)
              .width(ConfigData.WH_80_100)
              .fontSize($r('app.float.font_16'))
              .fontColor($r('app.color.title_black_color'))
              .onChange((value: string) => {
                this.wifiCandidateConfig.ssid = value;
              })
          }
          .width(CommonConstants.FULL_WIDTH)
          .margin({ top : CommonConstants.DIALOG_INPUT_MARGIN })
          // .height( CommonConstants.TEXT_INPUT_HEIGHT )
          // .backgroundColor( $r( 'app.color.input_background' ) )
          Row() {
            Text("bssid").fontSize($r('app.float.font_18')).width("18%")
            TextInput({ placeholder : $r('app.string.input_candidate_wifi_bssid') })
              .placeholderColor(Color.Grey)
              .placeholderFont({ size : $r('app.float.font_16') })
              .caretColor(Color.Blue)
              .width(ConfigData.WH_80_100)
              .fontSize($r('app.float.font_16'))
              .fontColor($r('app.color.title_black_color'))
              .onChange((value: string) => {
                this.wifiCandidateConfig.bssid = value;
              })
          }
          .width(CommonConstants.FULL_WIDTH)
          .margin({ top : CommonConstants.DIALOG_INPUT_MARGIN })
          // .height( CommonConstants.TEXT_INPUT_HEIGHT )
          // .backgroundColor( $r( 'app.color.input_background' ) )

          Row() {
            Text("preSharedKey").fontSize($r('app.float.font_16')).width("28%")
            TextInput({ placeholder : $r('app.string.input_candidate_wifi_preSharedKey') })
              .placeholderColor(Color.Grey)
              .placeholderFont({ size : $r('app.float.font_16') })
              .caretColor(Color.Blue)
              .width(ConfigData.WH_70_100)
              .fontSize($r('app.float.font_16'))
              .fontColor($r('app.color.title_black_color'))
              .onChange((value: string) => {
                this.wifiCandidateConfig.preSharedKey = value;
              })
          }
          .width(CommonConstants.FULL_WIDTH)
          .margin({ top : CommonConstants.DIALOG_INPUT_MARGIN })
          // .height( CommonConstants.TEXT_INPUT_HEIGHT )
          // .backgroundColor( $r( 'app.color.input_background' ) )

          Row() {
            Text("isHiddenSsid").fontSize($r('app.float.font_16')).width("28%")
            TextInput({ placeholder : $r('app.string.input_candidate_wifi_isHiddenSsid') })
              .placeholderColor(Color.Grey)
              .placeholderFont({ size : $r('app.float.font_16') })
              .caretColor(Color.Blue)
              .width(ConfigData.WH_70_100)
              .fontSize($r('app.float.font_16'))
              .fontColor($r('app.color.title_black_color'))
              .onChange((value: string) => {
                this.wifiCandidateConfig.preSharedKey = value;
              })
          }
          .width(CommonConstants.FULL_WIDTH)
          .margin({ top : CommonConstants.DIALOG_INPUT_MARGIN })
          // .height( CommonConstants.TEXT_INPUT_HEIGHT )
          // .backgroundColor( $r( 'app.color.input_background' ) )

          Row() {
            Text("securityType").fontSize($r('app.float.font_16')).width("28%")
            Column() {
              Select([
                { value : 'WIFI_SEC_TYPE_INVALID' },
                { value : 'WIFI_SEC_TYPE_OPEN' },
                { value : 'WIFI_SEC_TYPE_WEP' },
                { value : 'WIFI_SEC_TYPE_PSK' },
                { value : 'WIFI_SEC_TYPE_SAE' }
              ])
                .fontColor($r('app.color.title_black_color'))
                .optionBgColor($r('app.color.input_background'))
                .selectedOptionBgColor($r('app.color.input_background'))
                .selectedOptionFontColor($r('app.color.input_background'))
                .selected(3)
                .value('WIFI_SEC_TYPE_PSK')
                .font({ size : 16 })
                .selectedOptionFont({ size : 17 })
                .optionFont({ size : 15 })
                .width(ConfigData.WH_100_100)
                .onSelect((index: number) => {
                  this.wifiCandidateConfig.securityType = index;
                })
            }
            .width(ConfigData.WH_70_100)
            .borderRadius(1)
          }
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
          .width(CommonConstants.FULL_WIDTH)
          .margin({ top : CommonConstants.DIALOG_INPUT_MARGIN })

          Blank()
          Row() {
            Button($r('app.string.cancel_button'))
              .dialogButtonStyle()
              .onClick(() => {
                this.controller.close();
              })
              .height(CommonConstants.FULL_HEIGHT)
            Divider()
              .vertical(true)
            Button($r('app.string.confirm_button'))
              .dialogButtonStyle()
              .onClick(() => {
                this.onClickOk(this.wifiCandidateConfig);
              })
              .height(CommonConstants.FULL_HEIGHT)
          }
          .width(CommonConstants.DIALOG_OPERATION_WIDTH)
          .height(CommonConstants.DIALOG_OPERATION_HEIGHT)
          .justifyContent(FlexAlign.SpaceBetween)
        }
      }
      .scrollBarWidth(10)
      .scrollBar(BarState.Auto)
    }
    .padding($r('app.float.distance_24'))
    .width(CommonConstants.DIALOG_WIDTH)
    .borderRadius(CommonConstants.DIALOG_BORDER_RADIUS)
    .backgroundColor(Color.White)
  }
}

/**
 * Custom button style.
 */
@Extend(Button) function dialogButtonStyle() {
  .fontSize($r('app.float.font_16'))
  .height($r('app.float.dialog_btn_height'))
  .width($r('app.float.dialog_btn_width'))
  .backgroundColor(Color.White)
  .fontColor($r('app.color.main_blue'))
}