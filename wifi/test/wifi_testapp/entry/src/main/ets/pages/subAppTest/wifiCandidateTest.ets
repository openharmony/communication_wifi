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

import { TestData } from '../../entryability/model/testData'
import { WifiModel } from '../../entryability/model/wifiModel'
import ConfigData from '../../utils/ConfigData';
import wifiManager from '@ohos.wifiManager'
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { PageTitle } from '../../Component/pageTitle';
import TargetInformation from '../../entryability/candidateWifiModel/view/TargetInformation';
import TargetList from '../../entryability/candidateWifiModel/view/TargetList';
import { CommonConstants } from '../../entryability/candidateWifiModel/common/constant/CommonConstant';
import DataModel from '../../entryability/candidateWifiModel/viewmodel/DataModel';
import AddTargetDialog from '../../entryability/candidateWifiModel/view/AddTargetDialog';
import getCurrentTime from '../../entryability/candidateWifiModel/common/utils/DateUtil';
import TaskItemBean from '../../entryability/candidateWifiModel/common/bean/TaskItemBean';
import promptAction from '@ohos.promptAction';
import router from '@ohos.router';

interface myParams extends Object {
  testItem: TestData
}

const TAG = '[wifiCandidate]'

/**
 * wifi Found Test Page Of Wifi test
 */
@Entry
@Component
struct WifiCandidate {
  @State targetData: Array<TaskItemBean> = DataModel.getData();
  private wifiModel: WifiModel = new WifiModel()
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State totalTasksNumber: number = 0;
  @State completedTasksNumber: number = 0;
  @State latestUpdateDate: string = CommonConstants.DEFAULT_PROGRESS_VALUE;
  @Provide @Watch('onProgressChanged') overAllProgressChanged: boolean = false;
  dialogController: CustomDialogController = new CustomDialogController({
    builder : AddTargetDialog({
      onClickOk : this.saveTask.bind(this)
    }) ,
    alignment : DialogAlignment.Bottom ,
    offset : {
      dx : CommonConstants.DIALOG_OFFSET_X ,
      dy : $r('app.float.dialog_offset_y')
    } ,
    customStyle : true ,
    autoCancel : false
  });

  /**
   * Listening targetData.
   */
  onProgressChanged() {
    this.totalTasksNumber = this.targetData.length;
    this.completedTasksNumber = this.targetData.filter((item) => {
      return item.progressValue === CommonConstants.SLIDER_MAX_VALUE;
    }).length;
    this.latestUpdateDate = getCurrentTime();
  }

  aboutToAppear() {

  }

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Column() {
        TargetInformation({
          latestUpdateDate : this.latestUpdateDate ,
          totalTasksNumber : this.totalTasksNumber ,
          completedTasksNumber : this.completedTasksNumber
        })
        TargetList({
          targetData : $targetData ,
          onAddClick : (): void => this.dialogController.open()
        })
          .height(CommonConstants.FULL_HEIGHT)
      }
      .width(CommonConstants.FULL_WIDTH)
      .height(CommonConstants.LIST_BOARD_HEIGHT)
      .backgroundColor($r('app.color.index_background'))


      Column() {
        Row() {
          Button() {
            Text("添加候选网络")
              .width(ConfigData.WH_100_100)
              .height(ConfigData.WH_80_100)
          }
          .type(ButtonType.Normal)
          .width(ConfigData.WH_20_100)
          .height(ConfigData.WH_10_100)
          .backgroundColor($r("app.color.blue"))
          .padding({ left : "1vp" , top : "5vp" })
          .onClick(() => {
            // wifiManager.addCandidateConfig()
          })
          .margin({ left : "5vp" , right : "5vp" })

          Button() {
            Text("移除候选网络")
              .width(ConfigData.WH_100_100)
              .height(ConfigData.WH_80_100)
          }
          .type(ButtonType.Normal)
          .width(ConfigData.WH_20_100)
          .height(ConfigData.WH_10_100)
          .backgroundColor($r("app.color.blue"))
          .padding({ left : "1vp" , top : "5vp" })
          .onClick(() => {

          })
          .margin({ left : "5vp" , right : "5vp" })

          Button() {
            Text("获取候选网络配置")
              .width(ConfigData.WH_100_100)
              .height(ConfigData.WH_80_100)
          }
          .type(ButtonType.Normal)
          .width(ConfigData.WH_20_100)
          .height(ConfigData.WH_10_100)
          .backgroundColor($r("app.color.blue"))
          .padding({ left : "1vp" , top : "5vp" })
          .onClick(() => {

          })
          .margin({ left : "5vp" , right : "5vp" })

          Button() {
            Text("连接候选网络")
              .width(ConfigData.WH_100_100)
              .height(ConfigData.WH_80_100)
          }
          .type(ButtonType.Normal)
          .width(ConfigData.WH_20_100)
          .height(ConfigData.WH_10_100)
          .backgroundColor($r("app.color.blue"))
          .padding({ left : "1vp" , top : "5vp" })
          .onClick(() => {

          })
          .margin({ left : "5vp" , right : "5vp" })
        }
      }
    }
    .size({ width : ConfigData.WH_100_100 , height : ConfigData.WH_100_100 })
    .backgroundColor('#F5F5F5')
  }

  aboutToDisappear() {

  }

  /**
   * Save the progress value and update time after you click OK in the dialog box.
   *
   * @param context context from view.
   * @param value Latest Progress Value.
   */
  saveTask(wifiCandidateConfig: wifiManager.WifiDeviceConfig) {
    if ( wifiCandidateConfig.ssid === '' ) {
      promptAction.showToast({
        message : $r('app.string.cannot_input_empty') ,
        duration : CommonConstants.TOAST_TIME ,
        bottom : CommonConstants.TOAST_MARGIN_BOTTOM
      });
      return;
    }
    DataModel.addData(new TaskItemBean(wifiCandidateConfig.ssid , 0 , getCurrentTime()));
    this.targetData = DataModel.getData();
    this.overAllProgressChanged = this.overAllProgressChanged;
    this.dialogController.close();
  }
}
