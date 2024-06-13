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

import TaskItemBean from '../common/bean/TaskItemBean';
import TargetListItem from './TargetListItem';
import { CommonConstants } from '../common/constant/CommonConstant';
import DataModel from '../viewmodel/DataModel';

@Component
export default struct TargetList {
  @Consume overAllProgressChanged: boolean;
  @State isEditMode: boolean = false;
  @State selectArray: Array<boolean> = [];
  @State clickIndex: number = CommonConstants.DEFAULT_CLICK_INDEX;
  @State selectAll: boolean = false;
  @Link targetData: Array<TaskItemBean>;
  onAddClick!: () => void;

  build() {
    Column() {
      Row() {
        Text($r('app.string.sub_goals'))
          .fontSize($r('app.float.secondary_title'))
          .fontWeight(CommonConstants.FONT_WEIGHT_LARGE)
          .fontColor($r('app.color.title_black_color'))
        Blank()
        if ( this.targetData.length > 0 ) {
          if ( this.isEditMode ) {
            Text($r('app.string.cancel_button'))
              .operateTextStyle($r('app.color.main_blue'))
              .margin({ left : $r('app.float.distance_16') })
              .onClick(() => {
                this.selectAll = false;
                this.isEditMode = false;
                this.selectAllOrCancel(false);
              })
            Text($r('app.string.select_all_button'))
              .operateTextStyle($r('app.color.main_blue'))
              .margin({
                left : $r('app.float.distance_16')
              })
            Checkbox()
              .select(this.isSelectAll())
              .selectedColor($r('app.color.main_blue'))
              .width(CommonConstants.CHECKBOX_WIDTH)
              .onClick(() => {
                this.selectAll = !this.selectAll;
                this.selectAllOrCancel(this.selectAll);
              })
          } else {
            Text($r('app.string.edit_button'))
              .operateTextStyle($r('app.color.main_blue'))
              .onClick(() => {
                this.isEditMode = true;
                this.selectAllOrCancel(false);
              })
          }
        }
      }
      .width(CommonConstants.FULL_WIDTH)
      .height($r('app.float.wh_value_30'))
      .padding({
        left : $r('app.float.distance_16') ,
        right : $r('app.float.distance_11')
      })

      List({ space : CommonConstants.LIST_SPACE }) {
        ForEach(this.targetData , (item: TaskItemBean , index: number) => {
          ListItem() {
            TargetListItem({
              taskItem : item ,
              index : index ,
              selectArr : $selectArray ,
              isEditMode : this.isEditMode ,
              clickIndex : $clickIndex
            })
          }
        } , (item: TaskItemBean , index) => JSON.stringify(item) + index)
      }
      .edgeEffect(EdgeEffect.None)
      .margin({ top : $r('app.float.distance_12') })
      .width(CommonConstants.FULL_WIDTH)
      .height(CommonConstants.LIST_HEIGHT)

      Blank()
        .width(CommonConstants.FULL_WIDTH)
        .height(CommonConstants.DIALOG_OPERATION_HEIGHT)
      if ( this.isEditMode ) {
        Button($r('app.string.delete_button'))
          .opacity(this.isSelectRows() ? CommonConstants.NO_OPACITY : CommonConstants.OPACITY)
          .enabled(this.isSelectRows() ? true : false)
          .operateButtonStyle($r('app.color.main_red'))
          .onClick(() => {
            this.deleteSelected();
            this.selectAllOrCancel(false);
            this.selectAll = false;
          })
      } else {
        Button($r('app.string.add_task'))
          .operateButtonStyle($r('app.color.main_blue'))
          .onClick(() => this.onAddClick())
      }
    }
    .width(CommonConstants.MAIN_BOARD_WIDTH)
    .height(CommonConstants.LIST_BOARD_HEIGHT)
    .padding({ top : $r('app.float.distance_16') })
  }

  /**
   * Check whether there are selected rows.
   */
  isSelectRows(): boolean {
    return this.selectArray.filter((selected: boolean) => selected === true).length !== 0;
  }

  /**
   * Whether to select all.
   */
  isSelectAll(): boolean {
    if ( this.selectArray.length === 0 ) {
      return false;
    }
    let deSelectCount = this.selectArray.filter(selected => selected === false).length;
    if ( deSelectCount === 0 ) {
      this.selectAll = true;
      return true;
    }
    this.selectAll = false;
    return false;
  }

  /**
   * Select or deselect all.
   *
   * @param selectStatus true: Select all. Otherwise, deselect all.
   */
  selectAllOrCancel(selectStatus: boolean) {
    let newSelectArray: Array<boolean> = []
    this.targetData.forEach(() => {
      newSelectArray.push(selectStatus);
    });
    this.selectArray = newSelectArray;
  }

  /**
   * Delete the selected item and exit the editing mode.
   */
  deleteSelected() {
    DataModel.deleteData(this.selectArray);
    this.targetData = DataModel.getData();
    this.overAllProgressChanged = !this.overAllProgressChanged;
    this.isEditMode = false;
  }
}

/**
 * Custom text button style.
 */
@Extend(Text) function operateTextStyle(color: Resource) {
  .fontSize($r('app.float.font_16'))
  .fontColor(color)
  .lineHeight($r('app.float.wh_value_19'))
  .fontWeight(CommonConstants.FONT_WEIGHT)
}

/**
 * Custom button style.
 */
@Extend(Button) function operateButtonStyle(color: Resource) {
  .width($r('app.float.button_width'))
  .height($r('app.float.button_height'))
  .fontSize($r('app.float.font_16'))
  .fontWeight(CommonConstants.FONT_WEIGHT)
  .fontColor(color)
  .backgroundColor($r('app.color.button_background'))
}