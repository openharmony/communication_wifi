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

// @ts-nocheck
import ConfigData from '../utils/ConfigData';
import { TestData , TestApi } from '../entryability/model/testData'
import prompt from '@system.prompt';

const TAG = "[stressContentTable]"
/**
 *  ContentTable Component Page Of Wifi test
 */

@CustomDialog
export struct GetProfileConnSateDialog {
  private hitText: string
  private getProfileList: [] = [
    { value : 'A2DP_SOURCE' },
    { value : 'HANDS_FREE_AUDIO_GATEWAY' },
    { value : 'HID_HOST' }
  ]
  @State currentClick: Number = 1;
  @Link textValue: string
  @Link inputValue: string
  @Link apiItem: TestApi
  @Link currentIndex: Number
  @Link changeIndex: Number
  controller: CustomDialogController
  cancel: () => void
  confirm: ( string ) => void

  build() {
    Column() {
      Text( this.hitText )
        .fontSize( 20 )
        .margin( { top : 10 , bottom : 10 } )
      Select( this.getProfileList )
        .selected( this.currentClick )
        .value( this.getProfileList[ this.currentClick ].value )
        .font( { size : 20 } )
        .selectedOptionFont( { size : 20 } )
        .optionFont( { size : 17 } )
        .height( 80 )
        .width( ConfigData.WH_90_100 )
        .onSelect( ( index: Number ) => {
          console.log( "Select:" + index )
          this.currentClick = index
        } )

      Flex( { justifyContent : FlexAlign.SpaceAround } ) {
        Button( '取消' )
          .onClick( () => {
            this.controller.close()
            this.cancel()
          } )
          .backgroundColor( 0xffffff ).fontColor( Color.Black )
        Button( '确认' )
          .onClick( () => {
            this.inputValue = this.currentClick
            this.changeIndex = this.currentIndex
            //TODO: 设备调试时候需要打开
            if ( true ) {
              let message = ""
              message = this.apiItem.api( this.currentClick , this.pairedMac )
              this.apiItem.result = this.getProfileList[ this.currentClick ].value + "状态:" + message
              console.log( TAG , "this.apiItem.result:" + this.apiItem.result )
            } else {
              let message = ""
              this.apiItem.result = this.getProfileList[ this.currentClick ].value
              console.log( TAG , "this.apiItem.result:" + this.apiItem.result )
            }
            this.controller.close()
            this.confirm( this.inputValue )
          } )
          .backgroundColor( 0xffffff ).fontColor( Color.Red )
      }
      .margin( { bottom : 10 } )
    }
  }
}

@CustomDialog
export struct SetScanModeDialog {
  private hitText: string
  private scanModeList: [] = [
    { value : 'SCAN_MODE_NONE' },
    { value : 'CONNECTABLE' },
    { value : 'GENERAL_DISCOVERABLE' },
    { value : 'LIMITED_DISCOVERABLE' },
    { value : 'CONNECTABLE_GENERAL_DISCOVERABLE' },
    { value : 'CONNECTABLE_LIMITED_DISCOVERABLE' }
  ]
  @State currentClick: Number = 4;
  @Link textValue: string
  @Link inputValue: string
  @Link apiItem: TestApi
  @Link currentIndex: Number
  @Link changeIndex: Number
  @State duration: Number = 0
  controller: CustomDialogController
  cancel: () => void
  confirm: ( string ) => void

  build() {
    Column() {
      Text( this.hitText )
        .fontSize( 20 )
        .margin( { top : 10 , bottom : 10 } )
      Select( this.scanModeList )
        .selected( this.currentClick )
        .value( this.scanModeList[ this.currentClick ].value )
        .font( { size : 12 } )
        .selectedOptionFont( { size : 12 } )
        .optionFont( { size : 12 } )
        .height( 60 )
        .width( ConfigData.WH_90_100 )
        .onSelect( ( index: Number ) => {
          console.log( TAG , "Select:" + index )
          this.currentClick = index
        } )
      TextInput( {
        placeholder : '请输入延迟时间' ,
        text : this.duration.toString() ,
        type : InputType.Number ,
      } )
        .height( 60 ).width( ConfigData.WH_90_100 )
        .onChange( ( value: string ) => {
          if ( value == "" ) {
            this.duration = 0
          } else {
            this.duration = parseInt( value ) == nil ? 0 : parseInt( value )
          }
        } )
      Flex( { justifyContent : FlexAlign.SpaceAround } ) {
        Button( '取消' )
          .onClick( () => {
            this.controller.close()
            this.cancel()
          } )
          .backgroundColor( 0xffffff ).fontColor( Color.Black )
        Button( '确认' )
          .onClick( () => {
            this.inputValue = this.currentClick
            this.changeIndex = this.currentIndex
            //TODO: 设备调试时候需要打开
            if ( true ) {
              let message = {}
              message = this.apiItem.api( this.currentClick , this.duration )
              //              this.apiItem.result = message.mod.toString() + message.duration.toString()
              this.apiItem.result = "类型:" + this.scanModeList[ message.mod ].value + "延迟:" + message.duration.toString()
              console.log( TAG , "this.apiItem.result:" + this.apiItem.result )
            } else {
              let message = ""
              this.apiItem.result = this.scanModeList[ this.currentClick ].value
              console.log( TAG , "this.apiItem.result:" + this.apiItem.result )
            }
            this.controller.close()
            this.confirm( this.inputValue )
          } )
          .backgroundColor( 0xffffff )
          .fontColor( Color.Red )
      }
      .margin( { bottom : 10 } )
    }
  }
}

@CustomDialog
export struct InputDialog {
  private hitText: string
  @Link textValue: string
  @Link inputValue: string
  @Link apiItem: TestApi
  @Link currentIndex: Number
  @Link changeIndex: Number
  controller: CustomDialogController
  cancel: () => void
  confirm: ( string ) => void

  build() {
    Column() {
      Text( this.hitText )
        .fontSize( 20 )
        .margin( { top : 10 , bottom : 10 } )
      TextInput( { placeholder : '' , text : this.textValue } )
        .height( 60 )
        .width( ConfigData.WH_90_100 )
        .onChange( ( value: string ) => {
          this.textValue = value
        } )

      Flex( { justifyContent : FlexAlign.SpaceAround } ) {
        Button( '取消' )
          .onClick( () => {
            this.controller.close()
            this.cancel()
          } )
          .backgroundColor( 0xffffff ).fontColor( Color.Black )
        Button( '确认' )
          .onClick( () => {
            this.inputValue = this.textValue
            this.changeIndex = this.currentIndex
            //TODO: 设备调试时候需要打开
            let message = ""
            if ( true ) {
              message = this.apiItem.api( this.textValue )
              this.apiItem.result = message
            } else {
              this.apiItem.result = this.textValue
            }
            this.controller.close()
            this.confirm( this.inputValue )
          } )
          .backgroundColor( 0xffffff ).fontColor( Color.Red )
      }
      .margin( { bottom : 10 } )
    }
  }
}

/**
 * ContentTable
 */
@Component
export struct StressContentTable {
  private testItem: TestData
  @State currentApiItem: TestApi = {}
  @State apiItems: TestApi[] = [];
  @State changeIndex: Number = - 1
  @State localName: string = 'DaYuBlue1'
  @State currentIndex: Number = 1
  @StorageLink( 'pairedMac' ) pairedMac: string = "";
  getProfileConnSateDialog: CustomDialogController = new CustomDialogController({
    builder : GetProfileConnSateDialog( {
      hitText : "请设置配置类型" ,
      cancel : this.onCancel ,
      confirm : this.onAccept ,
      textValue : $localName ,
      inputValue : $localName ,
      currentIndex : $currentIndex ,
      apiItem : $currentApiItem ,
      changeIndex : $changeIndex ,
    } ) ,
    cancel : this.onCancel() ,
    autoCancel : true
  })
  setScanModelDialog: CustomDialogController = new CustomDialogController({
    builder : SetScanModeDialog( {
      hitText : "请设置扫描模式" ,
      cancel : this.onCancel ,
      confirm : this.onAccept ,
      textValue : $localName ,
      inputValue : $localName ,
      currentIndex : $currentIndex ,
      apiItem : $currentApiItem ,
      changeIndex : $changeIndex ,
    } ) ,
    cancel : this.onCancel() ,
    autoCancel : true
  })
  inputDialog: CustomDialogController = new CustomDialogController({
    builder : InputDialog( {
      hitText : "请设置本地名称" ,
      cancel : this.onCancel ,
      confirm : this.onAccept ,
      textValue : $localName ,
      inputValue : $localName ,
      currentIndex : $currentIndex ,
      apiItem : $currentApiItem ,
      changeIndex : $changeIndex ,
    } ) ,
    cancel : this.onCancel() ,
    autoCancel : true
  })

  onCancel() {
    console.log( '取消' )
  }

  onAccept( text: string ) {
    console.log( 'input text:' , text )
  }

  @Builder IngredientItem( apiItem: TestApi , index: Number ) {
    Stack() {
      Flex() {
        Flex( { alignItems : ItemAlign.Center } ) {
          Image( $r( 'app.media.WLAN' ) )
            .objectFit( ImageFit.Contain )
            .autoResize( false )
            .height( 30 )
            .width( 30 )
        }
        .layoutWeight( 1 )
        .padding( { left : 10 } )

        Flex( { direction : FlexDirection.Column , alignItems : ItemAlign.Start } ) {
          Text( apiItem.name )
            .fontSize( 17.4 )
            .fontWeight( FontWeight.Bold )
            .layoutWeight( 1 )
            .padding( { left : 10 , top : 15 } )
          Text( apiItem.method )
            .fontSize( 17.4 )
            .fontWeight( FontWeight.Bold )
            .layoutWeight( 1 )
            .padding( { left : 10 , top : 5 } )
        }
        .layoutWeight( 6 )
        .width( ConfigData.WH_80_100 )

        Flex( { alignItems : ItemAlign.Center } ) {
          Text( this.changeIndex >= 0 ? this.getCurrentState( index ) : apiItem.result )
            .fontSize( 17.4 )
            .flexGrow( 1 )
        }
        .layoutWeight( 3 )
        .padding( { left : 25 } )
      }
    }
    .height( 80 )
    .borderRadius( 10 )
    .margin( { top : 5 , bottom : 5 } )
    .backgroundColor( $r( "app.color.white" ) )
    .onClick( () => {
      switch ( apiItem.method ) {
        case "testScan": {
          let message = apiItem.api();
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast( { message : message } );
        }
        default: {
          let StartTime = new Date().getTime()
          for ( let indexNumber = 1 ; indexNumber < 101 ; indexNumber ++ ) {
            let message = apiItem.api();
            apiItem.result = message;
            prompt.showToast( { message : message } );
            this.currentIndex += 1;
            this.changeIndex = this.currentIndex;
            AppStorage.SetOrCreate( 'stressNumber' , indexNumber );
            console.log( TAG , apiItem.method + "indexNumber is ------: " + indexNumber );
          }
          let EndTime = new Date().getTime()
          console.log( TAG , "开始:" + Number( StartTime ) + "ms" )
          console.log( TAG , "结束:" + Number( EndTime ) + "ms" )
          console.log( TAG , "花费:" + Number( EndTime - StartTime ) + "ms" )
          let stressTime = EndTime - StartTime
          AppStorage.SetOrCreate( 'stressTime' , stressTime );
        }
          break;
      }
    } )
  }

  getCurrentState( index: Number ) {
    return this.apiItems[ index ].result
  }

  build() {
    Column() {
      Scroll() {
        Flex( {
          direction : FlexDirection.Column ,
          justifyContent : FlexAlign.SpaceBetween ,
          alignItems : ItemAlign.Start
        } ) {
          ForEach( this.apiItems , ( item: TestApi , index: Number ) => {
            this.IngredientItem( item , index )
          } )
        }
      }
      .scrollBarWidth( 20 )
    }
    .height( ConfigData.WH_60_100 )
    .padding( { top : 5 , right : 10 , left : 10 } )
  }
}