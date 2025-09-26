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

import http from '@ohos.net.http';
import { TitleBar } from '../../Component/titleBar';
import ConfigData from '../../utils/ConfigData';
import { BusinessError } from '@ohos.base';

const TAG = 'wifiTestApp [httpSocketTest]';

/**
 * HTTP Test Page Of Wifi test
 */
@Entry
@Component
struct HttpSocketTest {
  @State selectIndex: number = 0;
  @State selectValue: string = 'GET';
  @State typeList: Array<SelectOption> = [
    { value: 'GET'},
    { value: 'POST'},
    { value: 'PUT'},
    { value: 'DELETE'},
    { value: 'TRACE'},
    { value: 'CONNECT'},
    { value: 'OPTIONS'}
  ];
  @State urlValue: string = 'http://www.baidu.com';
  @State reqSelectIndex: number = 0;
  @State reqSelectValue: string = 'none';
  @State reqTypeList: Array<SelectOption> = [
    { value: 'none'},
    { value: 'raw'}
  ];
  @State reqValue: string = '';
  @State resData: string = '';
  @State codeValue: string = '';
  @State isLoading: boolean = false;

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TitleBar({ detail: "HTTP验证" })
      }

      Column() {
        // HTTP请求配置区域
        Text('HTTP请求配置')
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ top: 10, bottom: 10 })

        Row() {
          Select(this.typeList)
            .selected(this.selectIndex)
            .value(this.selectValue)
            .font({ size: 12, weight: 300 })
            .fontColor('#182431')
            .selectedOptionFont({ size: 16, weight: 400 })
            .optionFont({ size: 16, weight: 400 })
            .menuAlign(MenuAlignType.START, {dx:0, dy:0})
            .borderRadius('5')
            .width("25%")
            .optionHeight(300)
            .onSelect((index:number, text?: string | undefined)=>{
              console.log(TAG, 'Select:' + index)
              this.selectIndex = index;
              if(text){
                this.selectValue = text;
                if (this.selectValue == 'GET') {
                  this.urlValue = 'http://www.baidu.com';
                  this.reqValue = '';
                } else if (this.selectValue == 'POST') {
                  this.urlValue = 'https://httpbin.org/post';
                  this.reqValue = '{"username": "test","password": "123"}';
                }
              }
            })
          TextInput({text:this.urlValue}).width('75%').borderRadius('5')
            .onChange((val: string) => {
              this.urlValue = val;
            })
        }
        .width('100%')
        .margin({bottom:10})

        // 请求体配置
        Text('请求体配置')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ bottom: 5 })

        Row() {
          Select(this.reqTypeList)
            .selected(this.reqSelectIndex)
            .value(this.reqSelectValue)
            .font({ size: 12, weight: 300 })
            .fontColor('#182431')
            .selectedOptionFont({ size: 16, weight: 400 })
            .optionFont({ size: 16, weight: 400 })
            .menuAlign(MenuAlignType.START, {dx:0, dy:0})
            .borderRadius('5')
            .width("25%")
            .optionHeight(300)
            .onSelect((index:number, text?: string | undefined)=>{
              console.log(TAG, 'Select:' + index)
              this.reqSelectIndex = index;
              if(text){
                this.reqSelectValue = text;
              }
            })
          TextInput({text:this.reqValue}).width('75%').borderRadius('5')
            .onChange((val: string) => {
              this.reqValue = val;
            })
        }
        .width('100%')
        .margin({bottom:15})

        // 发送按钮和清空按钮
        Row() {
          Button('发送请求')
            .width('45%')
            .backgroundColor(this.isLoading ? Color.Gray : Color.Blue)
            .enabled(!this.isLoading)
            .onClick(() => {
              this.sendHttpRequest();
            })

          Button('清空响应')
            .width('45%')
            .backgroundColor(Color.Orange)
            .onClick(() => {
              this.clearResponse();
            })
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        .margin({ bottom: 15 })

        // 响应状态
        if (this.codeValue) {
          Row() {
            Text('响应状态: ')
              .fontSize(16)
              .fontWeight(FontWeight.Bold)
            Text(this.codeValue)
              .fontSize(16)
              .fontColor(this.codeValue.startsWith('2') ? Color.Green : Color.Red)
          }
          .width('100%')
          .margin({ bottom: 10 })
        }

        // 响应区域
        Text('响应数据')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ bottom: 5 })

        TextArea({ text: this.resData })
          .width('100%')
          .height('50%')
          .borderRadius(5)
          .backgroundColor(Color.White)
      }
      .width('95%')
      .height('85%')
      .padding(10)
    }
    .size({ width: ConfigData.WH_100_100, height: ConfigData.WH_100_100 })
    .backgroundColor('#F5F5F5')
  }

  sendHttpRequest() {
    this.isLoading = true;
    this.codeValue = '';
    this.resData = '';

    let httpRequest = http.createHttp();
    
    // 用于订阅HTTP响应头，此接口会比request请求先返回。可以根据业务需要订阅此消息
    httpRequest.on('headersReceive', (header: Object) => {
      console.log(TAG, 'header: ' + JSON.stringify(header));
    });

    class Header {
      public contentType: string;

      constructor(contentType: string) {
        this.contentType = contentType;
      }
    }

    let str2method = (value: string): http.RequestMethod => {
      switch (value) {
        case 'GET':
          return http.RequestMethod.GET;
        case 'HEAD':
          return http.RequestMethod.HEAD;
        case 'POST':
          return http.RequestMethod.POST;
        case 'PUT':
          return http.RequestMethod.PUT;
        case 'DELETE':
          return http.RequestMethod.DELETE;
        case 'TRACE':
          return http.RequestMethod.TRACE;
        case 'OPTIONS':
          return http.RequestMethod.OPTIONS;
        case 'CONNECT':
          return http.RequestMethod.CONNECT;
      }
      return http.RequestMethod.GET;
    }

    let str2head = (): Header => {
      return new Header('application/json')
    }

    let options: http.HttpRequestOptions = {
      method: str2method(this.selectValue),
      header: str2head(),
      extraData: this.reqValue,
      expectDataType: http.HttpDataType.STRING,
      connectTimeout: 60000,
      readTimeout: 60000
    }

    httpRequest.request(this.urlValue, options, (err: BusinessError, data: http.HttpResponse) => {
      this.isLoading = false;
      if (!err) {
        // data.result为HTTP响应内容，可根据业务需要进行解析
        console.log(TAG, 'Result:' + JSON.stringify(data.result));
        this.resData = 'Result:\n' + JSON.stringify(data.result);
        console.log(TAG, 'code:' + JSON.stringify(data.responseCode));
        this.resData += '\ncode:\t' + JSON.stringify(data.responseCode);
        this.codeValue = JSON.stringify(data.responseCode);
        console.log(TAG, 'type:' + JSON.stringify(data.resultType));
        this.resData += '\ntype:\t' + JSON.stringify(data.resultType);
        // data.header为HTTP响应头，可根据业务需要进行解析
        console.log(TAG, 'header:' + JSON.stringify(data.header));
        this.resData += '\nheader:\n' + JSON.stringify(data.header);
        console.log(TAG, 'cookies:' + JSON.stringify(data.cookies)); // 自API version 8开始支持cookie
        // 取消订阅HTTP响应头事件
        httpRequest.off('headersReceive');
        // 当该请求使用完毕时，开发者务必调用destroy方法主动销毁该JavaScript Object。
        httpRequest.destroy();
      } else {
        console.log(TAG, 'response err: ' + JSON.stringify(err));
        this.resData = 'response err: ' + JSON.stringify(err);
        this.codeValue = 'Error';
        // 取消订阅HTTP响应头事件
        httpRequest.off('headersReceive');
        // 当该请求使用完毕时，开发者务必调用destroy方法主动销毁该JavaScript Object。
        httpRequest.destroy();
      }
    })
  }

  clearResponse() {
    this.resData = '';
    this.codeValue = '';
  }
}
