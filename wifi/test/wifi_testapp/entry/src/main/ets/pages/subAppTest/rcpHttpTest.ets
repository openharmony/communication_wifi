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

import { rcp } from '@kit.RemoteCommunicationKit';
import connection from '@ohos.net.connection';
import { TestData } from '../../entryability/model/testData'
import ConfigData from '../../utils/ConfigData';
import { BusinessError } from '@ohos.base';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { PageTitle } from '../../Component/pageTitle';
import router from '@ohos.router';

interface myParams extends Object {
  testItem: TestData
}

const TAG = 'wifiTestApp [rcpHttpTest]';

/**
 * RCP (Remote Communication Protocol) HTTP Test Page
 */
@Entry
@Component
struct RcpHttpTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State selectIndex: number = 0;
  @State selectValue: string = 'GET';
  @State typeList: Array<SelectOption> = [
    { value: 'GET'},
    { value: 'POST'},
    { value: 'PUT'},
    { value: 'DELETE'},
    { value: 'HEAD'},
    { value: 'FETCH'}
  ];
  @State urlValue: string = 'http://www.baidu.com';
  @State reqValue: string = '';
  @State resData: string = '';
  @State codeValue: string = '';
  @State isLoading: boolean = false;
  @State networkStatus: string = '检测中...';
  @State networkType: string = '未知';
  @State sessionId: string = '';
  
  private rcpSession: rcp.Session | null = null;
  private netConnection: connection.NetConnection | null = null;

  aboutToAppear() {
    this.initRcpSession();
    this.registerNetworkListener();
    this.checkCurrentNetwork();
  }

  initRcpSession() {
    try {
      // 创建 RCP 会话
      const sessionConfig: rcp.SessionConfiguration = {
        requestConfiguration: {
          transfer: {
            timeout: {
              connectMs: 60000,    // 连接超时
              transferMs: 60000    // 传输超时
            }
          }
        }
      };
      this.rcpSession = rcp.createSession(sessionConfig);
      this.sessionId = this.rcpSession.id;
      console.log(TAG, `RCP Session created: ${this.sessionId}`);
    } catch (error) {
      console.error(TAG, `Failed to create RCP session: ${JSON.stringify(error)}`);
    }
  }

  // 注册网络监听
  registerNetworkListener() {
    try {
      this.netConnection = connection.createNetConnection();
      
      // 监听网络可用事件 - 默认网络切换时触发
      this.netConnection.on('netAvailable', (netHandle: connection.NetHandle) => {
        console.log(TAG, `网络切换: netId=${netHandle.netId}`);
        this.networkStatus = '网络切换';
        this.resData += `\n[系统] 检测到网络切换 (netId: ${netHandle.netId})`;
        
        // 根据官方文档要求：发生默认网络切换时，重新建立 session
        this.handleNetworkSwitch();
      });

      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        console.log(TAG, `网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        if (netCapabilityInfo.netCap) {
          this.updateNetworkType(netCapabilityInfo.netCap);
        }
      });

      this.netConnection.on('netLost', (netHandle: connection.NetHandle) => {
        console.log(TAG, `网络丢失: netId=${netHandle.netId}`);
        this.networkStatus = '网络断开';
        this.resData += '\n[系统] 网络连接丢失';
      });

      this.netConnection.register((error: Error) => {
        if (error) {
          console.error(TAG, `注册网络监听失败: ${JSON.stringify(error)}`);
          this.networkStatus = '监听注册失败';
        } else {
          console.log(TAG, '网络监听已注册');
        }
      });
    } catch (error) {
      console.error(TAG, `创建网络监听失败: ${JSON.stringify(error)}`);
      this.networkStatus = '监听创建失败';
    }
  }

  // 处理网络切换 - 重新建立 RCP Session
  handleNetworkSwitch() {
    console.log(TAG, '开始处理网络切换');
    this.resData += '\n[系统] 正在重建 RCP Session...';
    
    // 1. 关闭旧 session
    if (this.rcpSession) {
      try {
        this.rcpSession.close();
        console.log(TAG, '旧 RCP Session 已关闭');
        this.resData += '\n[系统] 旧 Session 已关闭';
      } catch (error) {
        console.error(TAG, `关闭 Session 失败: ${JSON.stringify(error)}`);
      }
    }
    
    // 2. 延迟后重新创建 session（等待新网络稳定）
    setTimeout(() => {
      this.initRcpSession();
      this.networkStatus = '网络已切换';
      this.resData += '\n[系统] RCP Session 已重建，可以继续发送请求';
      console.log(TAG, `新 RCP Session 已创建: ${this.sessionId}`);
    }, 1000);
  }

  async checkCurrentNetwork() {
    try {
      const netHandle = await connection.getDefaultNet();
      const netCapabilities = await connection.getNetCapabilities(netHandle);
      this.updateNetworkType(netCapabilities);
      this.networkStatus = '网络正常';
      console.log(TAG, `当前网络类型: ${this.networkType}`);
    } catch (error) {
      console.error(TAG, `获取网络状态失败: ${JSON.stringify(error)}`);
      this.networkStatus = '无网络';
      this.networkType = '未连接';
    }
  }

  updateNetworkType(netCapabilities: connection.NetCapabilities) {
    if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_WIFI)) {
      this.networkType = 'WiFi';
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_CELLULAR)) {
      this.networkType = '蜂窝网络';
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_ETHERNET)) {
      this.networkType = '以太网';
    } else {
      this.networkType = '其他';
    }
  }

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Column() {
        // RCP请求配置区域
        Text('RCP 请求配置')
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ top: 10, bottom: 10 })

        // Session ID 显示
        Row() {
          Text('Session ID: ')
            .fontSize(14)
            .fontColor(Color.Gray)
          Text(this.sessionId.substring(0, 16) + '...')
            .fontSize(14)
            .fontColor(Color.Gray)
        }
        .width('100%')
        .margin({ bottom: 10 })

        // 网络状态显示
        Row() {
          Text('网络状态: ')
            .fontSize(14)
            .fontColor(Color.Gray)
          Text(`${this.networkStatus} (${this.networkType})`)
            .fontSize(14)
            .fontColor(this.networkStatus === '网络正常' || this.networkStatus === '网络可用' ? Color.Green : Color.Orange)
        }
        .width('100%')
        .margin({ bottom: 10 })

        // 方法选择和 URL 输入
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
                } else if (this.selectValue == 'PUT') {
                  this.urlValue = 'https://httpbin.org/put';
                  this.reqValue = '{"data": "update content"}';
                } else if (this.selectValue == 'DELETE') {
                  this.urlValue = 'https://httpbin.org/delete';
                  this.reqValue = '';
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
        Text('请求体内容')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ bottom: 5 })

        TextInput({text:this.reqValue})
          .width('100%')
          .borderRadius('5')
          .maxLength(500)
          .onChange((val: string) => {
            this.reqValue = val;
          })
          .margin({bottom:15})

        // 发送按钮和清空按钮
        Row() {
          Button('发送请求')
            .width('45%')
            .backgroundColor(this.isLoading ? Color.Gray : Color.Blue)
            .enabled(!this.isLoading)
            .onClick(() => {
              this.sendRcpRequest();
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
          .height('45%')
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

  async sendRcpRequest() {
    if (!this.rcpSession) {
      this.resData = '错误: RCP Session 未初始化';
      return;
    }

    this.isLoading = true;
    this.codeValue = '';
    this.resData = '';

    try {
      let response: rcp.Response;
      const startTime = Date.now();

      switch (this.selectValue) {
        case 'GET':
          response = await this.rcpSession.get(this.urlValue);
          break;
        case 'POST':
          response = await this.rcpSession.post(this.urlValue, this.reqValue);
          break;
        case 'PUT':
          response = await this.rcpSession.put(this.urlValue, this.reqValue);
          break;
        case 'DELETE':
          response = await this.rcpSession.delete(this.urlValue);
          break;
        case 'HEAD':
          response = await this.rcpSession.head(this.urlValue);
          break;
        case 'FETCH':
          const request = new rcp.Request(this.urlValue, 'POST');
          response = await this.rcpSession.fetch(request);
          break;
        default:
          response = await this.rcpSession.get(this.urlValue);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // 处理响应
      this.isLoading = false;
      this.codeValue = response.statusCode.toString();
      
      // 构建响应数据显示
      this.resData = `请求方法: ${this.selectValue}\n`;
      this.resData += `请求URL: ${this.urlValue}\n`;
      this.resData += `\n=== 响应信息 ===\n`;
      this.resData += `状态码: ${response.statusCode}\n`;
      this.resData += `响应时间: ${duration}ms\n`;
      
      // 显示响应头
      if (response.headers) {
        this.resData += `\n=== 响应头 ===\n`;
        const headers = response.headers;
        Object.keys(headers).forEach((key: string) => {
          this.resData += `${key}: ${headers[key]}\n`;
        });
      }

      // 显示响应体
      this.resData += `\n=== 响应体 ===\n`;
      if (response.body) {
        const bodyText:string|null  = await response.toString();
        // 限制显示长度，避免过长
        if (bodyText!.length > 1000) {
          this.resData += bodyText!.substring(0, 1000) + '\n...(内容过长，已截断)';
        } else {
          this.resData += bodyText;
        }
      } else {
        this.resData += '(无响应体)';
      }

      console.log(TAG, `RCP Request completed: ${response.statusCode}`);
    } catch (error) {
      this.isLoading = false;
      const err = error as BusinessError;
      console.error(TAG, `RCP Request failed: ${JSON.stringify(err)}`);
      this.resData = `请求失败\n`;
      this.resData += `错误码: ${err.code}\n`;
      this.resData += `错误信息: ${err.message}\n`;
      this.resData += `详细信息: ${JSON.stringify(err)}`;
      this.codeValue = 'Error';
    }
  }

  clearResponse() {
    this.resData = '';
    this.codeValue = '';
  }

  aboutToDisappear() {
    // 取消网络监听
    if (this.netConnection) {
      try {
        this.netConnection.unregister((error: Error) => {
          if (error) {
            console.error(TAG, `取消网络监听失败: ${JSON.stringify(error)}`);
          } else {
            console.log(TAG, '网络监听已取消');
          }
        });
      } catch (error) {
        console.error(TAG, `取消网络监听异常: ${JSON.stringify(error)}`);
      }
      this.netConnection = null;
    }

    // 关闭 RCP Session
    if (this.rcpSession) {
      try {
        this.rcpSession.close();
        console.log(TAG, 'RCP Session closed');
      } catch (error) {
        console.error(TAG, `关闭 RCP Session 失败: ${JSON.stringify(error)}`);
      }
      this.rcpSession = null;
    }
  }
}

