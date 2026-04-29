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

import hilog from '@ohos.hilog';
import { rcp} from '@kit.RemoteCommunicationKit';
import connection from '@ohos.net.connection';
import { TestData} from '../../entryability/model/testData';
import ConfigData from '../../Utils/ConfigData';
import { BusinessError} from '@ohos.base';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { PageTitle} from '../../Component/pageTitle';
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
  @State selectValue: string = ConfigData.HTTP_METHOD_GET;
  @State typeList: Array<SelectOption> = [
    { value: ConfigData.HTTP_METHOD_GET},
    { value: ConfigData.HTTP_METHOD_POST},
    { value: ConfigData.HTTP_METHOD_PUT},
    { value: ConfigData.HTTP_METHOD_DELETE},
    { value: ConfigData.HTTP_METHOD_HEAD},
    { value: ConfigData.HTTP_METHOD_FETCH}
];
  @State urlValue: string = ConfigData.RCP_HTTP_URL_BAIDU;
  @State reqValue: string = '';
  @State resData: string = '';
  @State codeValue: string = '';
  @State isLoading: boolean = false;
  @State networkStatus: string = ConfigData.HTTP_STR_CHECKING;
  @State networkType: string = ConfigData.HTTP_STR_NET_UNKNOWN;
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
              connectMs: 60000,// 连接超时
              transferMs: 60000// 传输超时
            }
          }
        }
      };
      this.rcpSession = rcp.createSession(sessionConfig);
      this.sessionId = this.rcpSession.id;
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `RCP Session created: ${this.sessionId}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to create RCP session: ${JSON.stringify(error)}`);
    }
  }

  // 注册网络监听
  registerNetworkListener() {
    try {
      this.netConnection = connection.createNetConnection();

      // 监听网络可用事件 - 默认网络切换时触发
      this.netConnection.on('netAvailable', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络切换: netId=${netHandle.netId}`);
        this.networkStatus = ConfigData.HTTP_STR_NET_SWITCH;
        this.resData += `\n[系统] 检测到网络切换 (netId: ${netHandle.netId})`;

        // 根据官方文档要求：发生默认网络切换时，重新建立 session
        this.handleNetworkSwitch();
      });

      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        if (netCapabilityInfo.netCap){
          this.updateNetworkType(netCapabilityInfo.netCap);
        }
      });

      this.netConnection.on('netLost', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络丢失: netId=${netHandle.netId}`);
        this.networkStatus = ConfigData.HTTP_STR_NET_GONE;
        this.resData += '\n[系统] 网络连接丢失';
      });

      this.netConnection.register((error: Error) => {
        if (error){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `注册网络监听失败: ${JSON.stringify(error)}`);
          this.networkStatus = ConfigData.HTTP_STR_REG_FAIL;
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '网络监听已注册');
        }
      });
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `创建网络监听失败: ${JSON.stringify(error)}`);
      this.networkStatus = ConfigData.HTTP_STR_CREATE_FAIL;
    }
  }

  // 处理网络切换 - 重新建立 RCP Session
  handleNetworkSwitch() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '开始处理网络切换');
    this.resData += '\n[系统] 正在重建 RCP Session...';

    // 1. 关闭旧 session
    if (this.rcpSession){
      try {
        this.rcpSession.close();
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '旧 RCP Session 已关闭');
        this.resData += '\n[系统] 旧 Session 已关闭';
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭 Session 失败: ${JSON.stringify(error)}`);
      }
    }

    // 2. 延迟后重新创建 session（等待新网络稳定）
    setTimeout(() => {
      this.initRcpSession();
      this.networkStatus = ConfigData.HTTP_STR_NET_SWITCHED;
      this.resData += '\n[系统] RCP Session 已重建，可以继续发送请求';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `新 RCP Session 已创建: ${this.sessionId}`);
    }, 1000);
  }

  async checkCurrentNetwork() {
    try {
      const netHandle = await connection.getDefaultNet();
      const netCapabilities = await connection.getNetCapabilities(netHandle);
      this.updateNetworkType(netCapabilities);
      this.networkStatus = ConfigData.HTTP_STR_NET_OK;
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `当前网络类型: ${this.networkType}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `获取网络状态失败: ${JSON.stringify(error)}`);
      this.networkStatus = ConfigData.HTTP_STR_NO_NET;
      this.networkType = ConfigData.HTTP_STR_NOT_CONN;
    }
  }

  updateNetworkType(netCapabilities: connection.NetCapabilities){
    if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_WIFI)){
      this.networkType = ConfigData.HTTP_STR_BEARER_WIFI;
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_CELLULAR)){
      this.networkType = ConfigData.HTTP_STR_CELLULAR;
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_ETHERNET)){
      this.networkType = ConfigData.HTTP_STR_ETHERNET;
    } else {
      this.networkType = ConfigData.HTTP_STR_BEARER_OTHER;
    }
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Column() {
        // RCP请求配置区域
        Text($r('app.string.wifitest_text_rqqpz'))
          .fontSize(ConfigData.VP_18)
          .fontWeight(FontWeight.Bold)
          .width(ConfigData.WH_100_100)
          .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})

        // Session ID 显示
        Row() {
          Text($r('app.string.wifitest_text_si'))
            .fontSize(ConfigData.VP_14)
            .fontColor($r('app.color.color_999999_grey'))
          Text() {
            Span(this.sessionId.substring(0, 16))
            Span($r('app.string.wifitest_text_ellipsis'))
          }
            .fontSize(ConfigData.VP_14)
            .fontColor($r('app.color.color_999999_grey'))
        }
        .width(ConfigData.WH_100_100)
        .margin({bottom: ConfigData.VP_10})

        // 网络状态显示
        Row() {
          Text($r('app.string.wifitest_text_wlzt'))
            .fontSize(ConfigData.VP_14)
            .fontColor($r('app.color.color_999999_grey'))
          Text(`${this.networkStatus} (${this.networkType})`)
            .fontSize(ConfigData.VP_14)
            .fontColor(this.networkStatus === ConfigData.HTTP_STR_NET_OK || this.networkStatus === ConfigData.HTTP_STR_NET_AVAILABLE ? $r('app.color.green'): $r('app.color.ui_orange'))
        }
        .width(ConfigData.WH_100_100)
        .margin({bottom: ConfigData.VP_10})

        // 方法选择和 URL 输入
        Row() {
          Select(this.typeList)
            .selected(this.selectIndex)
            .value(this.selectValue)
            .font({size: ConfigData.VP_12, weight: ConfigData.FONT_W_300})
            .fontColor($r("app.color.font_color_182431"))
            .selectedOptionFont({size: ConfigData.VP_16, weight: ConfigData.FONT_W_400})
            .optionFont({size: ConfigData.VP_16, weight: ConfigData.FONT_W_400})
            .menuAlign(MenuAlignType.START, {dx:0, dy:0})
            .borderRadius($r('app.float.wh_value_5'))
            .width(ConfigData.WH_25_100)
            .optionHeight(300)
            .onSelect((index:number, text?: string | undefined)=>{
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Select:' + index)
              this.selectIndex = index;
              if(text){
                this.selectValue = text;
                if (this.selectValue == ConfigData.HTTP_METHOD_GET){
                  this.urlValue = ConfigData.RCP_HTTP_URL_BAIDU;
                  this.reqValue = '';
              } else if (this.selectValue == ConfigData.HTTP_METHOD_POST){
                  this.urlValue = ConfigData.HTTP_DEFAULT_URL_POST_BIN;
                  this.reqValue = ConfigData.HTTP_DEFAULT_POST_JSON;
              } else if (this.selectValue == ConfigData.HTTP_METHOD_PUT){
                  this.urlValue = ConfigData.HTTP_DEFAULT_URL_HTTPBIN_PUT;
                  this.reqValue = ConfigData.HTTP_DEFAULT_HTTPBIN_UPDATE_JSON;
              } else if (this.selectValue == ConfigData.HTTP_METHOD_DELETE){
                  this.urlValue = ConfigData.HTTP_DEFAULT_URL_HTTPBIN_DELETE;
                  this.reqValue = '';
              }
              }
            })
          TextInput({text:this.urlValue}).width(ConfigData.WH_75_100).borderRadius($r('app.float.wh_value_5'))
            .onChange((val: string) => {
              this.urlValue = val;
            })
        }
        .width(ConfigData.WH_100_100)
        .margin({bottom: ConfigData.VP_10})

        // 请求体配置
        Text($r('app.string.wifitest_text_qqtnr'))
          .fontSize(ConfigData.VP_16)
          .fontWeight(FontWeight.Bold)
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_5})

        TextInput({text:this.reqValue})
          .width(ConfigData.WH_100_100)
          .borderRadius($r('app.float.wh_value_5'))
          .maxLength(500)
          .onChange((val: string) => {
            this.reqValue = val;
          })
          .margin({bottom: ConfigData.VP_15})

        // 发送按钮和清空按钮
        Row() {
          Button(ConfigData.RCP_UI_SEND_REQUEST)
            .width(ConfigData.WH_45_100)
            .backgroundColor(this.isLoading ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
            .enabled(!this.isLoading)
            .onClick(() => {
              this.sendRcpRequest();
            })

          Button(ConfigData.RCP_UI_CLEAR_RESPONSE)
            .width(ConfigData.WH_45_100)
            .backgroundColor($r('app.color.ui_orange'))
            .onClick(() => {
              this.clearResponse();
            })
        }
        .width(ConfigData.WH_100_100)
        .justifyContent(FlexAlign.SpaceBetween)
        .margin({bottom: ConfigData.VP_15})

        // 响应状态
        if (this.codeValue){
          Row() {
            Text($r('app.string.wifitest_text_xyzt'))
              .fontSize(ConfigData.VP_16)
              .fontWeight(FontWeight.Bold)
            Text(this.codeValue)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.codeValue.startsWith(ConfigData.QV_MOCK_DOMAIN_2) ? $r('app.color.green'): $r('app.color.red'))
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_10})
        }

        // 响应区域
        Text($r('app.string.wifitest_text_xysj'))
          .fontSize(ConfigData.VP_16)
          .fontWeight(FontWeight.Bold)
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_5})

        TextArea({text: this.resData})
          .width(ConfigData.WH_100_100)
          .height(ConfigData.WH_45_100)
          .borderRadius($r('app.float.wh_value_5'))
          .backgroundColor($r('app.color.white'))
      }
      .width(ConfigData.WH_95_100)
      .height(ConfigData.PCT_85)
      .padding(ConfigData.VP_10)
    }
    .size({width: ConfigData.WH_100_100, height: ConfigData.WH_100_100})
    .backgroundColor($r("app.color.ohcc_hex_f5f5f5"))
  }

  async sendRcpRequest() {
    if (!this.rcpSession){
      this.resData = ConfigData.RCP_ERR_SESSION_NOT_INIT;
      return;
    }

    this.isLoading = true;
    this.codeValue = '';
    this.resData = '';

    try {
      let response: rcp.Response;
      const startTime = Date.now();

      switch (this.selectValue){
        case ConfigData.HTTP_METHOD_GET:
          response = await this.rcpSession.get(this.urlValue);
          break;
        case ConfigData.HTTP_METHOD_POST:
          response = await this.rcpSession.post(this.urlValue, this.reqValue);
          break;
        case ConfigData.HTTP_METHOD_PUT:
          response = await this.rcpSession.put(this.urlValue, this.reqValue);
          break;
        case ConfigData.HTTP_METHOD_DELETE:
          response = await this.rcpSession.delete(this.urlValue);
          break;
        case ConfigData.HTTP_METHOD_HEAD:
          response = await this.rcpSession.head(this.urlValue);
          break;
        case ConfigData.HTTP_METHOD_FETCH:
          const request = new rcp.Request(this.urlValue, ConfigData.HTTP_METHOD_POST);
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
      if (response.headers){
        this.resData += `\n=== 响应头 ===\n`;
        const headers = response.headers;
        Object.keys(headers).forEach((key: string) => {
          this.resData += `${key}: ${headers[key]}\n`;
        });
      }

      // 显示响应体
      this.resData += `\n=== 响应体 ===\n`;
      if (response.body){
        const bodyText:string|null  = await response.toString();
        // 限制显示长度，避免过长
        if (bodyText!.length > 1000){
          this.resData += bodyText!.substring(0, 1000) + '\n...(内容过长，已截断)';
        } else {
          this.resData += bodyText;
        }
      } else {
        this.resData += '(无响应体)';
      }

      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `RCP Request completed: ${response.statusCode}`);
    } catch (error){
      this.isLoading = false;
      const err = error as BusinessError;
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `RCP Request failed: ${JSON.stringify(err)}`);
      this.resData = `请求失败\n`;
      this.resData += `错误码: ${err.code}\n`;
      this.resData += `错误信息: ${err.message}\n`;
      this.resData += `详细信息: ${JSON.stringify(err)}`;
      this.codeValue = ConfigData.HTTP_RES_CODE_ERROR;
    }
  }

  clearResponse() {
    this.resData = '';
    this.codeValue = '';
  }

  aboutToDisappear() {
    // 取消网络监听
    if (this.netConnection){
      try {
        this.netConnection.unregister((error: Error) => {
          if (error){
            hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消网络监听失败: ${JSON.stringify(error)}`);
          } else {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '网络监听已取消');
          }
        });
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消网络监听异常: ${JSON.stringify(error)}`);
      }
      this.netConnection = null;
    }

    // 关闭 RCP Session
    if (this.rcpSession){
      try {
        this.rcpSession.close();
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'RCP Session closed');
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭 RCP Session 失败: ${JSON.stringify(error)}`);
      }
      this.rcpSession = null;
    }
  }
}