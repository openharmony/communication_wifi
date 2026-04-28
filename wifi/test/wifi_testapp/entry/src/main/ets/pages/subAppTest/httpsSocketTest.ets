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
import http from '@ohos.net.http';
import connection from '@ohos.net.connection';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { PageTitle} from '../../Component/pageTitle';
import { TestData} from '../../entryability/model/testData';
import router from '@ohos.router';
import ConfigData from '../../Utils/ConfigData';
import { BusinessError} from '@ohos.base';

interface myParams extends Object {
  testItem: TestData
}

const TAG = 'wifiTestApp [httpsSocketTest]';

/**
 * HTTPS Test Page Of Wifi test
 */
@Entry
@Component
struct HttpsSocketTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State selectIndex: number = 0;
  @State selectValue: string = ConfigData.HTTP_METHOD_GET;
  @State typeList: Array<SelectOption> = [
    { value: ConfigData.HTTP_METHOD_GET},
    { value: ConfigData.HTTP_METHOD_POST},
    { value: ConfigData.HTTP_METHOD_PUT},
    { value: ConfigData.HTTP_METHOD_DELETE},
    { value: ConfigData.HTTP_METHOD_TRACE},
    { value: ConfigData.HTTP_METHOD_CONNECT},
    { value: ConfigData.HTTP_METHOD_OPTIONS}
];
  @State urlValue: string = ConfigData.HTTP_DEFAULT_URL_BAIDU;
  @State reqSelectIndex: number = 0;
  @State reqSelectValue: string = ConfigData.RCP_REQ_SELECT_NONE;
  @State reqTypeList: Array<SelectOption> = [
    { value: ConfigData.RCP_REQ_SELECT_NONE},
    { value: ConfigData.HTTP_REQ_TYPE_RAW}
];
  @State reqValue: string = '';
  @State resData: string = '';
  @State codeValue: string = '';
  @State isLoading: boolean = false;
  @State sslVerify: boolean = true;
  @State networkStatus: string = ConfigData.HTTP_STR_CHECKING;
  @State networkType: string = ConfigData.HTTP_STR_NET_UNKNOWN;
  @State networkSwitchCount: number = 0;
  private netConnection: connection.NetConnection | null = null;

  aboutToAppear() {
    this.registerNetworkListener();
    this.checkCurrentNetwork();
  }

  // 注册网络监听
  registerNetworkListener() {
    try {
      this.netConnection = connection.createNetConnection();

      // 监听网络切换
      this.netConnection.on('netAvailable', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络切换: netId=${netHandle.netId}`);
        this.networkStatus = ConfigData.HTTP_STR_NET_SWITCHED;
        this.networkSwitchCount++;
        this.resData += `\n\n[系统] 检测到网络切换 (第${this.networkSwitchCount}次)`;
        this.resData += '\n[警告] HTTP模块无Close接口，旧连接可能未关闭';
        this.resData += '\n[建议] 推荐使用 RCP HTTP验证 页面进行测试';
      });

      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
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
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Scroll() {
        Column() {
          // 警告提示
          Row() {
            Text($r('app.string.wifitest_text_str'))
              .fontSize(ConfigData.VP_14)
              .fontColor($r('app.color.ui_orange'))
            Text($r('app.string.wifitest_text_hmkbzcwlqhsdzdzltjsyrhyz'))
              .fontSize(ConfigData.VP_12)
              .fontColor($r('app.color.ui_orange'))
          }
          .width(ConfigData.WH_100_100)
          .padding(ConfigData.VP_8)
          .backgroundColor($r("app.color.ohcc_hex_fff3e0"))
          .borderRadius($r('app.float.wh_value_5'))
          .margin({top: ConfigData.VP_5, bottom: ConfigData.VP_5})

          // 网络状态显示
          Row() {
            Text($r('app.string.wifitest_text_wlzt'))
              .fontSize(ConfigData.VP_14)
              .fontColor($r('app.color.color_999999_grey'))
            Text(`${this.networkStatus} (${this.networkType})`)
              .fontSize(ConfigData.VP_14)
              .fontColor(this.networkStatus === ConfigData.HTTP_STR_NET_OK ? $r('app.color.green'): $r('app.color.ui_orange'))
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_5})

          // 网络切换次数
          if (this.networkSwitchCount > 0){
            Row() {
              Text($r('app.string.wifitest_text_wlqhcs'))
                .fontSize(ConfigData.VP_14)
                .fontColor($r('app.color.color_999999_grey'))
              Text(`${this.networkSwitchCount}`)
                .fontSize(ConfigData.VP_14)
                .fontColor($r('app.color.red'))
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})
          }

          // HTTPS请求配置区域
          Text($r('app.string.wifitest_text_hqqpz_1'))
            .fontSize(ConfigData.VP_18)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})

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
                    this.urlValue = ConfigData.HTTP_DEFAULT_URL_BAIDU;
                    this.reqValue = '';
                } else if (this.selectValue == ConfigData.HTTP_METHOD_POST){
                    this.urlValue = ConfigData.HTTP_DEFAULT_URL_POST_BIN;
                    this.reqValue = ConfigData.HTTP_DEFAULT_POST_JSON;
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

          // SSL验证配置
          Row() {
            Text($r('app.string.wifitest_text_szsyz'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_40_100)
            Toggle({type: ToggleType.Switch, isOn: this.sslVerify})
              .onChange((isOn: boolean) => {
                this.sslVerify = isOn;
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `SSL验证: ${isOn}`);
              })
              .width(ConfigData.WH_20_100)
            Text(this.sslVerify ? ConfigData.HTTP_STR_SSL_ON: ConfigData.HTTP_STR_SSL_OFF)
              .fontSize(ConfigData.VP_14)
              .fontColor(this.sslVerify ? $r('app.color.green'): $r('app.color.red'))
              .width(ConfigData.WH_40_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_10})

          // 请求体配置
          Text($r('app.string.wifitest_text_qqtpz'))
            .fontSize(ConfigData.VP_16)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_5})

          Row() {
            Select(this.reqTypeList)
              .selected(this.reqSelectIndex)
              .value(this.reqSelectValue)
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
                this.reqSelectIndex = index;
                if(text){
                  this.reqSelectValue = text;
                }
              })
            TextInput({text:this.reqValue}).width(ConfigData.WH_75_100).borderRadius($r('app.float.wh_value_5'))
              .onChange((val: string) => {
                this.reqValue = val;
              })
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_15})

          // 发送按钮和清空按钮
          Row() {
            Button(ConfigData.HTTP_BTN_HTTPS)
              .width(ConfigData.WH_45_100)
              .backgroundColor(this.isLoading ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
              .enabled(!this.isLoading)
              .onClick(() => {
                this.sendHttpsRequest();
              })

            Button(ConfigData.HTTP_BTN_CLEAR)
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
            .height(ConfigData.VP_300)
            .borderRadius($r('app.float.wh_value_5'))
            .backgroundColor($r('app.color.white'))
            .margin({bottom: ConfigData.VP_20})
        }
        .width(ConfigData.WH_100_100)
        .padding(ConfigData.VP_10)
      }
      .width(ConfigData.WH_95_100)
      .height(ConfigData.PCT_85)
      .scrollable(ScrollDirection.Vertical)
      .scrollBar(BarState.Auto)
      .edgeEffect(EdgeEffect.Spring)
    }
    .size({width: ConfigData.WH_100_100, height: ConfigData.WH_100_100})
    .backgroundColor($r("app.color.ohcc_hex_f5f5f5"))
  }

  sendHttpsRequest() {
    this.isLoading = true;
    this.codeValue = '';
    this.resData = '';

    let httpRequest = http.createHttp();

    // 用于订阅HTTP响应头，此接口会比request请求先返回。可以根据业务需要订阅此消息
    httpRequest.on('headersReceive', (header: Object) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'header: ' + JSON.stringify(header));
    });

    class Header {
      public contentType: string;

      constructor(contentType: string){
        this.contentType = contentType;
      }
    }

    let str2method = (value: string): http.RequestMethod => {
      switch (value){
        case ConfigData.HTTP_METHOD_GET: return http.RequestMethod.GET;
        case ConfigData.HTTP_METHOD_HEAD: return http.RequestMethod.HEAD;
        case ConfigData.HTTP_METHOD_POST: return http.RequestMethod.POST;
        case ConfigData.HTTP_METHOD_PUT: return http.RequestMethod.PUT;
        case ConfigData.HTTP_METHOD_DELETE: return http.RequestMethod.DELETE;
        case ConfigData.HTTP_METHOD_TRACE: return http.RequestMethod.TRACE;
        case ConfigData.HTTP_METHOD_OPTIONS: return http.RequestMethod.OPTIONS;
        case ConfigData.HTTP_METHOD_CONNECT: return http.RequestMethod.CONNECT;
      }
      return http.RequestMethod.GET;
    }

    let str2head = (): Header => {
      return new Header(ConfigData.HTTP_CONTENT_TYPE_JSON)
    }

    let options: http.HttpRequestOptions = {
      method: str2method(this.selectValue),
      header: str2head(),
      extraData: this.reqValue,
      expectDataType: http.HttpDataType.STRING,
      connectTimeout: 60000,
      readTimeout: 60000,
      // HTTPS特定配置
      usingCache: true,
      priority: 1,
      usingProtocol: http.HttpProtocol.HTTP2,
      // SSL证书验证配置
      caPath: this.sslVerify ? undefined: "/system/etc/security/cacerts/"
    }

    httpRequest.request(this.urlValue, options, (err: BusinessError, data: http.HttpResponse) => {
      this.isLoading = false;
      if (!err){
        // data.result为HTTPS响应内容，可根据业务需要进行解析
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Result:' + JSON.stringify(data.result));
        this.resData = 'Result:\n' + JSON.stringify(data.result);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'code:' + JSON.stringify(data.responseCode));
        this.resData += '\ncode:\t' + JSON.stringify(data.responseCode);
        this.codeValue = JSON.stringify(data.responseCode);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'type:' + JSON.stringify(data.resultType));
        this.resData += '\ntype:\t' + JSON.stringify(data.resultType);
        // data.header为HTTPS响应头，可根据业务需要进行解析
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'header:' + JSON.stringify(data.header));
        this.resData += '\nheader:\n' + JSON.stringify(data.header);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'cookies:' + JSON.stringify(data.cookies));// 自API version 8开始支持cookie

        // 添加SSL相关信息
        if (data.header && data.header['server']){
          this.resData += '\nSSL连接成功';
        }

        // 取消订阅HTTPS响应头事件
        httpRequest.off('headersReceive');
        // 当该请求使用完毕时，开发者务必调用destroy方法主动销毁该JavaScript Object。
        httpRequest.destroy();
      } else {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'response err: ' + JSON.stringify(err));
        this.resData = 'response err: ' + JSON.stringify(err);
        this.codeValue = ConfigData.HTTP_RES_CODE_ERROR;

        // 检查是否是SSL相关错误
        if (err.message && err.message.includes('SSL')){
          this.resData += '\n\nSSL错误提示：请检查证书配置或尝试关闭SSL验证';
        }

        // 取消订阅HTTPS响应头事件
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