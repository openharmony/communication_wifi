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

import prompt from '@ohos.prompt'
import wifi from '@ohos.wifi'


/**
 * P2pModel api Test Page Of wifi test
 */

const TAG = "[P2pModel]"

export class P2pModel {
  getP2pPeerDevices( callback ) {
    console.log( TAG , 'scanP2p begin' )
    try {
      wifi.getP2pPeerDevices( ( err , wifiP2pDevice ) => {
        let p2pList = []
        if ( err ) {
          console.log( TAG , `scan p2p info err: ${ JSON.stringify( err ) }` )
          callback( p2pList )
          return
        }
        console.log( TAG , `scan p2p info call back: ` + JSON.stringify( wifiP2pDevice ) )
        let len = Object.keys( wifiP2pDevice ).length;
        for ( let i = 0 ; i < len ; ++i ) {
          p2pList.push( {
            deviceName : wifiP2pDevice[i].deviceName ,
            deviceAddress : wifiP2pDevice[i].deviceAddress ,
            primaryDeviceType : wifiP2pDevice[i].primaryDeviceType ,
            deviceStatus : wifiP2pDevice[i].deviceStatus ,
            groupCapabilitys : wifiP2pDevice[i].groupCapabilitys ,
          } )
          console.log( TAG , 'wifiP2pDevice:' + JSON.stringify( wifiP2pDevice[i] ) )
          console.log( TAG , 'p2pList:' + JSON.stringify( p2pList ) )
        }
        callback( p2pList )
      } )
    } catch( error ) {
      console.log( TAG , `Failed to testGetP2pPeerDevicesCallback. message: ${ error.message }, code: ${ error.code }` )
    }
  }

  getCurrentGroup( callback ) {
    console.log( TAG , 'scanP2pGroup begin' )
    wifi.getCurrentGroup( ( err , result ) => {
      let p2pGroupList = []
      if ( err ) {
        console.log( TAG , `scan info err: ${ JSON.stringify( err ) }` )
        callback( p2pGroupList )
        return
      }
      console.log( TAG , `scan info call back: ${ result.length }` )
      for ( let i = 0 ; i < result.length ; ++i ) {
        p2pGroupList.push( {
          ownerInfo : result[i].ownerInfo ,
          passphrase : result[i].passphrase ,
          interface : result[i].interface ,
          groupName : result[i].groupName ,
          networkId : result[i].networkId ,
          frequency : result[i].frequency ,
          clientDevices : result[i].clientDevices ,
          goIpAddress : result[i].goIpAddress ,
        } )
      }
      callback( p2pGroupList )
    } )
  }

  connectP2p( p2pScanInfo , wifiP2pGroupInfo) {
    prompt.showToast( { message : 'connecting' } )
    console.log( TAG , `connect deviceAddress=${ p2pScanInfo.deviceAddress }` )
    console.log( TAG , `p2pScanInfo:` + JSON.stringify( p2pScanInfo ) )
    let config = {
      deviceAddress : p2pScanInfo.deviceAddress ,
      netId : -2 ,
      passphrase : "", //wifiP2pGroupInfo.passphrase
      groupName : "", //wifiP2pGroupInfo.groupName
      goBand : 0
    }

    if ( wifi.p2pConnect( config ) ) {
      console.log( TAG , `connectP2P success` )
      wifi.createGroup( config )
    } else {
      console.log( TAG , `connectP2P fail` )
    }
  }

  //  resolveIP( ip ) {
  //    let address: string = ip.toString()
  //    if ( address === '0' ) {
  //      return '00:00:000:000'
  //    } else{
  //      console.log(" address /= 0")
  //    }
  //    address.substring( 0 , 2 )
  //    return `${ address.substring( 0 , 2 ) }:${ address.substring( 2 , 4 ) }:${ address.substring( 4 , 7 ) }:${ address.substring( 7 , 10 ) }`
  //  }
  //
  //  getIpInfo() {
  //    let ipInfoList = []
  //    let ipInfo = wifi.getIpInfo()
  //    console.log( `${ TAG } getIpInfo=${ JSON.stringify( ipInfo ) }` )
  //    ipInfoList.push( { key : $r( 'app.string.ip_address' ) , value : this.resolveIP( ipInfo.ipAddress ) } )
  //    ipInfoList.push( { key : $r( 'app.string.gate_way' ) , value : this.resolveIP( ipInfo.gateway ) } )
  //    ipInfoList.push( { key : $r( 'app.string.net_mask' ) , value : this.resolveIP( ipInfo.netmask ) } )
  //    ipInfoList.push( { key : $r( 'app.string.primary_dns' ) , value : this.resolveIP( ipInfo.primaryDns ) } )
  //    ipInfoList.push( { key : $r( 'app.string.second_dns' ) , value : this.resolveIP( ipInfo.secondDns ) } )
  //    ipInfoList.push( { key : $r( 'app.string.server_ip' ) , value : this.resolveIP( ipInfo.serverIp ) } )
  //    ipInfoList.push( { key : $r( 'app.string.lease_duration' ) , value : ipInfo.leaseDuration.toString() } )
  //    return ipInfoList
  //  }
  //
  //  getCountryCode() {
  //    let countryCodeList = []
  //    let countryCode = wifi.getCountryCode()
  //    countryCodeList.push( { key : $r( 'app.string.country_code' ) , value : countryCode } )
  //    return countryCodeList
  //  }
  //
  //  getFeatureSupport() {
  //    let featureSupportedList = []
  //    featureSupportedList.push( {
  //      key : $r( 'app.string.infrastructure_feature' ) ,
  //      value : wifi.isFeatureSupported( 0x0001 ).toString()
  //    } )
  //    featureSupportedList.push( {
  //      key : $r( 'app.string.ghz_feature' ) ,
  //      value : wifi.isFeatureSupported( 0x0002 ).toString()
  //    } )
  //    featureSupportedList.push( {
  //      key : $r( 'app.string.gas_anqp_feature' ) ,
  //      value : wifi.isFeatureSupported( 0x0004 ).toString()
  //    } )
  //    featureSupportedList.push( {
  //      key : $r( 'app.string.wifi_direct' ) ,
  //      value : wifi.isFeatureSupported( 0x0008 ).toString()
  //    } )
  //    featureSupportedList.push( {
  //      key : $r( 'app.string.soft_ap' ) ,
  //      value : wifi.isFeatureSupported( 0x0010 ).toString()
  //    } )
  //    featureSupportedList.push( {
  //      key : $r( 'app.string.wifi_aware' ) ,
  //      value : wifi.isFeatureSupported( 0x0040 ).toString()
  //    } )
  //    return featureSupportedList
  //  }
}