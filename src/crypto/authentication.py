# -*-coding:utf-8-*-
'''
Created on 2016-4-1

@author: ThinkPad
'''
from smartcard.util import toBytes,toHexString
from tlv.tlvparse import parseTag70
from crypto.pbocrsa import PbocRsa
from rsa.pkcs1 import _hash as Hash

def PbocRecoverIssuePubKey(caPubKeySet = {}, icFldSet={}):
    '''
          恢复发卡行公钥
    '''
    if caPubKeySet.has_key(icFldSet['8F']) == False:
        raise Exception('SDA失败:IC卡支持的CA索引[%s]未被终端支持' % icFldSet['8F'])
    
    rsa = PbocRsa()
    rsa.pkey = caPubKeySet[icFldSet['8F']]

    decrypted = rsa.pbocSignDataRecover(icFldSet['90'])
    #print 'recover issue certificate : ', decrypted
    certificate = rsa.pbocPubKeyCertParse(decrypted, 'ISSUE')
    '''
          根据PBOC规范说明检查发卡行证书
    '''
    try:
        certificate['ISSUE'].certificateCheck()
    except Exception,e:
        raise Exception(e)
    '''
          重新计算HASH
    '''
    srcdata = certificate['ISSUE'].__str__()
    srcdata = srcdata[2:len(srcdata)-42]
    if icFldSet.has_key('92'):
        srcdata += icFldSet['92']
    srcdata += icFldSet['9F32']
    hashmessage = ''.join(map(chr, toBytes(srcdata)))
    hashvalue   = toHexString(map(ord, list(Hash(hashmessage, 'SHA-%d' % int(certificate['ISSUE'].hashAlgId,16)))), format = 1)
    if hashvalue != certificate['ISSUE'].hashVal:
        raise Exception('SDA失败:终端计算hash[%s]与证书hash[%s]不一致' % (hashvalue, certificate['ISSUE'].hashVal))
    print '发卡行公钥证书恢复成功，终端计算hash[%s]与证书hash[%s]一致' % (hashvalue, certificate['ISSUE'].hashVal)
    '''
           检验发卡行标识是否匹配主账号最左面的3-8个数字
    '''
    issueId = certificate['ISSUE'].issueId.rstrip('F')
    if len(issueId) not in range(3,9):
        raise Exception('SDA失败:发卡行标识需至少3个数字与主账号左边3个数字一致')
    
    if icFldSet['5A'][0:len(issueId)] != issueId:
        raise Exception('SDA失败:发卡行标识[%s]与主账号左%d位[%s]不一致' % (icFldSet['5A'][0:len(issueId)], len(issueId), issueId))
    
    if icFldSet.has_key('92'):
        issuepubkey = certificate['ISSUE'].pubKey + icFldSet['92']
    else:
        issuepubkey = certificate['ISSUE'].pubKey

    return issuepubkey

def PbocSDA(caPubKeySet = {}, icFldSet={}, staticRecordLst=[]):
    '''
    SDA
          用于脱机数据认证的记录必须是TLV编码格式，并且Tag＝’70’。记录中用于脱机数据认证的数据取
          决于记录所属文件的SFI： 
          ——对于SFI从1到10的文件，记录的Tag （’70’）和记录长度不用于脱机数据认证处理， READ RECORD
          命令响应数据域中所有其他数据（SW1，SW2除外）都参与脱机数据认证； 
          ——对于SFI从 11到30的文件，记录的 Tag （’70’）和记录长度用于脱机数据认证处理，因而READ 
          RECORD命令响应数据域中所有数据（SW1，SW2除外）都参与脱机数据认证； 
          ——如果用于脱机数据认证的文件中的记录的Tag不是’70’，则认为脱机数据认证已经执行并失败，
          终端必须设置 TSI的“脱机数据认证已执行”位，以及TVR 相应的“脱机静态数据认证失败”
          位，“脱机动态数据认证失败”位或“CDA失败”位。
    '''
    print '----------------------开始进行静态数据认证(SDA)过程----------------------------'
    staticDataes = ''
    for record in staticRecordLst:
        #print 'record',record
        if record[1][:2] != '70':
            raise Exception('SDA失败:用于脱机数据认证的记录的标签必须为70')
        if ((record[0] >> 8) & 0x1F) in range(1, 11):
            staticDataes += parseTag70(record[1])
        elif ((record[0] >> 8) & 0x1F) in range(11, 31):
            staticDataes += record[1]
        else:
            raise Exception('SDA失败:存储IC卡参与认证的静态数据的SFI必须为1到30之间')
        #print 'record',record
    '''
           恢复发卡行公钥
    '''
    try:
        issuepubkey = PbocRecoverIssuePubKey(caPubKeySet, icFldSet)
    except Exception,e:
        raise Exception(e)
     
    print '发卡行公钥  issuepubkey : [%s]' % issuepubkey
    
    '''
           恢复签名数据
    '''
    rsa = PbocRsa(issuepubkey, icFldSet['9F32'])
    decrypted = rsa.pbocSignDataRecover(icFldSet['93'])
    print '恢复的签名数据 : ', decrypted
    signeddataobj = rsa.pbocSignDataParse(decrypted)['TAG93']
    #signeddataobj.showsignData()
    
    '''
           重新计算HASH
    '''
    if icFldSet.has_key('9F4A'):
        if icFldSet['9F4A'] != '82':
            raise Exception('SDA失败:静态数据认证标签列表存在并且其包含非82的标签')
        else:
            staticDataes += icFldSet['82']
    print '参与SDA的IC卡源数据: [%s]' % staticDataes
    print '进行HASH计算源数据  : ', decrypted[2:len(decrypted)-42] + staticDataes
    hashmessage = ''.join(map(chr, toBytes(decrypted[2:len(decrypted)-42] + staticDataes)))
    hashvalue   = toHexString(map(ord, list(Hash(hashmessage, 'SHA-%d' % int(signeddataobj.hashAlgId,16)))), format = 1)
    #print 'hashvalue : ',hashvalue
    if hashvalue != signeddataobj.hashVal:
        raise Exception('SDA失败:终端计算hash[%s]与签名数据中hash[%s]不一致' % (hashvalue, signeddataobj.hashVal))
    print '静态数据HASH校验成功，终端计算hash[%s]与签名数据中hash[%s]一致' % (hashvalue, signeddataobj.hashVal)
    print '----------------------进行静态数据认证(SDA)过程成功----------------------------'
    
    icFldSet['9F45'] = signeddataobj.dataVerCode
    

