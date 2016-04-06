# -*-coding:utf-8-*-
'''
Created on 2016-4-5

@author: 014731
'''
from smartcard.util import toBytes, toHexString 
from tlv.tlvparse import parseTag70 
from crypto.pbocrsa import PbocRsa
from rsa.pkcs1 import _hash as Hash 
 
def PbocRecoverIssuePubKey(caPubKeySet={}, icFldSet={}): 
    ''' 
          恢复发卡行公钥 
    ''' 
    if caPubKeySet.has_key(icFldSet['8F']) == False: 
        raise Exception('IC卡支持的CA索引[%s]未被终端支持' % icFldSet['8F']) 
     
    rsa = PbocRsa() 
    rsa.pkey = caPubKeySet[icFldSet['8F']] 
 
    decrypted = rsa.pbocSignDataRecover(icFldSet['90']) 
    # print 'recover issue certificate : ', decrypted 
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
    #certificate['ISSUE'].showCertificate()
    srcdata = certificate['ISSUE'].__str__() 
    srcdata = srcdata[2:len(srcdata) - 42] 
    if icFldSet.has_key('92'): 
        srcdata += icFldSet['92'] 
    srcdata += icFldSet['9F32'] 
    hashmessage = ''.join(map(chr, toBytes(srcdata))) 
    hashvalue = toHexString(map(ord, list(Hash(hashmessage, 'SHA-%d' % int(certificate['ISSUE'].hashAlgId, 16)))), format=1) 
    if hashvalue != certificate['ISSUE'].hashVal: 
        raise Exception('终端计算hash[%s]与证书hash[%s]不一致' % (hashvalue, certificate['ISSUE'].hashVal)) 
    print '发卡行公钥证书恢复成功，终端计算hash[%s]与证书hash[%s]一致' % (hashvalue, certificate['ISSUE'].hashVal) 
    ''' 
           检验发卡行标识是否匹配主账号最左面的3-8个数字 
    ''' 
    issueId = certificate['ISSUE'].issueId.rstrip('F') 
    if len(issueId) not in range(3, 9): 
        raise Exception('发卡行标识需至少3个数字与主账号左边3个数字一致') 
     
    if icFldSet['5A'][0:len(issueId)] != issueId: 
        raise Exception('发卡行标识[%s]与主账号左%d位[%s]不一致' % (icFldSet['5A'][0:len(issueId)], len(issueId), issueId)) 
    
    '''
           恢复的发卡行公钥中去除填充数据
           如果NI≤NCA–36，字段包含了在右边补上了NCA–36–NI个值为BB的字节的整个发卡行公钥。  
           如果NI>NCA-36，字段包含了发卡行公钥最高位的NCA–36个字节
    '''
    ca_len = len(icFldSet['90'])/2
    issue_len = int(certificate['ISSUE'].pubKeyLen, 16)
    if issue_len <= ca_len - 36:
        issuepubkey = certificate['ISSUE'].pubKey[0:issue_len*2]
    elif issue_len > ca_len - 36:
        if icFldSet.has_key('92') == False:
            raise Exception('缺少发卡行公钥余项数据')
        issuepubkey = certificate['ISSUE'].pubKey + icFldSet['92'] 

    return issuepubkey 

def PbocRecoverICPubKey(issuePubKey='', staticDataes='', icFldSet={}): 
    ''' 
          恢复IC公钥 
    ''' 
    rsa = PbocRsa(issuePubKey, icFldSet['9F32'])
    decrypted = rsa.pbocSignDataRecover(icFldSet['9F46']) 
    # print 'recover issue certificate : ', decrypted 
    certificate = rsa.pbocPubKeyCertParse(decrypted, 'IC') 
    ''' 
          根据PBOC规范说明检查IC卡公钥证书 
    ''' 
    try: 
        certificate['IC'].certificateCheck() 
    except Exception, e: 
        raise Exception(e) 
    ''' 
          重新计算HASH 
    ''' 
    #certificate['IC'].showCertificate()
    srcdata = decrypted[2:len(decrypted)-42]
    if icFldSet.has_key('9F48'): 
        srcdata += icFldSet['9F48'] 
    srcdata += icFldSet['9F47']
    srcdata += staticDataes
    if icFldSet.has_key('9F4A'): 
        if icFldSet['9F4A'] != '82': 
            raise Exception('静态数据认证标签列表存在并且其包含非82的标签,不符合PBOC规范要求') 
        else: 
            srcdata += icFldSet['82'] 
    print '进行HASH计算源数据  : ', srcdata 
    hashmessage = ''.join(map(chr, toBytes(srcdata))) 
    hashvalue = toHexString(map(ord, list(Hash(hashmessage, 'SHA-%d' % int(certificate['IC'].hashAlgId, 16)))), format=1) 
    if hashvalue != certificate['IC'].hashVal: 
        raise Exception('终端计算hash[%s]与证书hash[%s]不一致' % (hashvalue, certificate['IC'].hashVal)) 
    print 'IC卡公钥证书恢复成功，终端计算hash[%s]与证书hash[%s]一致' % (hashvalue, certificate['IC'].hashVal) 
    ''' 
           检验恢复得到的主账号和从IC卡读出的应用主账号是否相同
    ''' 
    if icFldSet['5A'] != certificate['IC'].pan: 
        raise Exception('从IC卡读出的应用主账号[%s]与恢复IC卡公钥证书得到的主账号[%s]不一致' % (icFldSet['5A'], certificate['IC'].pan)) 

    '''
           恢复的IC卡公钥中去除填充数据
           如果NIC≤NI–42，这个字段包含了在右边补上了 NI–42–NIC个值为 BB的字节的整个IC卡公钥。 
           如果NIC>NI-42，这个字段包含了IC卡公钥最高位的 NI–42个字节 
    '''
    issue_len = len(issuePubKey)/2
    ic_len    = int(certificate['IC'].pubKeyLen, 16)
    if ic_len <= issue_len - 42:
        icpubkey = certificate['IC'].pubKey[0:ic_len*2]
    elif ic_len > issue_len - 42:
        if icFldSet.has_key('9F48') == False:
            raise Exception('缺少IC卡公钥余项数据')
        icpubkey = certificate['IC'].pubKey + icFldSet['9F48']
 
    return icpubkey
 
def PbocSDA(caPubKeySet={}, icFldSet={}, staticRecordLst=[]): 
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
        # print 'record',record 
        if record[1][:2] != '70': 
            raise Exception('SDA失败:用于脱机数据认证的记录的标签必须为70') 
        if ((record[0] >> 8) & 0x1F) in range(1, 11): 
            staticDataes += parseTag70(record[1]) 
        elif ((record[0] >> 8) & 0x1F) in range(11, 31): 
            staticDataes += record[1] 
        else: 
            raise Exception('SDA失败:存储IC卡参与认证的静态数据的SFI必须为1到30之间') 
        # print 'record',record 
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
    # signeddataobj.showsignData() 
     
    ''' 
           重新计算HASH 
    ''' 
    if icFldSet.has_key('9F4A'): 
        if icFldSet['9F4A'] != '82': 
            raise Exception('SDA失败:静态数据认证标签列表存在并且其包含非82的标签') 
        else: 
            staticDataes += icFldSet['82'] 
    print '参与SDA的IC卡源数据: [%s]' % staticDataes 
    print '进行HASH计算源数据  : ', decrypted[2:len(decrypted) - 42] + staticDataes 
    hashmessage = ''.join(map(chr, toBytes(decrypted[2:len(decrypted) - 42] + staticDataes))) 
    hashvalue = toHexString(map(ord, list(Hash(hashmessage, 'SHA-%d' % int(signeddataobj.hashAlgId, 16)))), format=1) 
    # print 'hashvalue : ',hashvalue 
    if hashvalue != signeddataobj.hashVal: 
        raise Exception('SDA失败:终端计算hash[%s]与签名数据中hash[%s]不一致' % (hashvalue, signeddataobj.hashVal)) 
    print '静态数据HASH校验成功，终端计算hash[%s]与签名数据中hash[%s]一致' % (hashvalue, signeddataobj.hashVal) 
    print '----------------------进行静态数据认证(SDA)过程成功----------------------------' 
     
    icFldSet['9F45'] = signeddataobj.dataVerCode 
    
def PbocDDA(caPubKeySet={}, icFldSet={}, staticRecordLst=[]): 
    ''' 
    DDA 
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
    print '----------------------开始进行动态数据认证(DDA)过程----------------------------' 
    staticDataes = '' 
    for record in staticRecordLst: 
        # print 'record',record 
        if record[1][:2] != '70': 
            raise Exception('DDA失败:用于脱机数据认证的记录的标签必须为70') 
        if ((record[0] >> 8) & 0x1F) in range(1, 11): 
            staticDataes += parseTag70(record[1]) 
        elif ((record[0] >> 8) & 0x1F) in range(11, 31): 
            staticDataes += record[1] 
        else: 
            raise Exception('DDA失败:存储IC卡参与认证的静态数据的SFI必须为1到30之间') 
        # print 'record',record 
    ''' 
           恢复发卡行公钥 
    ''' 
    try: 
        issuepubkey = PbocRecoverIssuePubKey(caPubKeySet, icFldSet)
    except Exception,e: 
        raise Exception(e) 
      
    print '发卡行公钥  issuepubkey : [%s]' % issuepubkey 
    
    '''
           恢复IC卡公钥
    '''
    try: 
        icpubkey = PbocRecoverICPubKey(issuepubkey, staticDataes, icFldSet)
    except Exception,e: 
        raise Exception(e)
      
    print 'IC卡公钥  icpubkey : [%s]' % icpubkey
    
    '''
           发出内部认证（INTERNAL AUTHENTICATE）命令，命令中包含由DDOL指定的数据元
    '''
    
    
    print '----------------------进行动态数据认证(DDA)过程成功----------------------------' 
    
#---------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    from rsa.key import PublicKey
    icFldSet = {}
    caPubKeySet = {}
    staticRecordLst = []
    
    TagCa = 'CF9FDF46B356378E9AF311B0F981B21A1F22F250FB11F55C958709E3C7241918293483289EAE688A094C02C344E2999F315A72841F489E24B1BA0056CFAB3B479D0E826452375DCDBB67E97EC2AA66F4601D774FEAEF775ACCC621BFEB65FB0053FC5F392AA5E1D4C41A4DE9FFDFDF1327C4BB874F1F63A599EE3902FE95E729FD78D4234DC7E6CF1ABABAA3F6DB29B7F05D1D901D2E76A606A8CBFFFFECBD918FA2D278BDB43B0434F5D45134BE1C2781D157D501FF43E5F1C470967CD57CE53B64D82974C8275937C5D8502A1252A8A5D6088A259B694F98648D9AF2CB0EFD9D943C69F896D49FA39702162ACB5AF29B90BADE005BC157'
    ca_e  = '03'
    icFldSet['90'] = '35A8ADF591012BE2A218E039FF8FB086A6A4E744947017942D1B26D2CC22B08BC64B529896ECD00E0279330B216BDB8A8554E04E554BB389FFDE721D3102BF9F6F4D0F9995FCB8582BA9EA5E220B19CBF45F5272B31EEAF2552AD6C4DCC324591AEF809531EF5EDC92950D1D852CBF367B9081DB7BDFE543BEA906FD1948304B4E9A93B52D9FCEEF1B550F91347F6D25CE294BE1C0B50DFAC6C8B8832CA4A040E77B1E32C7BB3C089082EE212A5620B1BF685D7E83EE74F0B062DAE45FDFCDB2ED904959112642E6C45FDC77520F7DB921EA14AD01A8297DCF151C8D68675DC76F716151333BC039A37FE7CFE585FDBAC3C5B44F636549E3'
    icFldSet['92'] = ''
    icFldSet['9F32'] = '03'
    icFldSet['9F4A'] = '82'
    icFldSet['9F46'] = 'A11750E94CFE19CE64EBE53435BCAEF60ACFD564C8C9499580634D3A46F44057524AA57E9C0EC82BE69A76E11281FFD3F53DC20BE99378A8F2C2C98408327B4F97625EC254C96EC2B1E9A22693721740AA0F5E648496D8327AD7AB5307ECA2A3D79C76A9EE63A78E3F2E3419D25D93BDCA5208DCD1A99D93677C5F4E8EE6707F2B8C0C07BCEAD455ACA25B5393E4343E1A60DBEC375D275577B8BF9654B3D41F232BF3B29894D59D1B41BC2A9F503761'
    icFldSet['9F47'] = '03'
    icFldSet['9F48'] = ''
    icFldSet['8F']   = '0B'
    icFldSet['5A']   = '622908115461736415FF'
    icFldSet['93']   = 'AAA632168F0E894B79E84C68297152461841CA2012DC18B551495D3DEE293EF252DF8C1B5F9BFCA31223CA553A431F454ED5DE599594661E356D6D4710FAF95A652C216273A85FC8843175578547EFA57B474714FDA596C71ACA2A8C32F3328F933471CB56E9F3EF266EC8DA60C961692E4066A4F91711D034307D2C3A2A8CEF931EE11822FDEFD708FD48E48795F14027AD06BED22CE5BF5AADC5E8EA6C07D40198B2DA8CBAF7AED098D28CF77873AF'
    icFldSet['82']   = '7C00'
    #-----------------------------------------------------
    ca = PublicKey(int(TagCa, 16), int(ca_e, 16))
    caPubKeySet['0B'] = ca
    #-----------------------------------------------------
    staticRecordLst.append((int('0201', 16),'70505A096229081154617364155F3401018E0C000000000000000042031F009F0D05D0601CA8009F0E0500108000009F0F05D0681CF8005F24032403305F280201569F0702FF005F25031603309F08020030'))
    #-----------------------------------------------------
    
    try:
        PbocSDA(caPubKeySet, icFldSet, staticRecordLst)
    except Exception,e:
        print e
        sys.exit(1)
    
    try:
        PbocDDA(caPubKeySet, icFldSet, staticRecordLst)
    except Exception,e:
        print e
        sys.exit(1)
