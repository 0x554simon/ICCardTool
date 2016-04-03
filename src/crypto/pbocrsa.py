# -*-coding:utf-8-*-
'''
Created on 2016-3-31

@author: 014731
'''
from rsa.key import PublicKey
from rsa import common
from rsa import core
from rsa import transform
from util.CfgParser import CfgParser
from smartcard.util import toHexString

from certificate import IssueCertificate, ICCertificate, PbocSignData

class PbocRsa(object):
    '''
    PBOC RSA calculate
    '''

    def __init__(self, pkey_n=None, pkey_e=None):
        '''
        one public key contains the 'n' and 'e'
        public key : (e, n)
        pkey_n  : public key 'n', format: hexstring
        pkey_e  : public key 'e', format: hexstring
        '''
        if pkey_n is None or pkey_e is None:
            self.pkey = None
        else:
            self.pkey = PublicKey(int(pkey_n, 16), int(pkey_e, 16))
    
    def pbocSignDataRecover(self, sign_data):
        '''
        recover message from signed data
        sign_data : the data signed by private key, format : hexstring
        return value : the message recovered from signed data, format : hexstring
        '''
        bytelen = common.byte_size(self.pkey.n)
        signature = int(sign_data, 16)
        decrypted = core.decrypt_int(signature, self.pkey.e, self.pkey.n)
        lstdata = transform.int2bytes(decrypted, bytelen)
        
        return toHexString((map(ord, lstdata)), format = 1)
    
    def pbocPubKeyCertParse(self, certificate, cert_type):
        '''
        parse PBOC public key certificate
        certificate : pboc public key certificate data, format : hexstring
        cert_type   : the type of certificate, 
                      'ISSUE': issue public key certificate
                      'IC'   : ic card public key certificate
        issue certificate format:
        header  byte         : one byte, '6A'
        certificate format   : one byte, '02'
        issue identify       : four bytes,the left 3-8 numbers of pan, right pad 'F'
        certificate expire date : two bytes, MMYY
        certificate ssn      : three bytes
        hash algorithm identify : one byte
        issue pubkey algorithm identify : one byte
        length of issue public key : one byte
        length of issue public key-e: one byte
        issue public key or left of issue public key : N(ca) - 36 bytes
                                                       N(i) <= N(ca) - 36, it contains N(ca)–36–N(i) bytes 'BB' on
                                                       the right of issue public key
                                                       N(i) > N(ca)-36, it contains the high N(ca) - 36 bytes of issue public key
        hash value  : twenty bytes
        end byte    : one byte, 'BC'
        
        ic card certificate format:
        header  byte         : one byte, '6A'
        certificate format   : one byte, '04'
        PAN                  : ten bytes, right pad 'F'
        certificate expire date : two bytes, MMYY
        certificate ssn      : three bytes
        hash algorithm identify : one byte
        ic  pubkey algorithm identify : one byte
        length of ic public key : one byte
        length of ic public key-e: one byte
        ic public key or left of ic public key : N(i) - 42 bytes
                                                N(ic) <= N(i) - 42, it contains N(i)–42–N(ic) bytes 'BB' on
                                                the right of ic public key
                                                N(ic) > N(i)-42, it contains the high N(i) - 42 bytes of ic public key
        hash value  : twenty bytes
        end byte    : one byte, 'BC'
        '''
        for alp in certificate:
            if alp.upper() not in ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']:
                raise Exception('certificate data format error, the character in certificate must be in [0-9] or in [A-F] or in [a-f]')
            
        if len(certificate) % 2 != 0:
            raise Exception('the length [%d] of certificate error, length must be even number' % len(certificate))
        
        certificateformat = {}
        args = []
        args.append(certificate[0:2])
        args.append(certificate[2:4])

        if cert_type.strip() == 'ISSUE':
            args.append(certificate[4:12])
            args.append(certificate[12:16])
            args.append(certificate[16:22])
            args.append(certificate[22:24])
            args.append(certificate[24:26])
            args.append(certificate[26:28])
            args.append(certificate[28:30])
            args.append(certificate[30:len(certificate) - 42])
            args.append(certificate[len(certificate)-42:len(certificate)-2])
            args.append(certificate[len(certificate)-2:len(certificate)])
            issuecertificate = IssueCertificate(*args)
            certificateformat[cert_type.strip()] = issuecertificate
        elif cert_type.strip() == 'IC':
            args.append(certificate[4:24])
            args.append(certificate[24:28])
            args.append(certificate[28:34])
            args.append(certificate[34:36])
            args.append(certificate[36:38])
            args.append(certificate[38:40])
            args.append(certificate[40:42])
            args.append(certificate[42:len(certificate) - 42])
            args.append(certificate[len(certificate)-42:len(certificate)-2])
            args.append(certificate[len(certificate)-2:len(certificate)])
            iccertificate    = ICCertificate(*args)
            certificateformat[cert_type.strip()] = iccertificate
        else:
            pass
        
        return certificateformat
    
    def pbocSignDataParse(self, sign_data):
        '''
        pboc tag 93 value, format:
        header  byte         : one byte, '6A'
        sign data format     : one byte, '03'
        hash algorithm identify : one byte
        data verify code     : two bytes
        padding bytes        : contains N(i)-26 bytes 'BB'
        hash value  : twenty bytes
        end byte    : one byte, 'BC'
        '''
        for alp in sign_data:
            if alp.upper() not in ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']:
                raise Exception('sign data format error, the character in sign data must be in [0-9] or in [A-F] or in [a-f]')
            
        if len(sign_data) % 2 != 0:
            raise Exception('the length [%d] of sign data error, length must be even number' % len(sign_data))
        
        signdataformat = {}
        args = []
        args.append(sign_data[0:2])
        args.append(sign_data[2:4])
        args.append(sign_data[4:6])
        args.append(sign_data[6:10])
        args.append(sign_data[10:len(sign_data) - 42])
        args.append(sign_data[len(sign_data)-42:len(sign_data)-2])
        args.append(sign_data[len(sign_data)-2:len(sign_data)])
        signdataobj = PbocSignData(*args)
        signdataformat['TAG93'] = signdataobj
        
        return signdataformat
    
def loadPublicKey(cfgfile = '../conf/capubkeys.conf'):
    '''
    load all public key into memory from config file
    '''
    caPublicKeySet = {}
    cfgobj = CfgParser(cfgfile)
    caPubKeyLst = cfgobj.GetCfgSection('CA_PUB_KEYS')
    for ca in caPubKeyLst:
        pki  = ca[0].upper()
        ca_e = '%08X' % int(ca[1].split(',')[0], 16)
        ca_n = ca[1].split(',')[1]
        cakey = PublicKey(int(ca_n, 16), int(ca_e, 16))
        caPublicKeySet[pki] = cakey
    '''
    for elemkey in caPublicKeySet:
        print elemkey,':',caPublicKeySet[elemkey]
    '''    
    return caPublicKeySet
#-----------------------------------------------------------------------------------
if __name__ == '__main__':
    ca_n = 'B0627DEE87864F9C18C13B9A1F025448BF13C58380C91F4CEBA9F9BCB214FF8414E9B59D6ABA10F941C7331768F47B2127907D857FA39AAF8CE02045DD01619D689EE731C551159BE7EB2D51A372FF56B556E5CB2FDE36E23073A44CA215D6C26CA68847B388E39520E0026E62294B557D6470440CA0AEFC9438C923AEC9B2098D6D3A1AF5E8B1DE36F4B53040109D89B77CAFAF70C26C601ABDF59EEC0FDC8A99089140CD2E817E335175B03B7AA33D'
    ca_e = '03'
    
    rsa = PbocRsa(ca_n, ca_e)

    issue90 = '270E57F46BFA7E37C798B6FE9640D870FF55A5CB7877172E63A02757189D84D664B36A8B0E8D3EAFDC22C646B7EEFEC48DBDFFACD6DF1DC041C2E7C3631F65DBDF91A66D0A8401168D54D517364FDC4B87F8CF450B60A5495514B66E90FD47EE19FACDBFBF6E1C2C34C7548A2386945F2D9771002B09A524E442468FB5865144A22B9D96C7F2BAE295CCA37A0638CB8A4C10C90399E8E2342A5D3EDFF569CDF42931D7ED0ED6F6E14DB89F2BBC8AC7EB'

    blocksize = common.byte_size(rsa.pkey.n)
    decrypted = rsa.pbocSignDataRecover(issue90)
    print 'recover issue certificate : ', decrypted
    certificate = rsa.pbocPubKeyCertParse(decrypted, 'ISSUE')
    
    certificate['ISSUE'].showCertificate()
    
    issuepubkey = certificate['ISSUE'].pubKey[0:int(certificate['ISSUE'].pubKeyLen, 16)*2] + 'CF4C774820E4AAE829BE05FBED74E4AC8E4612AD2765B5DB36327A4D7E9E7F1623751B47'
    print 'issuepubkey:', issuepubkey 
    #---------------------------------------------------------------------------------------------------------------    
    issue_n = issuepubkey
    issue_e = '03'
    
    ic9F46 = '71200EEA4283710242FDD01F93B43E2E6FFA5AA70CEFEF1996323FFE21E3E6C9DB83EBD01599424C68AA6C1DF381C32E79E40F96CF8C3B243F06B777A4D945E08553F16322B60CC1F3CAD1A7E4A29F08648E810E21BBC7DCBCBA59DBA30067257758C6565DDD80A2E2A4B28B98AE62D107E6B5D65C852EE5879142C576647A58458AD90649997AD952BC9B888B6B5CD9206AFA17BFA8D119C15AB898CA5F6FCAB14D2B7CA0366E998CF105377B947B51'
    
    rsa = PbocRsa(issue_n, issue_e)
    
    blocksize = common.byte_size(rsa.pkey.n)
    decrypted = rsa.pbocSignDataRecover(ic9F46)
    print 'recover ic certificate : ', decrypted
    certificate = rsa.pbocPubKeyCertParse(decrypted, 'IC')
    
    certificate['IC'].showCertificate()
    
    icpubkey = certificate['IC'].pubKey[0:int(certificate['IC'].pubKeyLen, 16)*2] 
    print 'icpubkey:', icpubkey 
    #----------------------------------------------------------------------------------------------------------
    tag93 = '3AA64E5465167147761ED894C81E13416BB7FEAB45D378C26BAB874151A85404EC2407EFA65D52B1548F19FF12A2489CB9324727F69FF3EAACED86DAF492924B503144CBB2F3D9EDB63CA4BCF2FCB53725D97DF1405E9FF98E55938079108187A4852F273D6C66BACC49F0C43A34A139852C605F8F710FF316C136CCE8B025059582D8C4DDF8CE3A8595A56D8DC33225E889D8B94E12858A52B365CCECC16FCB28A21EE4AD7F66D0A8D6BBB010DD9053'
    decrypted = rsa.pbocSignDataRecover(tag93)
    print 'recover tag93 : ', decrypted
    signdata = rsa.pbocSignDataParse(decrypted)
    
    signdata['TAG93'].showsignData()
    
    tag93hashval = signdata['TAG93'].hashVal
    print 'tag93hashval:', tag93hashval
    print '-'*120
    loadPublicKey()  
        