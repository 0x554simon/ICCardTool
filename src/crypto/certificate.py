# -*-coding:utf-8-*-
'''
Created on 2016-4-1

@author: 014731
'''

import time

class PbocCertificate(object):
    '''
    pboc certificate
    '''
    def __init__(self, headbyte, formate, expDate, certSsn, hashAlgId, pubKeyAlgId, pubKeyLen, eKeyLen, pubKey, hashVal, endbyte):
        '''
        Constructor
        '''
        self.headbyte = headbyte
        self.formate  = formate
        self.expDate  = expDate
        self.certSsn  = certSsn
        self.hashAlgId= hashAlgId
        self.pubKeyAlgId = pubKeyAlgId
        self.pubKeyLen = pubKeyLen
        self.eKeyLen  = eKeyLen
        self.pubKey   = pubKey
        self.hashVal  = hashVal
        self.endbyte  = endbyte
        
    def certificateCheck(self):
        '''
        check the public key certificate by format defined in POBC document
        the certificate begins with '6A', end with 'BC', 
        the certificate expire date must be equal/after current date
        '''
        
        #check the header
        if self.headbyte != '6A':
            raise Exception('This certificate has wrong header [%s], it should be [%s]' % (self.headbyte, '6A'))
        
        #check the tail
        if self.endbyte != 'BC':
            raise Exception('This certificate has wrong endbyte [%s], it should be [%s]' % (self.endbyte, 'BC'))
        
        #check the expire date
        currdate = time.localtime()
        currdate_int = int('%04d%02d' % (currdate[0], currdate[1]))
        expiredate_int = int('20'+self.expDate[2:4]+self.expDate[0:2])
        if currdate_int > expiredate_int:
            raise Exception('This certificate had expired, expire date : [%d] < current date : [%d]' % (expiredate_int, currdate_int))

    
    def showCertificate(self, diffrence):
        print '%s' % self.headbyte
        print '%s' % self.formate
        print '%s' % diffrence
        print '%s' % self.expDate
        print '%s' % self.certSsn
        print '%s' % self.hashAlgId
        print '%s' % self.pubKeyAlgId
        print '%s' % self.pubKeyLen
        print '%s' % self.eKeyLen
        print '%s' % self.pubKey
        print '%s' % self.hashVal
        print '%s' % self.endbyte

class IssueCertificate(PbocCertificate):
    '''
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
    '''

    def __init__(self, headbyte, formate, issueId, expDate, certSsn, hashAlgId, issuePubKeyAlgId, pubKeyLen, eKeyLen, pubKey, hashVal, endbyte):
        '''
        Constructor
        '''
        self.issueId  = issueId
        super(IssueCertificate, self).__init__(headbyte, formate, expDate, certSsn, hashAlgId, issuePubKeyAlgId, pubKeyLen, eKeyLen, pubKey, hashVal, endbyte)
        
        
    def certificateCheck(self):
        '''
        check the public key certificate by format defined in POBC document
        the certificate begins with '6A', end with 'BC', issue public key certificate format is '02'
        the certificate expire date must be equal/after current date
        '''
       
        #check the format
        if self.formate != '02':
            raise Exception('This certificate has wrong format [%s], it should be [%s]' % (self.formate, '02'))
        
        try:
            super(IssueCertificate,self).certificateCheck()
        except Exception,e:
            raise Exception(e)
    
    def showCertificate(self):
        print 'issue certificate :'
        super(IssueCertificate,self).showCertificate(self.issueId)
        
    def __str__(self):
        return '%s%s%s%s%s%s%s%s%s%s%s%s' % (self.headbyte,self.formate,self.issueId,self.expDate,\
                                             self.certSsn,self.hashAlgId,self.pubKeyAlgId,self.pubKeyLen,\
                                             self.eKeyLen,self.pubKey,self.hashVal,self.endbyte)

class ICCertificate(PbocCertificate):
    '''
    issue certificate format:
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

    def __init__(self, headbyte, formate, pan, expDate, certSsn, hashAlgId, icPubKeyAlgId, pubKeyLen, eKeyLen, pubKey, hashVal, endbyte):
        '''
        Constructor
        '''
        self.pan  = pan
        super(ICCertificate, self).__init__(headbyte, formate, expDate, certSsn, hashAlgId, icPubKeyAlgId, pubKeyLen, eKeyLen, pubKey, hashVal, endbyte)
        
    def certificateCheck(self):
        '''
        check the public key certificate by format defined in POBC document
        the certificate begins with '6A', end with 'BC', ic public key certificate format is '04'
        the certificate expire date must be equal/after current date
        '''
        #check the format
        if self.formate != '04':
            raise Exception('This certificate has wrong format [%s], it should be [%s]' % (self.formate, '04'))
        
        try:
            super(ICCertificate,self).certificateCheck()
        except Exception,e:
            raise Exception(e)
    
    def showCertificate(self):
        print 'ic card certificate :'
        super(ICCertificate,self).showCertificate(self.pan)

    def __str__(self):
        return '%s%s%s%s%s%s%s%s%s%s%s%s' % (self.headbyte,self.formate,self.pan,self.expDate,\
                                             self.certSsn,self.hashAlgId,self.pubKeyAlgId,self.pubKeyLen,\
                                             self.eKeyLen,self.pubKey,self.hashVal,self.endbyte)
       
class PbocSignData(object):
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
    def __init__(self, headbyte, formate, hashAlgId, dataVerCode, paddingDataes, hashVal, endbyte):
        '''
        Constructor
        '''
        self.headbyte     = headbyte
        self.formate      = formate
        self.hashAlgId    = hashAlgId
        self.dataVerCode  = dataVerCode
        self.paddingDataes= paddingDataes
        self.hashVal      = hashVal
        self.endbyte      = endbyte
        
    def signDataCheck(self):
        '''
        check the public key certificate by format defined in POBC document
        the certificate begins with '6A', end with 'BC', 
        '''
        
        #check the header
        if self.headbyte != '6A':
            raise Exception('This signed data has wrong header [%s], it should be [%s]' % (self.headbyte, '6A'))
        
        #check the tail
        if self.endbyte != 'BC':
            raise Exception('This signed data has wrong endbyte [%s], it should be [%s]' % (self.endbyte, 'BC'))
        
        #check the format
        if self.formate != '03':
            raise Exception('This signed data has wrong format [%s], it should be [%s]' % (self.formate, '03'))
    
    def showsignData(self):
        print 'Tag 93 :'
        print '%s' % self.headbyte
        print '%s' % self.formate
        print '%s' % self.hashAlgId
        print '%s' % self.dataVerCode 
        print '%s' % self.paddingDataes
        print '%s' % self.hashVal  
        print '%s' % self.endbyte

#----------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import sys
    issueCert = IssueCertificate('6A','02','625961FF','1230','003979','01','01','B0','01','B04DD13135310298D3CCFD05956E0F2E3694A491C3869E72077A419E585F720D7875EB8804DCD0D731603009D11F3EB3BE3AE70A602B5D02E4D94AC02CF7C2666D8A768CD6FB5BC532957FAD4658E5400981728C1B3D81CC1F7117BB144BB061276ABCDF80ECA9172A1133314F61E8EB248934C982276F35C9F6DE8BA1F6F7B0FF7459D1067D6C4B3B429A30DD706287067E1CA4A5BB2A05B0D90681A641B2B5D42785B0AAF4118DFCC1C56D92179E91BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB','097E642D7479C99B0B9B1ED444D832269878FF51','BC')
    try:
        issueCert.certificateCheck()
    except Exception,e:
        print e
        print 'certificate check failed'
        sys.exit(1)
    issueCert.showCertificate()
    #---------------------------------------------------------
    print '-'*120
    icCert = ICCertificate('6A','04','625961FF','1230','622908115461736415FF','01','01','B0','01','B04DD13135310298D3CCFD05956E0F2E3694A491C3869E72077A419E585F720D7875EB8804DCD0D731603009D11F3EB3BE3AE70A602B5D02E4D94AC02CF7C2666D8A768CD6FB5BC532957FAD4658E5400981728C1B3D81CC1F7117BB144BB061276ABCDF80ECA9172A1133314F61E8EB248934C982276F35C9F6DE8BA1F6F7B0FF7459D1067D6C4B3B429A30DD706287067E1CA4A5BB2A05B0D90681A641B2B5D42785B0AAF4118DFCC1C56D92179E91BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB','097E642D7479C99B0B9B1ED444D832269878FF51','BC')
    try:
        icCert.certificateCheck()
    except Exception,e:
        print e
        print 'certificate check failed'
        sys.exit(1)
    icCert.showCertificate()