# -*-encoding:utf-8-*-
'''
Created on 2016-3-24

@author: 014731
'''
from tlv.tlvparse import parse
from smartcard.util import toHexString as Bytes2HexString

class CAPDU(object):
    '''
    C-APDU  :
    CLA  INS  P1  P2  Lc  Data  Le
    CLA    command class
    INS    command code
    P1、P2 params
    Lc     length of data
    Data   data, contain the MAC if needed
    Le     max length of response you need
    '''

    def __init__(self,cla=[0x00],ins=[0x00],p1=[0x00],p2=[0x00],lc=[],data=[],le=[]):
        '''
        __init__
        params list:
        @cla   byte  list default[0x00]
        @ins   byte  list default[0x00]
        @p1    byte  list default[0x00]
        @p2    byte  list default[0x00]
        @lc    byte  list default[]
        @data  bytes list default[]
        @le    byte  list default[]
        '''
        self.cla  = cla
        self.ins  = ins
        self.p1   = p1
        self.p2   = p2
        self.lc   = lc
        self.data = data
        self.le   = le
        
    def packCapdu(self):
        '''
        packcapdu, C-APDU: CLA+INS+P1+P2+Lc+Data+Le
        '''
        if self.cla is None or self.ins is None:
            print 'CLA or INS is None'
            raise Exception('''CLA or INS can't None''')
            
        capdu = []
        capdu += self.cla
        capdu += self.ins
        capdu += self.p1
        capdu += self.p2
        capdu += self.lc
        capdu += self.data
        capdu += self.le
        
        return capdu
    
    def formatstr(self):
        capdu = self.packCapdu()
        print 'CAPDU : [%s]' % Bytes2HexString(capdu)
    
class RAPDU(object):
    '''
    R-APDU response struct:
    DATA  SW1  SW2
    DATA    response data
    SW1     statusword 1
    SW2     statusword 2
    '''
    def __init__(self, data=[], sw1=0x00, sw2=0x00):
        '''
        __init__
        params list:
        @data   bytes  default []
        @sw1    int    default 0x00
        @sw2    int    default 0x00
        '''
        self.data = data
        self.sw1  = sw1
        self.sw2  = sw2
    
    def getHexResponse(self):
        '''
        getResponse, return hexstring format : (response, statusWord)
        '''
        response   = Bytes2HexString(self.data, format = 1)
        statusWord = '%02X%02X' % (self.sw1, self.sw2)
        return (response, statusWord)
    
    def parseGPORsp(self):
        '''
        GPO response has tow format:
        format 1:  Tag80 len AIP AFL
        format 2:  Tag77 len TLV1 ... TLV(n)
        '''
        if self.data[1:2][0] - len(self.data[2:]) != 0:
            print 'GPO response data length error'
            return None
        
        resdict = {}   
        if self.data[0:1][0] & 0x80 == 0x80:
            '''
            format 1 : Tag80 len AIP AFL
            '''
            resdict['82'] = Bytes2HexString(self.data[2:4], format = 1)
            resdict['94'] = Bytes2HexString(self.data[4:], format = 1)
        elif self.data[0:1][0] & 0x77 == 0x77:
            '''
            format 2 : Tag77 len TLV1 ... TLV(n)
            '''
            resdict = parse(Bytes2HexString(self.data[2:], format = 1), resdict)
        
        return resdict

    def formatstr(self):
        print 'RAPDU : [%s] [%02X %02X]' % (Bytes2HexString(self.data), self.sw1, self.sw2)

#-------------------------------------------------------------------------------------------
if __name__ == '__main__':
    Capdu = CAPDU(cla=[0xA0],ins=[0xA4],p1=[0x00],p2=[0x00],lc=[0x02],data=[0x7F],le=[0x10])
    Capdu.formatstr()
    print '-'*120
    Rapdu = RAPDU(data = [0xA0, 0xA4, 0x00, 0x00, 0x02], sw1 = 0x90, sw2 = 0x00)
    print Rapdu.getHexResponse()
    Rapdu.formatstr()
    
        