#-*-encoding:utf-8-*-
'''
Created on 2016-3-24

@author: 014731
'''
from apdu.APDU import CAPDU
from apdu.ApduCmdSet import ApduCmdSet
from smartcard.Session import Session
from smartcard.util import toHexString as Bytes2HexString

class ICSession(Session,object):
    '''
    classdocs
    '''
    def __init__(self,readerName=None, cardServiceClass=None):
        super(ICSession, self).__init__(readerName = readerName, cardServiceClass = cardServiceClass)
    
    def getHexAtr(self):
        '''
        getHexAtr(self) -> hexStringAtr
        hexstring atr format
        '''
        return Bytes2HexString(self.getATR(), format = 1)
    
    def sendApdu(self, command):
        '''
        sendApdu(self, command) -> (hexStringResponse, hexStringSw1Sw2)
        command:    list of APDU bytes, e.g. [0xA0, 0xA4, 0x00, 0x00, 0x02]
        '''
        cmd = command[0:]
        capdu = CAPDU()
        response = []
        while True:
            response[len(response):], sw1,sw2 =self.sendCommandAPDU(cmd)
            '''
            sw1 == 0x61
            remain data len = sw2
            '''
            if sw1 == 0x61 or sw1 == 0x9F:
                capdu.cla = [ApduCmdSet.GET_RESPONSE[0]]
                capdu.ins = [ApduCmdSet.GET_RESPONSE[1]]
                capdu.p1  = [0x00]
                capdu.p2  = [0x00]
                capdu.lc  = []
                capdu.data = []
                capdu.le  = [sw2]
                
                cmd = capdu.packCapdu()
            elif sw1 == 0x6C:
                '''
                sw1 = 0x6C, resend the same apdu, but le =sw2
                '''
                cmd[-1] = sw2
            else:
                break
        '''
        bytes response contains sw1sw2, so we delete them before returning
        '''
        return (Bytes2HexString(response, format = 1)[:-4], "%02X%02X" % (sw1, sw2))

#----------------------------------------------------
if __name__ == '__main__':
    from tlv.tlvparse  import parse
    import smartcard
    readerlst = smartcard.System.readers()
    print readerlst
    icsession = ICSession(readerName=str(readerlst[0]), cardServiceClass=None)
    print 'ATR :',icsession.getHexAtr()
    command = [0x00, 0xA4, 0x04, 0x00,0x0E,0x32,0x50,0x41,0x59,0x2E,0x53,0x59,0x53,0x2E,0x44,0x44,0x46,0x30,0x31]+[0x00]
    response, statusword = icsession.sendApdu(command)
    print 'response : %s sw1sw2: %s' % (response, statusword)
    fld = {}
    fld = parse(response,fld)
    print 'response : ', fld
    command = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0,0x00,0x00,0x03,0x33,0x01,0x01,0x01] + [0x00]
    response, statusword = icsession.sendApdu(command)
    print 'response : %s sw1sw2: %s' % (response, statusword)
    fld = {}
    fld = parse(response,fld)
    print 'response : ', fld
    icsession.close()
        