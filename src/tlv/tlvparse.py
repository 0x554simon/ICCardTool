# -*-encoding:utf-8-*-
'''base=[0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F]'''
base = [str(x) for x in range(0, 10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]

class TLV:
    def init(self):
        self.tag = ""
        self.len = 0
        self.val = ""
    
    def setTag(self, tag):
        self.tag = tag

    def setLen(self, leng):
        self.len = leng

    def setVal(self, val):
        self.val = val

    def getTag(self):
        return self.tag

    def getLen(self):
        return self.len
 
    def getVal(self):
        return self.val


    def showTLV(self):
        print "-"*32
        print "-Tag : %s\n-Len : %02X\n-Val : %s" % (self.tag, self.len, self.val)
        print "-"*32

'''hexstr convert to dec'''
def hexstr2dec(hexstr):
    return int(hexstr.upper(), 16)

'''dec convert to hexstr'''
def dec2hexstr(dec):
    mid = []
    while True:
        if dec == 0:
            break
        dec, rem = divmod(dec, 16)
        mid.append(base[rem])
    hexstr = ''.join(str(x) for x in mid[::-1])
    return (hexstr if len(hexstr) % 2 == 0 else '0' + hexstr)

''' parse tlv format '''
def parse(tlvstr, flddict = {}):
    tlv = TLV()
    fld = flddict
    position = 0
    while True:
        tlv.init()
        if position == len(tlvstr):
            break

        ''' tag '''
        tagfirst = tlvstr[position : 2 + position]
        tagbyte = hexstr2dec(tagfirst)
        ''' base format '''
        if tagbyte & 0x1f != 0x1f:
            ''' one byte '''
            tlv.setTag(tagfirst)
            position += 2
        else:
            ''' two bytes '''
            tlv.setTag(tlvstr[position : 4 + position])
            position += 4

        ''' len '''
        lenfirst = tlvstr[position : 2 + position]
        lenbyte = hexstr2dec(lenfirst)
        if lenbyte & 0x80 == 0x00:
            ''' b1~b7 '''
            tlv.setLen(lenbyte & 0x7f)
            position += 2
        else:
            ''' more bytes '''
            position += 2
            tlv.setLen(hexstr2dec(tlvstr[position : ((lenbyte & 0x7f) * 2) + position]))
            position += (lenbyte & 0x7f) * 2

        ''' val '''
        tlv.setVal(tlvstr[position : position + (tlv.getLen()) * 2])
        position += (tlv.getLen()) * 2

        #tlv.showTLV()

        ''' construct format '''
        if tagbyte & 0x20 == 0x20:
            parse(tlv.getVal(),fld)
        else:
            if flddict.has_key(tlv.tag):
                if int(tlv.tag, 16) == 0x4F:
                    flddict[tlv.tag] = flddict[tlv.tag].append(tlv.val)
                else: 
                    raise Exception("TAG [%s] duplicate" % tlv.tag)
            else:
                if int(tlv.tag, 16) == 0x4F:
                    flddict[tlv.tag] = [tlv.val]
                else:
                    flddict[tlv.tag] = tlv.val
    return fld

def parsePdol(pdol):
    pdolLst = []
    position = 0
    while True:
        if position == len(pdol):
            break
        ''' tag '''
        tagfirst = pdol[position : 2 + position]
        tagbyte = hexstr2dec(tagfirst)
        ''' base format '''
        if tagbyte & 0x1f != 0x1f:
            ''' one byte '''
            position += 2
            pdolLst.append((tagfirst, pdol[position : 2 + position]))
            position += 2
        else:
            ''' two bytes '''
            pdolLst.append((pdol[position : 4 + position], pdol[position + 4 : 6 + position]))
            position += 6
    return pdolLst
    
def parseAFL(aflbytes):
    '''
    AFL format: one group per 4bytes
    first  byte: sfi
    second byte: first record index
    third  byte: last record index
    fourth byte: the count of records which are sign dataes, AFL's second record is the first
    eg : 08010100 10010400 18010101 20010100
    
    return: (recordBytesLst, signBytesLst)
    '''
    if len(aflbytes) == 0 or len(aflbytes) % 4 != 0:
        print 'AFL format error'
        return None
    
    position = 0
    readRecordLst = []
    signRecordLst = []
    while True:
        if position == len(aflbytes):
            break
        
        afl = aflbytes[position:position+4]
        sfi = afl[0] >> 3
        for idx in xrange(afl[1], afl[2]+1):
            readRecordLst.append((sfi<<8)|idx)
            
        if afl[3] > 0x00:
            for idx in xrange(afl[3]):
                signRecordLst.append((sfi<<8)|(afl[1]+idx))
        position += 4        
    return (readRecordLst, signRecordLst)

def parseTag70(hextag70):
    if hextag70[0:2] != '70':
        return None
    ''' length '''
    position = 2
    lenfirst = hextag70[position : 2 + position]
    lenbyte = hexstr2dec(lenfirst)
    if lenbyte & 0x80 == 0x00:
        ''' b1~b7 '''
        length = lenbyte & 0x7f
        position += 2
    else:
        ''' more bytes '''
        position += 2
        length = hexstr2dec(hextag70[position : ((lenbyte & 0x7f) * 2) + position])
        position += (lenbyte & 0x7f) * 2

    ''' return value '''
    return hextag70[position : position + length * 2] 
#----------------------------------------------------------------------------
if __name__ == '__main__':
    '''
    inputstr = raw_input("input the param : ")
    
    print "TLV FORMAT STRING : %s\n\n" % (inputstr)
    
    parse(inputstr)
    '''
    print parseTag70('7081B49F4681B071200EEA4283710242FDD01F93B43E2E6FFA5AA70CEFEF1996323FFE21E3E6C9DB83EBD01599424C68AA6C1DF381C32E79E40F96CF8C3B243F06B777A4D945E08553F16322B60CC1F3CAD1A7E4A29F08648E810E21BBC7DCBCBA59DBA30067257758C6565DDD80A2E2A4B28B98AE62D107E6B5D65C852EE5879142C576647A58458AD90649997AD952BC9B888B6B5CD9206AFA17BFA8D119C15AB898CA5F6FCAB14D2B7CA0366E998CF105377B947B51')
