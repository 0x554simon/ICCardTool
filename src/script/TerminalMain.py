# -*-encoding:utf-8-*-
'''
Created on 2016-3-25

@author: ThinkPad
'''
import sys
import smartcard.System as st
import apdu.ApduCmdSet as cmdset
import apdu.FileIdentify as sfname
import crypto.pbocrsa as pbocrsa
from tlv.tlvparse import parse, parsePdol, parseAFL
from apdu.APDU import CAPDU,RAPDU
from util.CfgParser import CfgParser
from util.MyRandom import MyRandom
from session.ICSession import ICSession
from smartcard.util import toHexString,toBytes
from crypto.authentication import PbocSDA

def showReaders():
    readers = st.listReaders()
    print 'All smart card readers : '
    
    i = 0
    print '%6s | %-s' % ('Index ','ReaderName')
    print '-'*(len('Index  | ')+len('ReaderName'))
    while i < len(readers):
        print '[%4d] | %-s' % (i, readers[i])
        i += 1
    print '-'*(len('Index  | ')+len('ReaderName'))
    return readers

def selectIndex(entities):
    '''
    return the index is chosen
    '''
    if len(entities) == 0:
        print 'ERROR: There is no entity available'
        return None
    if len(entities) == 1:
        '''
        only one choice
        '''
        return 0    
    
    while True:
        idx = raw_input('please select the index for selecting option: ').replace('\n','')
        if idx.isdigit() == False:
            print 'ERROR: the index must be number, please select again'
            continue
        
        if int(idx) < 0 or int(idx) >= len(readers):
            print 'ERROR: Unavailable index, please select again'
            continue
        else:
            break
    return int(idx)

def showDictData(dictData={}):
    for key in dictData:
        print '[%4s] : [%s]' % (key, dictData[key])

def showAIDS(aids=[]):
    print 'All AIDS supported in smart card: '
    i = 0
    print '%6s | %-s' % ('Index ','aidName')
    print '-'*(len('Index  | ')+len('aidName'))
    while i < len(aids):
        print '[%4d] | %-s' % (i, aids[i])
        i += 1
    print '-'*(len('Index  | ')+len('aidName'))
   
def choiceAID(aids=[]):
    '''
    return the index is chosen
    '''
    if aids == []:
        return None

    showAIDS(aids)
    return selectIndex(aids)
     
#---------------------------------------------------------------------------------------------------------------  
if __name__ == '__main__':
    
    readers = showReaders()
    idx = selectIndex(readers)
    if idx is None:
        sys.exit(1)
    readerName = str(readers[idx])
    print readerName
    capdu = CAPDU()
    
    try:
        flddict = {}
        aidset  = []
        session = ICSession(readerName=readerName)
        atrhex  = session.getHexAtr()
        print 'Card Reset ATR : ', atrhex
        print '----------------------------------------begin apdu--------------------------------------------------'
        '''
        select PSE, get file control info
        '''
        capdu.cla = cmdset.ApduCmdSet.PBOC_SELECT[:1]
        capdu.ins = cmdset.ApduCmdSet.PBOC_SELECT[1:]
        '''
        p1 : 0x04  - selected by name
        '''
        capdu.p1  = [0x04]
        '''
        p2 : 0x00  - the first or only one
        '''
        capdu.p2  = [0x00]
        capdu.lc  =[len(sfname.FileIdentify.PSE)]
        capdu.data= sfname.FileIdentify.PSE
        capdu.le  = [0x00]
        PSE_select_cmd = capdu.packCapdu()
        response, sw1sw2 = session.sendApdu(PSE_select_cmd)
        print 'SELECT PSE :\n> capdu    = [%s]\n< response = [%s] sw1sw2 = [%s]' % (toHexString(PSE_select_cmd),response, sw1sw2)
        flddict = parse(response, flddict)
        showDictData(flddict)
        print '-'*120
        #---------------------------------------------------
        '''
        reader PSE0101 - PSExxnn from ic card, xx = the value of Tag88 in select pse response,nn=02,03,04,...
        '''
        capdu.cla = cmdset.ApduCmdSet.PBOC_READ_RECORD[:1]
        capdu.ins = cmdset.ApduCmdSet.PBOC_READ_RECORD[1:]
        capdu.lc  = []
        capdu.data= []
        capdu.le  = [0x00]
        capdu.p2  = [(int(flddict['88'], 16)<<3)|0x04]
        i = 1
        while True:
            capdu.p1 = [i]
            i += 1
            PSE_read_record = capdu.packCapdu()
            response, sw1sw2 = session.sendApdu(PSE_read_record)
            '''
            sw1sw2 = 6A83, record not found, end the loop
            '''
            if sw1sw2 == '6A83':
                break
            
            print 'Read Record PSE01%02X :\n> capdu    = [%s]\n< response = [%s] sw1sw2 = [%s]' % (capdu.p1[0],toHexString(PSE_read_record),response, sw1sw2)
            if sw1sw2 != '9000':
                print 'apdu execute failed, response sw1sw2 = [%s]' % sw1sw2
                sys.exit(1)
            flddict = parse(response, flddict)
            showDictData(flddict)      
            print '-'*120
        #---------------------------------------------------
        '''
        flddict['4F'].append('A000000333010102')
        flddict['4F'].append('A000000333010106')
        '''
        '''
        user chose the AID
        '''
        aidIdx = choiceAID(flddict['4F'])
        '''
        select AID, get file control info
        '''
        capdu.cla = cmdset.ApduCmdSet.PBOC_SELECT[:1]
        capdu.ins = cmdset.ApduCmdSet.PBOC_SELECT[1:]
        capdu.lc  = [len(flddict['4F'][aidIdx])/2]
        capdu.data= toBytes(flddict['4F'][aidIdx])
        '''
        p1 : 0x04  - selected by name
        '''
        capdu.p1  = [0x04]
        '''
        p2 : 0x00  - the first or only one
        '''
        capdu.p2  = [0x00]
        capdu.le  = [0x00]
        AID_select_cmd = capdu.packCapdu()
        response, sw1sw2 = session.sendApdu(AID_select_cmd)
        print 'SELECT AID :\n> capdu    = [%s]\n< response = [%s] sw1sw2 = [%s]' % (toHexString(AID_select_cmd),response, sw1sw2)
        flddict = {}
        flddict = parse(response, flddict)
        #showDictData(flddict) 
        print '-'*120
        #---------------------------------------------------
        '''
        GPO, get AFL list
        GPO data : 83 XX values which tag defined in PDOL(9F38)
        '''
        cfgobj = CfgParser('../conf/terminal.conf')
        tflddict = {}
        cfglst = cfgobj.GetCfgSection('TERMINAL_TAG')
        for member in cfglst:
            tflddict[member[0].upper()] = member[1]
        if tflddict.has_key('9F37') == False:
            random = MyRandom()
            tflddict['9F37'] = random.genTerminalRandom()
        pdolTag = parsePdol(flddict['9F38'])
        #print pdolTag
        pdolData = ''
        for member in pdolTag:
            pdolData += tflddict[member[0]]
        #print pdolData
        pdolData = '83'+'%02X' % (len(pdolData)/2)+pdolData
        GPO_cmd = cmdset.ApduCmdSet.PBOC_GET_PROCESSING_OPTIONS
        GPO_cmd.append(len(pdolData)/2)
        GPO_cmd += toBytes(pdolData)
        GPO_cmd.append(0x00)
        response, sw1sw2 = session.sendApdu(GPO_cmd)
        print 'GPO :\n> capdu    = [%s]\n< response = [%s] sw1sw2 = [%s]' % (toHexString(GPO_cmd),response, sw1sw2)
        rapdu = RAPDU(toBytes(response), toBytes(sw1sw2[0:2]), toBytes(sw1sw2[2:4]))
        flddict.update(rapdu.parseGPORsp())
        #showDictData(flddict)
        print '-'*120
        #---------------------------------------------------
        '''
        parse AFL, read record
        '''
        readRecords,signRecords = parseAFL(toBytes(flddict['94']))
        print '--',readRecords
        print '--',signRecords
        '''
        static data record must be in order when record more than one
        so wo use list to save the record data, [(dgi, dgi_data)...]
        '''
        staticRecordLst = []
        for dgi in readRecords:
            capdu.cla = cmdset.ApduCmdSet.PBOC_READ_RECORD[:1]
            capdu.ins = cmdset.ApduCmdSet.PBOC_READ_RECORD[1:]
            capdu.p1  = [dgi & 0x00FF]
            capdu.p2  = [(dgi>>5)|0x04]
            capdu.lc  = []
            capdu.data= []
            capdu.le  = [0x00]
            READ_RECORD_cmd = capdu.packCapdu()
            response, sw1sw2 = session.sendApdu(READ_RECORD_cmd)
            print 'READ RECORD %04X :\n> capdu    = [%s]\n< response = [%s] sw1sw2 = [%s]' % (dgi, toHexString(READ_RECORD_cmd),response, sw1sw2)
            flddict = parse(response, flddict)
            #showDictData(flddict)
            
            if dgi in signRecords:
                staticRecordLst.append((dgi, response))
        print '-'*120
        print '----------------------------------------end  apdu--------------------------------------------------'
        #print 'staticRecordLst :',staticRecordLst
        PbocSDA(pbocrsa.loadPublicKey(), flddict, staticRecordLst)
        showDictData(flddict)
        session.close()
    except Exception,e:
        print e
    
    