#-*-encoding:utf-8-*-
'''
Created on 2016-3-27

@author: ThinkPad
'''
import random

class MyRandom(random.Random,object):
    '''
    classdocs
    '''
    def __init__(self,seed=None):
        '''
        Constructor
        '''
        super(MyRandom, self).__init__()
        self.seed(seed)
        
    def genTerminalRandom(self):
        rnum = self.randint(0x00, 0xFFFFFFFF)
        
        return "%08X" % rnum
        
        