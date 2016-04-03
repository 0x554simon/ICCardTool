#-*-encoding:utf-8-*-
'''
Created on 2016-2-27

@author: ThinkPad
'''
import ConfigParser as comcfg

class CfgParser(object):
    '''
    parser config file
    '''

    def __init__(self,cfgfilename):
        '''
        Constructor
        '''
        self.cfg = comcfg.ConfigParser()
        self.cfg.read(cfgfilename)
    
    '''
    get param's value in the section
    '''
    def GetCfgValue(self, section, param):
        if len(section) == 0 or len(param) == 0:
            return None
        rslt = None
        try:
            rslt = self.cfg.get(section, param)
        except comcfg.NoSectionError:
            print 'no section [%s], return None' % section
        except comcfg.NoOptionError:
            print 'no option  [%s], return None' % param
        
        return rslt 
    
    '''
    get all info in the section
    '''
    def GetCfgSection(self, section):
        if len(section) == 0:
            return None
        rslt = None
        try:
            rslt = self.cfg.items(section)
        except comcfg.NoSectionError:
            print 'no section [%s], return None' % section
        
        return rslt

#-------------------------------------------------------
def test(cfgfile=None, section = None, option = None):
    cfg = CfgParser(cfgfile)
    if section is not None and option is not None:
        print '[%s]\n%s = %s' % (section, option, cfg.GetCfgValue(section, option))
    elif section is not None and option is None:
        print '[%s]\n%s' % (section, cfg.GetCfgSection(section))
    else:
        pass
    
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print 'USAGE : %s filename section option\n\t** we need two params at least **' % sys.argv[0]
        
    if len(sys.argv) == 4:
        test(cfgfile = sys.argv[1], section = sys.argv[2], option = sys.argv[3])
    
    if len(sys.argv) == 3:
        test(cfgfile = sys.argv[1], section = sys.argv[2])