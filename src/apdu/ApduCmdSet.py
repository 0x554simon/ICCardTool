# -*-encoding:utf-8-*-

'''
Created on 2016-3-24

@author: 014731
'''

class ApduCmdSet(object):
    '''
    ISO7816定义的ISO智能卡通用APDU命令集:
    VERIFY                       启动从接口设备送入卡内的验证数据与卡内存储的引用数据(例如口令)进行比较
    ENVELOPE                     用来发送那些不能由有效协议来发送的APDU 或APDU的一部分或任何数据串
    GET_DATA                     可在当前上下文(例如应用特定环境或当前DF)范围内用于检索一个原始数
                                                                                        据对象或者包含在结构化数据对象中所包含的一个或多个数据对象
    PUT_DATA                     可在当前上下文(例如应用特定环境或当前DF)范围内用于存储一个原始数
                                                                                        据对象或者包含在结构化数据对象中的一个或多个数据对象正确的
                                                                                        存储功能(写一次和/或更新和/或添加)通过数据对象的定义和性质来引出
    SELECT_FILE                  设置当前文件后续命令可以通过那个逻辑信道隐式地引用该当前文件,(PSE,PPSE,AID)
    READ_RECORD                  给出了EF的规定记录的内容或EF的一个记录开始部分的内容
    READ_BINARY                  读出带有透明结构的EF内容的一部分
    ERASE_BINARY                 顺序地从给出的偏移开始将EF的内容的一部分置为其逻辑擦除的状态
    GET_RESPONSE                 用于从卡发送至接口设备用可用的协议不能传送的那一些的APDU(或APDU的一部分)
    WRITE_BINARY                 将二进制值写入EF
    WRITE_RECORD                 WRITE RECORD命令报文启动下列操作之一: ——写一次记录; ——对早已呈现在卡内的记录
                                                                                       数据字节与在命令APDU中给出的记录数据字节进行逻辑“或”运算; ——对早已呈现在卡内的
                                                                                       记录数据字节与在命令APDU中给出的记录数据字节进行逻辑“和”运算
    UPDATE_RECORD                启动使用命令APDU给出的位来更新特定记录
    APPEND_RECORD                启动在线性结构EF的结束端添加记录或者在循环结构的EF内写记录号1
    UPDATE_BINARY                启动使用在命令APDU中给出的位来更新早已呈现在EF中的位
    GET_CHALLENGE                要求发出一个询问(例如随机数)以便用于安全相关的规程(例EXTERNAL AUTHENTICATE 命令)
    MANAGE_CHANNEL               打开和关闭逻辑信道
    INTERNAL_AUTHENTICATE        启动卡使用从接口设备发送来的询问数据和在卡内存储的相关秘密(例如密钥)来计算鉴别数据 
                                                                                       当该相关秘密被连接到MF时命令可以用来鉴别整个卡 当该相关秘密被连接到另一个DF时命令可以用来鉴别那个DF
    EXTERNAL_AUTHENTICATE        使用卡计算的结果(是或否)有条件地来更新安全状态而该卡的计算是以该卡先前发出
                                 (例如通过GETCHALLENGE命令)的询问在卡内存储的可能的秘密密钥以及接口设备发送的鉴别数据为基础的
    
    VERIFY_SAFE                  启动从接口设备送入卡内的验证数据与卡内存储的引用数据(例如口令)进行比较
    GET_DATA_SAFE                可在当前上下文(例如应用特定环境或当前DF)范围内用于检索一个原始数据对象或者包含在结构化数据对
                                                                                        象中所包含的一个或多个数据对象
    PUT_DATA_SAFE                可在当前上下文(例如应用特定环境或当前DF)范围内用于存储一个原始数据对象或者包含在结构化数据
                                                                                        对象中的一个或多个数据对象正确的 存储功能(写一次和/或更新和/或添加)通过数据对象的定义和性质来引出
    SELECT_FILE_SAFE             设置当前文件后续命令可以通过那个逻辑信道隐式地引用该当前文件,(PSE,PPSE,AID)
    READ_RECORD_SAFE             给出了EF的规定记录的内容或EF的一个记录开始部分的内容
    READ_BINARY_SAFE             读出带有透明结构的EF内容的一部分
    ERASE_BINARY_SAFE            顺序地从给出的偏移开始将EF的内容的一部分置为其逻辑擦除的状态
    GET_RESPONSE_SAFE            用于从卡发送至接口设备用可用的协议不能传送的那一些的APDU(或APDU的一部分)
    WRITE_BINARY_SAFE            将二进制值写入EF
    WRITE_RECORD_SAFE            WRITE RECORD命令报文启动下列操作之一: ——写一次记录; ——对早已呈现在卡内的记录数据字节与在命令
                                 APDU中给出的记录数据字节进行逻辑“或”运算; ——对早已呈现在卡内的记录数据字节与在命令APDU中给出
                                                                                       的记录数据字节进行逻辑“和”运算
    UPDATE_RECORD_SAFE           启动使用命令APDU给出的位来更新特定记录
    APPEND_RECORD_SAFE           启动在线性结构EF的结束端添加记录或者在循环结构的EF内写记录号1
    UPDATE_BINARY_SAFE           启动使用在命令APDU中给出的位来更新早已呈现在EF中的位
    GET_CHALLENGE_SAFE           要求发出一个询问(例如随机数)以便用于安全相关的规程(例EXTERNAL AUTHENTICATE 命令)
    MANAGE_CHANNEL_SAFE          打开和关闭逻辑信道
    INTERNAL_AUTHENTICATE_SAFE   启动卡使用从接口设备发送来的询问数据和在卡内存储的相关秘密(例如密钥)来计算鉴别数据 当该相关秘
                                                                                       密被连接到MF时命令可以用来鉴别整个卡 当该相关秘密被连接到另一个DF时命令可以用来鉴别那个DF
    EXTERNAL_AUTHENTICATE_SAFE   使用卡计算的结果(是或否)有条件地来更新安全状态而该卡的计算是以该卡先前发出(例如通过GETCHALLENGE命令)
                                                                                        的询问在卡内存储的可能的秘密密钥以及接口设备发送的鉴别数据为基础的
                                                                                        
    PBOC 定义的智能卡APDU命令集:
    PBOC_APPLICATION_BLOCK            锁定卡内指定应用，安全模式操作
    PBOC_APPLICATION_UNBLOCK          解锁卡内被锁定的应用 ，安全模式操作
    PBOC_CARD_BLOCK                   锁定卡片，安全模式操作
    PBOC_EXTERNAL_AUTHENTICATE        外部认证
    PBOC_GENERATE_AC                  生成应用密文,卡片不执行CDA，命令的响应报文数据域中的数据对象按照格式1(标签为80的基本数据对象)编码。
                                                                                                     如果卡片执行CDA，命令的响应报文数据域中的数据对象按照格式2(标签为77的结构数据对象)编码。
    PBOC_GET_DATA                     取数据
    PBOC_GET_PROCESSING_OPTIONS       获取处理选项
    PBOC_INTERNAL_AUTHENTICATE        内部认证
    PBOC_PIN_CHANGE                   发卡行解锁PIN或同时既改变PIN也解锁PIN
    PBOC_PIN_UNBLOCK                  发卡行解锁PIN或同时既改变PIN也解锁PIN
    PBOC_PUT_DATE                     设置数据,修改卡片中的一些基本数据对象的值
    PBOC_READ_RECORD                  从一个线性文件中读一条文件记录
    PBOC_SELECT                       通过文件名或AID来选择IC卡中的PSE或ADF
    PBOC_UPDATE_RECORD                修改文件中一条记录的内容
    PBOC_VERIFY                       IC卡将命令报文数据域内的交易PIN数据和与该应用相关的参考PIN数据进行比较验证
    '''


    ''' 普通模式C-APDU '''
    VERIFY                     =   [0x00, 0x20]
    ENVELOPE                   =   [0x80, 0xC2]
    GET_DATA                   =   [0x00, 0xCA]
    PUT_DATA                   =   [0x00, 0xDA]
    SELECT_FILE                =   [0x00, 0xA4]
    READ_RECORD                =   [0x00, 0xB2]
    READ_BINARY                =   [0x00, 0xB0]
    ERASE_BINARY               =   [0x00, 0x0E]
    GET_RESPONSE               =   [0x00, 0xC0]
    WRITE_BINARY               =   [0x00, 0xD0]
    WRITE_RECORD               =   [0x00, 0xD2]
    UPDATE_RECORD              =   [0x00, 0xDC]
    APPEND_RECORD              =   [0x00, 0xE2]
    UPDATE_BINARY              =   [0x00, 0xD6]
    GET_CHALLENGE              =   [0x00, 0x84]
    MANAGE_CHANNEL             =   [0x00, 0x70]
    INTERNAL_AUTHENTICATE      =   [0x00, 0x88]
    EXTERNAL_AUTHENTICATE      =   [0x00, 0x82]

    ''' 带有MAC安全模式的C-APDU '''              
    VERIFY_SAFE                =   [0x04, 0x20]
    GET_DATA_SAFE              =   [0x04, 0xCA]
    PUT_DATA_SAFE              =   [0x04, 0xDA]
    SELECT_FILE_SAFE           =   [0x04, 0xA4]
    READ_RECORD_SAFE           =   [0x04, 0xB2]
    READ_BINARY_SAFE           =   [0x04, 0xB0]
    ERASE_BINARY_SAFE          =   [0x04, 0x0E]
    GET_RESPONSE_SAFE          =   [0x04, 0xC0]
    WRITE_BINARY_SAFE          =   [0x04, 0xD0]
    WRITE_RECORD_SAFE          =   [0x04, 0xD2]
    UPDATE_RECORD_SAFE         =   [0x04, 0xDC]
    APPEND_RECORD_SAFE         =   [0x04, 0xE2]
    UPDATE_BINARY_SAFE         =   [0x04, 0xD6]
    GET_CHALLENGE_SAFE         =   [0x04, 0x84]
    MANAGE_CHANNEL_SAFE        =   [0x04, 0x70]
    INTERNAL_AUTHENTICATE_SAFE =   [0x04, 0x88]
    EXTERNAL_AUTHENTICATE_SAFE =   [0x04, 0x82]
    
    '''
    PBOC命令
    '''
    PBOC_APPLICATION_BLOCK          =   [0x84, 0x1E, 0x00, 0x00]
    PBOC_APPLICATION_UNBLOCK        =   [0x84, 0x18, 0x00, 0x00]
    PBOC_CARD_BLOCK                 =   [0x84, 0x16, 0x00, 0x00]
    PBOC_EXTERNAL_AUTHENTICATE      =   EXTERNAL_AUTHENTICATE + [0x00,0x00]
    PBOC_GENERATE_AC                =   [0x80, 0xAE]
    PBOC_GET_DATA                   =   [0x80, 0xCA]
    PBOC_GET_PROCESSING_OPTIONS     =   [0x80, 0xA8, 0x00, 0x00]
    PBOC_INTERNAL_AUTHENTICATE      =   INTERNAL_AUTHENTICATE + [0x00, 0x00]
    PBOC_PIN_CHANGE  = PBOC_PIN_UNBLOCK = [0x84, 0x24]
    PBOC_PUT_DATE                   =   PUT_DATA_SAFE
    PBOC_READ_RECORD                =   READ_RECORD
    PBOC_SELECT                     =   SELECT_FILE
    PBOC_UPDATE_RECORD              =   UPDATE_RECORD_SAFE
    PBOC_VERIFY                     =   VERIFY
#------------------------------------------------------------
if __name__ == '__main__':
    print '类 ApduCmdSet 属性说明文档:'
    print ApduCmdSet.__doc__
    
    print '类 ApduCmdSet 定义的所有指令:'
    print '-'*41
    for key in ApduCmdSet.__dict__:
        if key.startswith('_', 0, 1) == False:
            print '%-26s : [0x%02X, 0x%02X]' % (key, ApduCmdSet.__dict__[key][0], ApduCmdSet.__dict__[key][1])
    print '-'*41
            