"use strict";

console.log("hello!");

var ref = require('ref');
var ffi=require('ffi');
var Struct = require('ref-struct');
var ArrayType = require('ref-array');


//define consts
var ERROR_OK			=0

var  ERROR_SOCKET_CREATE = 	-100
var ERROR_CONNECT	=	-101
var  ERROR_SOCKET_WRITE=	-102
var ERROR_SOCKET_READ	=-103
var ERROR_ICP_ID=		-104
var ERROR_AUTH	=	-105
var ERROR_MSG_LEN	=	-106
var ERROR_FEE_CODE	=	-107
var ERROR_SERVICE_ID=	-108
var ERROR_FLOW_CONTROL=	-109
var ERROR_SOCKET_CLOSE	=-110
var ERROR_CMD		=	-111

var ERROR_INTERNAL=		-200
var ERROR_UNKNOWN	=	-201
var ERROR_ARGUMENT=		-202

var CMD_SMGP_LOGIN	                 = 0x00000001    // �ͻ��˵�¼����
var CMD_SMGP_LOGIN_RESP	            =  0x80000001    // ��������Ӧ��
var CMD_SMGP_SUBMIT                =   0x00000002    // SP���Ͷ�������
var CMD_SMGP_SUBMIT_RESP          =    0x80000002    // SP���Ͷ���Ӧ��
var CMD_SMGP_DELIVER             =     0x00000003    // SMGW��SP���Ͷ�������
var CMD_SMGP_DELIVER_RESP       =      0x80000003    // SMGW��SP���Ͷ���Ӧ��
var CMD_SMGP_ACTIVE_TEST       =       0x00000004    // ������·
var CMD_SMGP_ACTIVE_TEST_RESP =        0x80000004    // ������·Ӧ��
var CMD_SMGP_FORWARD       =           0x00000005    // SMGWת����������
var CMD_SMGP_FORWARD_RESP =            0x80000005    // SMGWת������Ӧ��
var CMD_SMGP_EXIT			=		  0x00000006    // �˳�����
var CMD_SMGP_EXIT_RESP=				  0x80000006    // �˳�Ӧ��
var CMD_SMGP_QUERY		=			  0x00000007    // spͳ�Ʋ�ѯ����
var CMD_SMGP_QUERY_RESP				=  0x80000007	// spͳ�Ʋ�ѯӦ��
var CMD_SMGP_MT_ROUTE_UPDATE      =    0x00000008	// MT·�ɸ�������
var CMD_SMGP_MT_ROUTE_UPDATE_RESP=     0x80000008	// MT·�ɸ���Ӧ��
var CMD_SMGP_MO_ROUTE_UPDATE		=  0x00000009    // MO·�ɸ�������
var CMD_SMGP_MO_ROUTE_UPDATE_RESP   =  0x80000009	// MO·�ɸ���Ӧ��

var  MAX_SMGP_MSGID_LEN               =10
var  MAX_SMGP_CLIENTID_LEN           =  8
var  MAX_SMGP_PASSWORD_LEN          =  15
var  MAX_SMGP_AUTH_LEN             =   16
var  MAX_SMGP_MSGCONTENT_LEN      =   252
var  MAX_SMGP_ISMGCODE_LEN       =      6
var  MAX_SMGP_SERVICEID_LEN     =      10
var  MAX_SMGP_FEETYPE_LEN            =  2
var  MAX_SMGP_FEECODE_LEN           =   6
var  MAX_SMGP_FIXEDFEE_LEN         =    6
var  MAX_SMGP_TIME_LEN            =    17
var  MAX_SMGP_TERMINALID_LEN     =     21
var  MAX_SMGP_RESERVE_LEN       =       8
var  MAX_SMGP_RECVTIME_LEN     =       14
var  SMGP_HEAD_LEN				    =  12/*smgpЭ����ͷ����						*/
var  MAX_AUTHENTICATOR_LEN		=  16		/*MD5�����ֶγ���						*/
var  MAX_USER_NUM			=	100		/* �����·��û���                       */
var  MAX_SUMBIT_LEN		=		2466	/* ����SUBMIT������						*/
var LINKID_LENGTH             =    21          //DSMP��Link_id����
var MSG_SRC_LENGTH           =     21          //��Ϣ��Դ����
var MASK_LENGTH             =      32          //���볤��

var  SEQ_LEN               =           10
var  STAT_LEN             =             7
var  DATE_LEN            =             10
var  TEXT_LEN           =              20
var  SUB_LEN           =                3
var  DLVRD_LEN        =                 3
var  ERR_LEN         =                  3


var  MAX_SMGP_DESTTERM_NUM      =     100          // �������պ�������

var TSMGP_SUBMIT = Struct({
  'cMsgType': 'char',
  'cNeedReport': 'char',

  'cPriority': 'char',
  'sServiceID': ArrayType('char', MAX_SMGP_SERVICEID_LEN),
  'sFeeType': ArrayType('char', MAX_SMGP_FEETYPE_LEN),

  'sFixedFee': ArrayType('char', MAX_SMGP_FIXEDFEE_LEN),
  'sFeeCode': ArrayType('char', MAX_SMGP_FEECODE_LEN),
  'ucMsgFormat': 'char',
  'sValidTime': ArrayType('char', MAX_SMGP_TIME_LEN),
  'sAtTime': ArrayType('char', MAX_SMGP_TIME_LEN),
  'sSrcTermID': ArrayType('char', MAX_SMGP_TERMINALID_LEN),
  'sChargeTermID': ArrayType('char', MAX_SMGP_TERMINALID_LEN),
  'cDestTermIDCount': 'char',
  'sDestTermID': ArrayType('char', MAX_SMGP_TERMINALID_LEN*MAX_USER_NUM),
  'ucMsgLength': 'char',
  'sMsgContent': ArrayType('char', MAX_SMGP_MSGCONTENT_LEN),
  'sReserve': ArrayType('char', MAX_SMGP_RESERVE_LEN)
});
var TSMGP_SUBMIT_Ptr = ref.refType(TSMGP_SUBMIT);

var TSMGP_SUBMIT_RESP = Struct({
  'sMsgID': ArrayType('char', MAX_SMGP_MSGID_LEN),
  'lStatus': 'int'
});
var TSMGP_SUBMIT_RESP_Ptr = ref.refType(TSMGP_SUBMIT_RESP);

var TSMGP_TLV = Struct({
    'cPid': 'uint8',
    'b_cPid': 'bool',
    'cUdhi': 'uint8',
    'b_cUdhi': 'bool',

    'strLinkId':  ArrayType('uint8', LINKID_LENGTH),
    'b_strLinkId': 'bool',
    'cFeeFlag': 'uint8',
    'b_cFeeFlag': 'bool',

    'cFeeMaskFlag': 'uint8',
    'b_cFeeMaskFlag': 'bool',

    'strFeeNumberMask':  ArrayType('uint8', MASK_LENGTH),
    'b_strFeeNumberMask': 'bool',
    'cDestMaskFlag': 'uint8',
    'b_cDestMaskFlag': 'bool',

    'strDestNumberMask':  ArrayType('uint8', MASK_LENGTH),
    'b_strDestNumberMask': 'bool',
    'cPkTotal': 'uint8',
    'b_cPkTotal': 'bool',
    'cPkNumber': 'uint8',
    'b_cPkNumber': 'bool',
    'cMsgType': 'uint8',
    'b_cMsgType': 'bool',
    'cSpDealResult': 'uint8',
    'b_cSpDealResult': 'bool',
    'cSrcMaskFlag': 'uint8',
    'b_cSrcMaskFlag': 'bool',

    'strSrcNumberMask':  ArrayType('uint8', MASK_LENGTH),
    'b_strSrcNumberMask': 'bool',
    'cNodesCount': 'uint8',
    'b_cNodesCount': 'bool',
    'strMsgSrc':  ArrayType('uint8', MSG_SRC_LENGTH),
    'b_strMsgSrc': 'bool',
    'cSpMaskFlag': 'uint8',
    'b_cSpMaskFlag': 'bool',
    'strMServiceID':  ArrayType('uint8', 21),
    'b_strMServiceID': 'bool',
});
var TSMGP_TLV_Ptr = ref.refType(TSMGP_TLV);


try{
  var smgp=ffi.Library(__dirname+'/libSmgpapi.so',{
    SMGP_Connect:['int',['string','short','string','string','int']],
    SMGP_Submit:['int',['int',TSMGP_SUBMIT_Ptr,TSMGP_SUBMIT_RESP_Ptr,TSMGP_TLV_Ptr]],
    SMGP_Disconnect:['int',['int']]
  });
}catch(e){
  console.log(e);
}

var conn_id = smgp.SMGP_Connect('192.168.2.116',9890,'333','0555',0);

console.log('SMGP_Connect/conn_id:');
console.log(conn_id);
console.log('-----------------------------------------------------------');

var tsmgp_submit= new TSMGP_SUBMIT;
tsmgp_submit.cMsgType= 6;
tsmgp_submit.cNeedReport=0;
tsmgp_submit.cPriority=3;
str2array(tsmgp_submit.sServiceID,'99999');
str2array(tsmgp_submit.sFeeType,'00');
str2array(tsmgp_submit.sSrcTermID,'106592313');
str2array(tsmgp_submit.sChargeTermID,'106592313');
tsmgp_submit.ucMsgFormat=15;
tsmgp_submit.ucMsgLength=8;
str2array(tsmgp_submit.sMsgContent,'123');
str2array(tsmgp_submit.sDestTermID,'13558815120');

var response=new TSMGP_SUBMIT_RESP;

var tlv=new TSMGP_TLV({
  b_cPid:false,
  b_cUdhi:false,
  b_strLinkId:false,
  b_cFeeFlag:false,

  b_cFeeMaskFlag:false,

  b_strFeeNumberMask:false,
  b_cDestMaskFlag:false,

  b_strDestNumberMask:false,
  b_cPkTotal:false,
  b_cPkNumber:false,
  b_cMsgType:false,
  b_cSpDealResult:false,
  b_cSrcMaskFlag:false,

  b_strSrcNumberMask:false,
  b_cNodesCount:false,
  b_strMsgSrc:false,
  b_cSpMaskFlag:false,
  b_strMServiceID:false
});


try{
  var result = smgp.SMGP_Submit(conn_id,tsmgp_submit.ref(),response.ref(),tlv.ref());
  console.log('SMGP_Submit/result:')
  console.log(result);
  console.log(response);
  console.log(response.sMsgID.buffer.toString());
  console.log('***********************************************************');
}catch(e){
  console.log('Error:');
  console.log(e);
  console.log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
}

var result=smgp.SMGP_Disconnect(conn_id);

console.log('result:');
console.log(result);
console.log('--------------------------------------------------------');

function str2array(arr,str){
  for(var i=0;i<str.length;i++){
    arr[i]=str.charAt(i);
  }
}

function array2str(arr){
  var str='';
  for(var i=0;i<arr.length;i++){
    str+=String.fromCharCode(arr[i]);
  }
  return str;
}
