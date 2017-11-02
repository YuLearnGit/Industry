/*
 * modbus_decode.c
 *
 *  Created on: 2015年6月15日
 *      Author: zwj, dl
 */

#include "modbus_decode.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

/* Modbus Function Codes */
#define MODBUS_FUNC_READ_COILS                          0x01
#define MODBUS_FUNC_READ_DISCRETE_INPUTS                0x02
#define MODBUS_FUNC_READ_HOLDING_REGISTERS              0x03
#define MODBUS_FUNC_READ_INPUT_REGISTERS                0x04
#define MODBUS_FUNC_WRITE_SINGLE_COIL                   0x05
#define MODBUS_FUNC_WRITE_SINGLE_REGISTER               0x06
#define MODBUS_FUNC_READ_EXCEPTION_STATUS               0x07
#define MODBUS_FUNC_DIAGNOSTICS                         0x08
#define MODBUS_FUNC_GET_COMM_EVENT_COUNTER              0x0B
#define MODBUS_FUNC_GET_COMM_EVENT_LOG                  0x0C
#define MODBUS_FUNC_WRITE_MULTIPLE_COILS                0x0F
#define MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS            0x10
#define MODBUS_FUNC_REPORT_SLAVE_ID                     0x11
#define MODBUS_FUNC_READ_FILE_RECORD                    0x14
#define MODBUS_FUNC_WRITE_FILE_RECORD                   0x15
#define MODBUS_FUNC_MASK_WRITE_REGISTER                 0x16
#define MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS       0x17
#define MODBUS_FUNC_READ_FIFO_QUEUE                     0x18
#define MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT    0x2B
#define MODBUS_SUB_FUNC_CANOPEN                         0x0D
#define MODBUS_SUB_FUNC_READ_DEVICE_ID                  0x0E

/* Various Modbus lengths */
#define MODBUS_BYTE_COUNT_SIZE 1
#define MODBUS_DOUBLE_BYTE_COUNT_SIZE 2
#define MODBUS_FILE_RECORD_SUB_REQUEST_SIZE 7
#define MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET 5
#define MODBUS_READ_DEVICE_ID_HEADER_LEN 6
#define MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET 5

#define MODBUS_EMPTY_DATA_LEN   0
#define MODBUS_FOUR_DATA_BYTES  4
#define MODBUS_BYTE_COUNT_SIZE  1
#define MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET 4
#define MODBUS_WRITE_MULTIPLE_MIN_SIZE          5
#define MODBUS_MASK_WRITE_REGISTER_SIZE         6
#define MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET    8
#define MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE             9
#define MODBUS_READ_FIFO_SIZE                           2
#define MODBUS_MEI_MIN_SIZE                             1
#define MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE            1
#define MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE             3
#define MODBUS_SUB_FUNC_READ_DEVICE_START_LEN           2
#define MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET       1

#define MODBUS_TRANS_PROTO_LEN_SIZE                     6

/* Other defines */
#define MODBUS_PROTOCOL_ID 0
#define  DEBUG
/* Modbus data structures */
typedef struct _modbus_header
{
    /* MBAP Header */
    __u16 transaction_id;
    __u16 protocol_id;
    __u16 length;
    __u8  unit_id;

    /* PDU Start */
    __u8 function_code;
} modbus_header_t;


//****************************************************************************
//函数名： IsRejectFunCode(__u8 *function_code_array,__u8 header_function_code,__u8 fc_number)
//功能：判断是否是被拒绝的功能码   由ModbusCheckFunctionCode()调用
//参数：__u8 *app_data,__u16 app_len,__u8 fc_number
//返回值：THIS_IS_REJECT_FUN_CODE  THIS_IS_NOT_REJECT_FUN_CODE
//作者：Denny
//日期：2015-7-8
//备注：
//****************************************************************************

static inline bool 
funcode_match(__u8 min, __u8 max, __u8 check_funcode, bool invert)
{
	#ifdef DEBUG
   			printk("function_code_number is : %d\n",check_funcode);
   	#endif
	return (check_funcode >= min && check_funcode <= max) ^ invert;
}

//****************************************************************************
//函数名：ModbusCheckFunctionCode(__u8 *app_data,__u16 app_len,const struct xt_modbusTcp_mtinfo *info)
//功能：拒绝勾选的功能码
//参数：__u8 *app_data,__u16 app_len,const struct xt_modbusTcp_mtinfo *info
//返回值：MODBUS_FUNCODE_REJECT  MODBUS_FUNCODE_RECEIVE
//作者：Denny
//日期：2015-7-8
//备注：
//****************************************************************************
static int ModbusCheckFunctionCode(__u8 *app_data,__u16 app_len,const struct xt_modbusTcp_mtinfo *info)
{
		__u8 min = info->modbus_func[0];
		__u8 max = info->modbus_func[1];
		modbus_header_t *header;
		if(max == 0)
			return MODBUS_FUNCODE_MATCHED;
		#ifdef DEBUG
   			printk("Modbus_funcode range %u:%u\n",min,max);
   		#endif
		
  		/* Lay the header struct over the payload */
	    header = (modbus_header_t *) app_data;
		#ifdef DEBUG
   			printk("Examing function %u\n",header->function_code);
   		#endif
		if(funcode_match(min,max,header->function_code,!!(info->flags & MODBUSTCP_FUNC)))
		{
		#ifdef DEBUG
   			printk("MODBUS_FUNCODE_MATCHED\n");
   		#endif
		return MODBUS_FUNCODE_MATCHED;
		}
		else
		{
			#ifdef DEBUG
	   			printk("MODBUS_FUNCODE_NOT_MATCHED\n");
	   		#endif
			return MODBUS_FUNCODE_NOT_MATCHED;
		}
}



//****************************************************************************
//函数名：ModbusLenCheck(__u8 *app_data,__u16 app_len)
//功能：ModbusTCP数据包长度检测
//参数：__u8 *app_data,__u16 app_len
//返回值：MODBUS_LEN_OK MODBUS_LEN_FAIL
//作者：zwj
//日期：2015-6-5
//备注：
//****************************************************************************
static int ModbusLenCheck(__u8 *app_data,__u16 app_len)
{
	modbus_header_t *header = (modbus_header_t *)app_data;

	if( ntohs(header->length) == (app_len - MODBUS_TRANS_PROTO_LEN_SIZE))
	{
		return MODBUS_LEN_OK;
	}
	else
	{
		return MODBUS_LEN_FAIL;
	}
}

//****************************************************************************
//函数名：ModbusCheckRequestLengths(__u8 *app_data,__u16 app_len)
//功能：ModbusTCP请求数据包长度检测
//参数：__u8 *app_data,__u16 app_len
//返回值：MODBUS_LEN_OK MODBUS_LEN_FAIL
//作者：zwj
//日期：2015-6-5
//备注：
//****************************************************************************
static int ModbusCheckRequestLengths(__u8 *app_data, __u16 app_len)
{
    uint16_t modbus_payload_len = app_len - MODBUS_MIN_LEN;
    uint8_t tmp_count = 0;
    int check_passed = 0;

    modbus_header_t *header;
    /* Lay the header struct over the payload */
    header = (modbus_header_t *) app_data;
	#ifdef DEBUG
   			printk("header_function_code is :%d\n",header->function_code);
   		#endif
    switch (header->function_code)
    {
        case MODBUS_FUNC_READ_COILS:
        case MODBUS_FUNC_READ_DISCRETE_INPUTS:
        case MODBUS_FUNC_READ_HOLDING_REGISTERS:
        case MODBUS_FUNC_READ_INPUT_REGISTERS:
        case MODBUS_FUNC_WRITE_SINGLE_COIL:
        case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        case MODBUS_FUNC_DIAGNOSTICS:
            if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_EXCEPTION_STATUS:
        case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
        case MODBUS_FUNC_GET_COMM_EVENT_LOG:
        case MODBUS_FUNC_REPORT_SLAVE_ID:
            if (modbus_payload_len == MODBUS_EMPTY_DATA_LEN)
                check_passed = 1;
            break;

        case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
        case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len >= MODBUS_WRITE_MULTIPLE_MIN_SIZE)
            {
                tmp_count = *(app_data + MODBUS_MIN_LEN +
                              MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
                if (modbus_payload_len == tmp_count + MODBUS_WRITE_MULTIPLE_MIN_SIZE)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_MASK_WRITE_REGISTER:
            if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len >= MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE)
            {
                tmp_count = *(app_data + MODBUS_MIN_LEN +
                              MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
                if (modbus_payload_len == MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE + tmp_count)
                    check_passed = 1;
            }
            break;


        case MODBUS_FUNC_READ_FIFO_QUEUE:
            if (modbus_payload_len == MODBUS_READ_FIFO_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:
            if (modbus_payload_len >= MODBUS_MEI_MIN_SIZE)
            {
                uint8_t mei_type = *(app_data + MODBUS_MIN_LEN);

                /* MEI Type 0x0E is covered under the Modbus spec as
                   "Read Device Identification". Type 0x0D is defined in
                   the spec as "CANopen General Reference Request and Response PDU"
                   and falls outside the scope of the Modbus preprocessor.

                   Other values are reserved.
                */
                if ((mei_type == MODBUS_SUB_FUNC_READ_DEVICE_ID) &&
                    (modbus_payload_len == MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE))
                    check_passed = 1;
            }
            break;


        case MODBUS_FUNC_READ_FILE_RECORD:
            /* Modbus read file record request contains a byte count, followed
               by a set of 7-byte sub-requests. */
            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(app_data + MODBUS_MIN_LEN);
                if ((tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE) &&
                    (tmp_count % MODBUS_FILE_RECORD_SUB_REQUEST_SIZE == 0))
                {
                    check_passed = 1;
                }
            }
            break;

        case MODBUS_FUNC_WRITE_FILE_RECORD:
            /* Modbus write file record request contains a byte count, followed
               by a set of sub-requests that contain a 7-byte header and a
               variable amount of data. */

            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(app_data + MODBUS_MIN_LEN);
                if (tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE)
                {
                    uint16_t bytes_processed = 0;

                    while (bytes_processed < (uint16_t)tmp_count)
                    {
                        uint16_t record_length = 0;

                        /* Check space for sub-request header info */
                        if ((modbus_payload_len - bytes_processed) <
                                MODBUS_FILE_RECORD_SUB_REQUEST_SIZE)
                            break;

                        /* Extract record length. */
                        record_length = *(app_data + MODBUS_MIN_LEN +
                            MODBUS_BYTE_COUNT_SIZE + bytes_processed +
                            MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET);

                        record_length = record_length << 8;

                        record_length |= *(app_data + MODBUS_MIN_LEN +
                            MODBUS_BYTE_COUNT_SIZE + bytes_processed +
                            MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET + 1);

                        /* Jump over record data. */
                        bytes_processed += MODBUS_FILE_RECORD_SUB_REQUEST_SIZE +
                                           2*record_length;

                        if (bytes_processed == (uint16_t)tmp_count)
                            check_passed = 1;
                    }
                }
            }
            break;

        default: /* Don't alert if we couldn't check the length. */
            check_passed = 1;
            break;
    }

    if (check_passed)
            {
    			#ifdef DEBUG
    				printk("modbus_payload_len: %d   temp_count : %d\n", modbus_payload_len, tmp_count);
				#endif

                return MODBUS_LEN_OK;
            }
            else
            {
				#ifdef DEBUG
            		printk("request function_code check FAIL \n");
				#endif

            	return MODBUS_LEN_FAIL;
            }
}


//****************************************************************************
//函数名：ModbusCheckResponseLengths(__u8 *app_data,__u16 app_len)
//功能：ModbusTCP响应数据包长度检测
//参数：__u8 *app_data,__u16 app_len
//返回值：MODBUS_LEN_OK MODBUS_LEN_FAIL
//作者：zwj
//日期：2015-6-5
//备注：
//****************************************************************************
static int  ModbusCheckResponseLengths(__u8 *app_data, __u16 app_len)
{
    uint16_t modbus_payload_len = app_len - MODBUS_MIN_LEN;
    uint8_t tmp_count;
    int check_passed = 0;

    modbus_header_t *header;
    /* Lay the header struct over the payload */
    header = (modbus_header_t *) app_data;
    switch (header->function_code)
    {
        case MODBUS_FUNC_READ_COILS:
        case MODBUS_FUNC_READ_DISCRETE_INPUTS:
        case MODBUS_FUNC_GET_COMM_EVENT_LOG:
        case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                tmp_count = *(app_data + MODBUS_MIN_LEN); /* byte count */
		#ifdef DEBUG
              printk("modbus_payload_len: %d   temp_count : %d\n", modbus_payload_len, tmp_count);
		#endif

                if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_READ_HOLDING_REGISTERS:
        case MODBUS_FUNC_READ_INPUT_REGISTERS:
            if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
            {
                /* count of 2-byte registers*/
                tmp_count = *(app_data + MODBUS_MIN_LEN);
                if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + 2*tmp_count)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_WRITE_SINGLE_COIL:
        case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        case MODBUS_FUNC_DIAGNOSTICS:
        case MODBUS_FUNC_GET_COMM_EVENT_COUNTER:
        case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
        case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
            if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_EXCEPTION_STATUS:
            if (modbus_payload_len == MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_MASK_WRITE_REGISTER:
            if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
                check_passed = 1;
            break;

        case MODBUS_FUNC_READ_FIFO_QUEUE:
            if (modbus_payload_len >= MODBUS_DOUBLE_BYTE_COUNT_SIZE)
            {
                uint16_t tmp_count_16;

                /* This function uses a 2-byte byte count!! */
                tmp_count_16 = *(uint16_t *)(app_data + MODBUS_MIN_LEN);
                tmp_count_16 = ntohs(tmp_count_16);
                if (modbus_payload_len == MODBUS_DOUBLE_BYTE_COUNT_SIZE + tmp_count_16)
                    check_passed = 1;
            }
            break;

        case MODBUS_FUNC_ENCAPSULATED_INTERFACE_TRANSPORT:
            if (modbus_payload_len >= MODBUS_READ_DEVICE_ID_HEADER_LEN)
            {
                uint8_t mei_type = *(app_data + MODBUS_MIN_LEN);
                uint8_t num_objects = *(app_data + MODBUS_MIN_LEN +
                                        MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET);
                uint16_t offset;
                uint8_t i;

                /* MEI Type 0x0E is covered under the Modbus spec as
                   "Read Device Identification". Type 0x0D is defined in
                   the spec as "CANopen General Reference Request and Response PDU"
                   and falls outside the scope of the Modbus preprocessor.

                   Other values are reserved.
                */

                if (mei_type == MODBUS_SUB_FUNC_CANOPEN)
                    check_passed = 1;

                if (mei_type != MODBUS_SUB_FUNC_READ_DEVICE_ID)
                    break;

                /* Loop through sub-requests, make sure that the lengths inside
                   don't violate our total Modbus PDU size. */

                offset = MODBUS_READ_DEVICE_ID_HEADER_LEN;
                for (i = 0; i < num_objects; i++)
                {
                    uint8_t sub_request_data_len;

                    /* Sub request starts with 2 bytes, type + len */
                    if (offset + MODBUS_SUB_FUNC_READ_DEVICE_START_LEN > modbus_payload_len)
                        break;

                    /* Length is second byte in sub-request */
                    sub_request_data_len = *(app_data + MODBUS_MIN_LEN +
                                            offset + MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET);

                    /* Set offset to byte after sub-request */
                    offset += (MODBUS_SUB_FUNC_READ_DEVICE_START_LEN + sub_request_data_len);
                }

                if ((i == num_objects) && (offset == modbus_payload_len))
                    check_passed = 1;
            }
            break;

        /* Cannot check this response, as it is device specific. */
        case MODBUS_FUNC_REPORT_SLAVE_ID:

        /* Cannot check these responses, as their sizes depend on the corresponding
           requests. Can re-visit if we bother with request/response tracking. */
        case MODBUS_FUNC_READ_FILE_RECORD:
        case MODBUS_FUNC_WRITE_FILE_RECORD:

        default: /* Don't alert if we couldn't check the lengths. */
            check_passed = 1;
            break;
    }

    if (check_passed)
        {
	#ifdef DEBUG
    	printk("response length check OK \n");
	#endif

            return MODBUS_LEN_OK;
        }
        else
        {
	#ifdef DEBUG
        	printk("response length check FAIL \n");
	#endif

        	return MODBUS_LEN_FAIL;
        }
}

//****************************************************************************
//函数名：ModbusCheckRequestCoilAddr(__u8 *app_data,__u16 app_len)
//功能：ModbusTCP请求数据包长度检测
//参数：__u8 *app_data,__u16 app_len
//返回值：MODBUS_LEN_OK MODBUS_LEN_FAIL
//作者：zwj
//日期：2015-6-5
//备注：
//****************************************************************************
static int ModbusCheckRequestDataAddr(__u8 *app_data, __u16 app_len, const struct xt_modbusTcp_mtinfo *info)
{
    uint16_t start_addr;
    uint16_t coil_num;
    int check_passed = 0;
    int addr_min = (info->data_addr[0])-1;
    int addr_max = info->data_addr[1];
	modbus_header_t *header;
	if(addr_max == 0)
		return  MODBUS_DATA_ADDR_CHECK_OK;
	#ifdef DEBUG
   		printk("Data address range is %u:%u\n",addr_min,addr_max);
   	#endif
    
    /* Lay the header struct over the payload */
    header = (modbus_header_t *) app_data;

    switch (header->function_code)
    {
        case MODBUS_FUNC_READ_COILS://0x01
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_READ_DISCRETE_INPUTS://0x02
        	printk("addr_min: %d, addr_max:%d\n", addr_min, addr_max);
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));
		#ifdef DEBUG
        	printk("start_addr: %d, coil_num:%d\n", start_addr, coil_num);
		#endif

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_READ_HOLDING_REGISTERS://0x03
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_READ_INPUT_REGISTERS://0x04
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_WRITE_SINGLE_COIL://0x05
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	if( start_addr >= addr_min && start_addr <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_WRITE_SINGLE_REGISTER://0x06
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	if( start_addr >= addr_min && start_addr <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_WRITE_MULTIPLE_COILS://0x0F
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        		check_passed = 1;
        	break;
        case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS://0x10
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_MASK_WRITE_REGISTER://0x16
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));

        	if( start_addr >= addr_min && start_addr <= addr_max )
        		check_passed = 1;
        	break;

        case MODBUS_FUNC_READ_WRITE_MULTIPLE_REGISTERS://0x17
        	//Read Address
        	start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN )));
        	coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 2 )));

        	if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        	{
        		//Write Address
        		start_addr =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE * 4)));
        		coil_num = ntohs((*(uint16_t *)(app_data + MODBUS_MIN_LEN + MODBUS_BYTE_COUNT_SIZE  * 6 )));
        		if( start_addr >= addr_min && start_addr + coil_num <= addr_max )
        			check_passed = 1;
        	}
        	else check_passed = 0;
        	break;

        default: /* Don't alert if we couldn't check the length. */
            check_passed = 1;
            break;
    }

    if (check_passed)
    {
	#ifdef DEBUG
    	printk("Data address check OK\n");
	#endif

        return MODBUS_DATA_ADDR_CHECK_OK;
    }
    else
    {
	#ifdef DEBUG
    	printk("Data address check FAIL\n");
	#endif

    	return MODBUS_DATA_ADDR_CHECK_FAIL;
   	}
}


//****************************************************************************
//函数名:data_check(__u16 min, __u16 max, __u16 che_data)
//****************************************************************************
static inline bool
data_check(__u16 min, __u16 max, __u16 che_data, bool invert)
{
	return (che_data >= min && che_data <= max) ^ invert;
	printk("Data being examed is :%d\n",che_data);
}

//****************************************************************************
//函数名: ModbusCheckRequestData(__u8 *app_data, __u16 app_len, xt_modbusTcp_mtinfo *info)
//****************************************************************************
static int ModbusCheckRequestData(__u8 *app_data, __u16 app_len, const struct xt_modbusTcp_mtinfo *info)
{
    uint16_t check_data;
    int check_passed = 0;
    int data_min = info->con_data[0];
    int data_max = info->con_data[1];
	if(data_max==0)
		return MODBUS_DATA_CHECKED_OK;
    modbus_header_t *header;
	#ifdef DEBUG
	if(data_min == data_max)
		printk("Data checking is :%d\n",data_min);
	else{
   		printk("Data range is :%d-%d\n",data_min,data_max);
		}
   	#endif
    
    /* Lay the header struct over the payload */
    header = (modbus_header_t *) app_data;

    switch (header->function_code)
    {

		
       case MODBUS_FUNC_WRITE_SINGLE_REGISTER://0x06
        	check_data =ntohs( (*(uint16_t *)(app_data + MODBUS_MIN_LEN + 2 )));
        	if(data_check(data_min,data_max,check_data,!!(info->flags & MODBUSTCP_DATA)))
        		check_passed = 1;
        	break; 
			
        default: /* 默认通过 */
            check_passed = 1;
            break;
    }

    if (check_passed)
    {
	#ifdef DEBUG
    	printk("Request data check OK\n");
	#endif

        return MODBUS_DATA_CHECKED_OK;
    }
    else
    {
	#ifdef DEBUG
    	printk("Request data check FAIL\n");
	#endif

    	return MODBUS_DATA_CHECKED_FAIL;
   	}
}

//****************************************************************************
//函数名：ModbusDecode(char *app_data, __u16 app_len, __u8 flags)
//功能：ModbusTCP深度包解析
//参数：char *app_data, __u16 app_len, __u8 flags
//返回值：MODBUS_FAIL MODBUS_OK
//作者：zwj
//日期：2015-6-5
//备注：
//****************************************************************************
int ModbusDecode(char *app_data, __u16 app_len, __u8 flags, const struct xt_modbusTcp_mtinfo *info)
{
     modbus_header_t *header;

    if (app_len < MODBUS_MIN_LEN)
        return MODBUS_FAIL;

    /* Lay the header struct over the payload */
    header = (modbus_header_t *) app_data;

    /* The protocol ID field should read 0x0000 for Modbus. It allows for
       multiplexing with some other protocols over serial line. */
    if (header->protocol_id != MODBUS_PROTOCOL_ID)
    {
		#ifdef DEBUG
    		printk("modbus_protocol_id check FAIL\n");
		#endif

        return MODBUS_FAIL;
    }
		#ifdef DEBUG
    		printk("modbus_protocol_id check OK\n");
		#endif

	/*if(ModbusLenCheck(app_data,app_len) != MODBUS_LEN_OK)
	{
		#ifdef DEBUG
			printk("modbus_len check FAIL\n");
		#endif

		return MODBUS_FAIL;
	}
		#ifdef DEBUG
			printk("modbus_len check OK\n");
		#endif
	*/

	if( flags == FROM_SERVER_FLAG)
	{
		#ifdef DEBUG
			printk("reponse data packet\n");
		#endif

		//响应数据包
		if( ModbusCheckResponseLengths(app_data, app_len) != MODBUS_LEN_OK)
			return MODBUS_FAIL;
		//if( ModbusCheckResponseCoilAddr(app_data, app_len, info) != MODBUS_COIL_ADDR_CHECK_OK)
			//return MODBUS_FAIL;
	}
	else
	{
		#ifdef DEBUG
			printk("request data packet\n");
		#endif

		//请求数据包

		//if( ModbusCheckRequestLengths(app_data, app_len) != MODBUS_LEN_OK)
			//return MODBUS_FAIL;
		if( ModbusCheckFunctionCode(app_data,app_len,info) !=  MODBUS_FUNCODE_MATCHED)
					return MODBUS_FAIL;
		if( ModbusCheckRequestDataAddr(app_data, app_len, info) != MODBUS_DATA_ADDR_CHECK_OK)
			return MODBUS_FAIL;
		if( ModbusCheckRequestData(app_data, app_len, info) != MODBUS_DATA_CHECKED_OK)
			return MODBUS_FAIL;
	}

    return MODBUS_OK;
}
