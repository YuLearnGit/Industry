#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter.h>
//#include <linux/netfilter/xt_modbusTcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>

enum {
	MODBUSTCP_ADDR = 0x01,
	MODBUSTCP_FUNC = 0x02,
	MODBUSTCP_DATA = 0x04,
		
};

struct xt_modbusTcp_mtinfo {
	__u16 data_addr[2];   /* Modbus data address.  */
	__u8 modbus_func[2];  /* Modbus function code. */
	__u16 con_data[2];    /* Control data range.   */     
	__u8 flags;           /* Options invert flags  */
};


enum {
	O_ADDR = 0,
	O_FUNC,
	O_DATA,
};

static void modbusTcp_mt_help(void)
{
	printf(
"modbusTcp match options:\n"
"--data-addr address[:address]	    Match data address against value or range\n"
"							        of values (inclusive)\n"
"[!]--modbus-func funcode[:funcode]	Match modbus fuction code against value or range\n"
"							        of values (inclusive)\n"
"[!]--modbus-data data[:data]	    Match modbus control data against value or range\n"
"									of values (inclusive)\n");
}

static const struct xt_option_entry modbusTcp_mt_opts[] = {
	{.name = "data-addr", .id = O_ADDR, .type = XTTYPE_UINT16RC, .flags = XTOPT_INVERT},
	{.name = "modbus-func", .id = O_FUNC, .type = XTTYPE_UINT8RC, .flags = XTOPT_INVERT},
	{.name = "modbus-data", .id = O_DATA, .type = XTTYPE_UINT16RC, .flags = XTOPT_INVERT},
	XTOPT_TABLEEND,
};

static void modbusTcp_mt_parse(struct xt_option_call *cb)
{
	struct xt_modbusTcp_mtinfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_ADDR:
		info->data_addr[0]=cb->val.u16_range[0];
		info->data_addr[1]=cb->val.u16_range[0];
		if(cb->nvals >= 2)
			info->data_addr[1]=cb->val.u16_range[1];
		if (cb->invert)
			info->flags |= MODBUSTCP_ADDR;
                break;
	case O_FUNC:
		info->modbus_func[0]=cb->val.u8_range[0];
		info->modbus_func[1]=cb->val.u8_range[0];
		if(cb->nvals >= 2)
			info->modbus_func[1]=cb->val.u8_range[1];
		if (cb->invert)
			info->flags |= MODBUSTCP_FUNC;
				break;
	case O_DATA :
		info->con_data[0]=cb->val.u16_range[0];
		info->con_data[1]=cb->val.u16_range[0];
		if(cb->nvals >= 2)
			info->con_data[1]=cb->val.u16_range[1];
		if (cb->invert)
			info->flags |= MODBUSTCP_DATA;
                break;
	}
}

static void modbusTcp_mt_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM,
			   "modbusTcp match: You must specify `--data-addr' and '--modbus-func'and '--modbus-data' ");
}




static void
modbusTcp_mt_print(const void *ip, const struct xt_entry_match *match,int numeric)
{
	const struct xt_modbusTcp_mtinfo *info = (const void *)match->data;

	if(info->data_addr[1] != 0)
	{
		printf(" data address %s", (info->flags & MODBUSTCP_ADDR) ? "!" : "");
		if (info->data_addr[0] == info->data_addr[1])
			printf("%u", info->data_addr[0]);
		else
			printf("%u:%u", info->data_addr[0], info->data_addr[1]);
	}
	
	if(info->modbus_func[1] != 0)
	{
		printf(" function code %s", (info->flags & MODBUSTCP_ADDR) ? "!" : "");
		if (info->modbus_func[0] == info->modbus_func[1])
			printf("%u", info->modbus_func[0]);
		else
			printf("%u:%u", info->modbus_func[0], info->modbus_func[1]);
	}
	if(info->con_data[1] != 0)
	{
		printf(" modbus data %s", (info->flags & MODBUSTCP_DATA) ? "!" : "");
		if (info->con_data[0] == info->con_data[1])
			printf("%u", info->con_data[0]);
		else
			printf("%u:%u", info->con_data[0], info->con_data[1]);
	}

}





static void modbusTcp_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_modbusTcp_mtinfo *info = (const void *)match->data;

	if(info->data_addr[1] != 0)
	{
		printf(" data address %s", (info->flags & MODBUSTCP_ADDR) ? "!" : "");
		if (info->data_addr[0] == info->data_addr[1])
			printf("%u", info->data_addr[0]);
		else
			printf("%u:%u", info->data_addr[0], info->data_addr[1]);
	}
	
	if(info->modbus_func[1] != 0)
	{
		printf(" function code %s", (info->flags & MODBUSTCP_ADDR) ? "!" : "");
		if (info->modbus_func[0] == info->modbus_func[1])
			printf("%u", info->modbus_func[0]);
		else
			printf("%u:%u", info->modbus_func[0], info->modbus_func[1]);
	}
	if(info->con_data[1] != 0)
	{
		printf(" modbus data %s", (info->flags & MODBUSTCP_DATA) ? "!" : "");
		if (info->con_data[0] == info->con_data[1])
			printf("%u", info->con_data[0]);
		else
			printf("%u:%u", info->con_data[0], info->con_data[1]);
	}

}



static struct xtables_match modbusTcp_mt_reg = {

	
		.version       = XTABLES_VERSION,
		.name          = "modbusTcp",
		.revision      = 1,
		.family        = NFPROTO_IPV4,
		.size          = XT_ALIGN(sizeof(struct xt_modbusTcp_mtinfo)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_modbusTcp_mtinfo)),
		.help          = modbusTcp_mt_help,
		.x6_parse      = modbusTcp_mt_parse,
		.x6_fcheck     = modbusTcp_mt_check,
		.print         = modbusTcp_mt_print,
		.save          = modbusTcp_mt_save,
		.x6_options    = modbusTcp_mt_opts,
	

};

void _init(void)
{
	xtables_register_match(&modbusTcp_mt_reg);
       
}
