/* Shared library add-on to iptables for the MARKMPLS target
 * (C) 2017 by Vadim Fedorenko <vadimjunk@gmail.com>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "../kernel/ipt_MARKMPLS.h"

static const struct xt_option_entry MARKMPLS_opts[] = {
	XTOPT_TABLEEND,
};

static void MARKMPLS_help(void)
{
	printf("MARKMPLS target inserts packet MARK "
		"as MPLS label\n");
}

static void MARKMPLS_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void MARKMPLS_check(struct xt_fcheck_call *cb)
{
}

static void MARKMPLS_save(const void *ip, const struct xt_entry_target *target)
{
}


static struct xtables_target MARKMPLS_tg_reg = {
	.name		= "MARKMPLS",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= 0,
	.userspacesize	= 0,
	.help		= MARKMPLS_help,
	.save		= MARKMPLS_save,
	.x6_parse	= MARKMPLS_parse,
	.x6_fcheck	= MARKMPLS_check,
	.x6_options	= MARKMPLS_opts,
};


void _init(void)
{
	xtables_register_target(&MARKMPLS_tg_reg);
}
