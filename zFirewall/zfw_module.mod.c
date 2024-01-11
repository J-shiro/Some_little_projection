#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xc3aaf0a9, "__put_user_1" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xce0d74fc, "module_put" },
	{ 0x687088, "try_module_get" },
	{ 0x92997ed8, "_printk" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x167e7f9d, "__get_user_1" },
	{ 0x8be3b0d2, "kmalloc_caches" },
	{ 0xabb42a28, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xbf2974c1, "__register_chrdev" },
	{ 0x5c00cae1, "init_net" },
	{ 0x68ca54a0, "nf_register_net_hook" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xe75c5bb0, "nf_unregister_net_hook" },
	{ 0xa98b56fc, "module_layout" },
};

MODULE_INFO(depends, "");

