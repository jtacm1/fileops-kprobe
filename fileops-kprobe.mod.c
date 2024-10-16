#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
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
__used __section(__versions) = {
	{ 0x6e5e9ea5, "module_layout" },
	{ 0x1972d5cd, "param_ops_string" },
	{ 0x409bcb62, "mutex_unlock" },
	{ 0xd1fbc889, "unregister_kprobe" },
	{ 0x8ee53e31, "register_kprobe" },
	{ 0x977f511b, "__mutex_init" },
	{ 0xc5850110, "printk" },
	{ 0x953e1b9e, "ktime_get_real_seconds" },
	{ 0xf8aae665, "current_task" },
	{ 0x37a0cba, "kfree" },
	{ 0xb8ef88a6, "d_path" },
	{ 0xf163e0f9, "kmem_cache_alloc_trace" },
	{ 0xe157ef13, "kmalloc_caches" },
	{ 0x5a245f6d, "_raw_write_lock" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "81EF0250EC9B0EC8996CD89");
