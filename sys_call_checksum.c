/*
 * I know this "defence" has its weaknesses but inserted to run
 * at initramfs with centralised logging it can prove to be useful
 * in certain environments that you might not be able to replatform
 * or replatform quickly.
 *
 * Was mostly an exercise in better understanding Linux internals and code.
 *
 * A beer owed to vrasneur@free.fr for the code I have reused, thanks for
 * publishing yours it was helpful to learn from. Also thanks to 0xAX for
 * linux-insides as it helped me appreciate a lot.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <asm/syscall.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("alternate");
MODULE_DESCRIPTION("Create a sha256 sum of the system call table");
MODULE_VERSION("0.1");

#define OFFSET_SYSCALL 256
int hash_sys_call_table(void **sys_call_tble);

static void **s_call_table = NULL;

static void const *rk_memmem(void const *haystack, size_t hl,
                             void const *needle, size_t nl)
{
    void const *res = NULL;

    if(nl <= hl) {
        int idx = 0;
        char const *buf = haystack;

        for(idx = 0; idx <= hl - nl; idx++) {
            if(memcmp(buf, needle, nl) == 0) {
                res = buf;
                break;
            }

            buf++;
        }
    }

    return res;
}

static void **rk_find_syscall_table(void)
{
    void **syscall_table = NULL;
    unsigned long syscall_entry;
    char const *buf = NULL;

    // get the entry_SYSCALL_64 address
    rdmsrl(MSR_LSTAR, syscall_entry);
    // find the sys_call_table reference in the code
    buf = rk_memmem((void const *)syscall_entry, OFFSET_SYSCALL, "\xff\x14\xc5", 3);

   if (buf != NULL) {
        // convert to pointer
        unsigned long ptr = *(unsigned long *)(buf + 3);
        syscall_table = (void **)(0xFFFFFFFF00000000 | ptr);
    }

    /*printk(KERN_INFO "found syscall table at: %p\n", syscall_table);*/

    return syscall_table;
}

int hash_sys_call_table(void **sys_call_tble) {

    struct scatterlist sg;
    struct hash_desc desc;

    unsigned char hashtext[64];

    /*We need to reserve 16 bytes for each char of the memory addresses of
     * __NR_syscall_max. 8 bytes in a long on a x86_64 */
    int table_len = ((sizeof(long) * 2) * __NR_syscall_max) + 1;
    unsigned char table_array[table_len];
    unsigned char *p = table_array;
    int n = 0, x = 0, i = 0;


    memset(hashtext, 0x00, sizeof(hashtext));
    memset(table_array, 0x00, sizeof(table_array));

    /* DEBUG
    int z = 0;
    for (z=0; z <= __NR_syscall_max; z++) {
	printk(KERN_INFO "%s syscall %d:%p", KBUILD_MODNAME, z, table[z]);
    }*/

    for (x=0; x < __NR_syscall_max; x++) {
	n = snprintf(NULL, 0, "%p", sys_call_tble[x]);
	snprintf(p, n+1, "%p", sys_call_tble[x]);
	p += n;
    }

    table_array[table_len] = '\0';

    sg_init_one(&sg, table_array, table_len);
    desc.tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);

    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, table_len);
    crypto_hash_final(&desc, hashtext);

    for(i = 0; i < strlen(hashtext); i++) {
        printk("%02x", hashtext[i]);
    }
    printk(KERN_DEBUG "\n");

    crypto_free_hash(desc.tfm);

    return 0;

}

static int __init mod_init(void) {

        printk(KERN_DEBUG "%s loaded\n", KBUILD_MODNAME);
	s_call_table = rk_find_syscall_table();
	hash_sys_call_table(s_call_table);
	return 0;
}

static void __exit mod_exit(void) {
        printk(KERN_DEBUG "%s unloaded\n", KBUILD_MODNAME);
	return;
}

module_init(mod_init);
module_exit(mod_exit);


