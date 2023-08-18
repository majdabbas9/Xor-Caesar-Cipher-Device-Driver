#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "encdec.h"

#define MODULE_NAME "encdec"

#define ASCIISHELLLIMIT 128
MODULE_LICENSE("GPL");
MODULE_AUTHOR("majd , mohamed");

int 	encdec_open(struct inode* inode, struct file* filp);
int 	encdec_release(struct inode* inode, struct file* filp);
int 	encdec_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar(struct file* filp, char* buf, size_t count, loff_t* f_pos);
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos);

ssize_t encdec_read_xor(struct file* filp, char* buf, size_t count, loff_t* f_pos);
ssize_t encdec_write_xor(struct file* filp, const char* buf, size_t count, loff_t* f_pos);

int memory_size = 0;

MODULE_PARM(memory_size, "i");

int major = 0;

struct file_operations fops_caesar = {
    .open = encdec_open,
    .release = encdec_release,
    .read = encdec_read_caesar,
    .write = encdec_write_caesar,
    .llseek = NULL,
    .ioctl = encdec_ioctl,
    .owner = THIS_MODULE
};

struct file_operations fops_xor = {
    .open = encdec_open,
    .release = encdec_release,
    .read = encdec_read_xor,
    .write = encdec_write_xor,
    .llseek = NULL,
    .ioctl = encdec_ioctl,
    .owner = THIS_MODULE
};

// Implemetation suggestion:
// -------------------------
// Use this structure as your file-object's private data structure
typedef struct {
    unsigned char key;
    int read_state;
} encdec_private_date;

char* caesarCipherString; // the string for Caesar cipher that will be stored in the kernel
char* xorCipherString;   // the string for Xor cipher that will be stored in the kernel

int init_module(void)
{
    major = register_chrdev(major, MODULE_NAME, &fops_caesar);
    if (major < 0)
    {
        return major;
    }
    caesarCipherString = (char*)kmalloc(memory_size, GFP_KERNEL);   // Allocate memory into the kernel using GFP_KERNAL flag which in charge for storing in the kernel
    xorCipherString = (char*)kmalloc(memory_size, GFP_KERNEL);     // Allocate memory into the kernel using GFP_KERNAL flag which in charge for storing in the kernel

    return 0;
}

void cleanup_module(void)
{
    unregister_chrdev(major, MODULE_NAME);
    kfree(caesarCipherString);
    kfree(xorCipherString);
}

int encdec_open(struct inode* inode, struct file* filp)
{
    int minor = MINOR(inode->i_rdev);

    switch (minor) // checking if we need to update the file object "filp" op to fops caesar or xor
    {
    case 0:
        filp->f_op = &fops_caesar;
        break;
    case 1:
        filp->f_op = &fops_xor;
        break;
    default:
        return -ENODEV;
    }
    encdec_private_date* epd = kmalloc(sizeof(encdec_private_date), GFP_KERNEL); // allocating the privte data
    epd->key = 0;
    epd->read_state = ENCDEC_READ_STATE_DECRYPT; // default for reading state
    filp->private_data = epd; // updating filp private data
    return 0;
}

int encdec_release(struct inode* inode, struct file* filp)
{
    kfree(filp->private_data);
    return 0;
}

int encdec_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg)
{
    int minor = MINOR(inode->i_rdev), i = 0;

    switch (cmd)
    {
    case ENCDEC_CMD_CHANGE_KEY: // case we need to change the key
        ((encdec_private_date*)filp->private_data)->key = arg; 
        break;
    case ENCDEC_CMD_SET_READ_STATE: // case we need to change the read state
        ((encdec_private_date*)filp->private_data)->read_state = arg;
        break;
    case ENCDEC_CMD_ZERO:
        switch (minor) { // checking which string we need to zero (caesar or xor)

        case 0:
            for (i = 0; i < memory_size; i++)caesarCipherString[i] = 0;  // zeroing the string
            break;
        case 1:
            for (i = 0; i < memory_size; i++)xorCipherString[i] = 0;    // zeroing the string
            break;
        default:
            return -ENODEV;
        }
        break;
    }

    return 0;
}
ssize_t encdec_read_caesar(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
    if (*(f_pos) >= memory_size)return -EINVAL;

    int charSucceedToRead = 0, read_state = ((encdec_private_date*)filp->private_data)->read_state, i;
    char chTmp; // temp char to help us excute the reading

    if ((*(f_pos)+count) <= memory_size) // checking if there is space for all of reading count
    {
        charSucceedToRead = count;
        copy_to_user(buf, caesarCipherString + *(f_pos), charSucceedToRead); // copying the caesar string to the user buffer

        // if(read_state==ENCDEC_READ_STATE_RAW) do nothing we already copied to the user
        if (read_state == ENCDEC_READ_STATE_DECRYPT)
        {
            for (i = 0; i < count; i++)
            {
                chTmp = *(buf + i);
                chTmp = ((chTmp - ((encdec_private_date*)filp->private_data)->key) + ASCIISHELLLIMIT) % ASCIISHELLLIMIT; 
                *(buf + i) = chTmp; // updating the user buff
            }
        }
    }
    else // if there is no space
    {
        charSucceedToRead = memory_size - *(f_pos);
        copy_to_user(buf, caesarCipherString + *(f_pos), charSucceedToRead); // copying certain amount from the caesar string to user buffer

        if (read_state == ENCDEC_READ_STATE_DECRYPT)
        {
            for (i = 0; i < charSucceedToRead; i++)
            {
                chTmp = *(buf + i);
                chTmp = ((chTmp - ((encdec_private_date*)filp->private_data)->key) + ASCIISHELLLIMIT) % ASCIISHELLLIMIT;// updating the user buff
                *(buf + i) = chTmp;
            }
        }

    }

    *(f_pos)+=charSucceedToRead; // updating our postion
    return charSucceedToRead;
}
ssize_t encdec_write_caesar(struct file* filp, const char* buf, size_t count, loff_t* f_pos)
{
    if (*(f_pos) >= memory_size || (count + *(f_pos)) > memory_size)return -ENOSPC; // if postion is greater than the memory size or count + postion greater than memory size we do nothing

    copy_from_user(caesarCipherString+ *f_pos, buf, count);
    char chTmp; // temp char to help us
    int i = 0;

    for (i = *(f_pos); i < (count + *(f_pos)); i++)
    {
        chTmp = *(caesarCipherString + i);
        chTmp = (chTmp + ((encdec_private_date*)filp->private_data)->key) % ASCIISHELLLIMIT;
        *(caesarCipherString + i) = chTmp; // updating the caesar string
    }

    *(f_pos) += count;
    return count;
}
ssize_t encdec_read_xor(struct file* filp, char* buf, size_t count, loff_t* f_pos)
{
    if (*(f_pos) >= memory_size)return -EINVAL;

    int charSucceedToRead = 0, read_state = ((encdec_private_date*)filp->private_data)->read_state, i;
    char chTmp;// temp char to help us excute the reading

    if ((*(f_pos)+count) <= memory_size)// checking if there is space for all of reading count
    {
        charSucceedToRead = count;
        copy_to_user(buf, xorCipherString + *(f_pos), count);// copying the xor string to the user buffer

        // if(read_state==ENCDEC_READ_STATE_RAW) do nothing we already copied to the user
        if (read_state == ENCDEC_READ_STATE_DECRYPT)
        {
            for (i = 0; i < count; i++)
            {
                chTmp = *(buf + i);
                chTmp = chTmp ^ ((encdec_private_date*)filp->private_data)->key;  // copying certain amount from the xor string to user buffer
                *(buf + i) = chTmp;// updating the user buff
            }
        }
    }
    else // if there is no space
    {
        charSucceedToRead = memory_size - *(f_pos);
        copy_to_user(buf, caesarCipherString + *(f_pos), charSucceedToRead);

        if (read_state == ENCDEC_READ_STATE_DECRYPT)
        {
            for (i = 0; i < charSucceedToRead; i++)
            {
                chTmp = *(buf + i);
                chTmp = chTmp ^ ((encdec_private_date*)filp->private_data)->key;
                *(buf + i) = chTmp;// updating the user buff
            }
        }

    }
    *(f_pos)+=charSucceedToRead;
    return charSucceedToRead;
}
ssize_t encdec_write_xor(struct file* filp, const char* buf, size_t count, loff_t* f_pos)
{
    if (*(f_pos) >= memory_size || (count + (*f_pos)) > memory_size)return -ENOSPC;// if postion is greater than the memory size or count + postion greater than memory size we do nothing

    copy_from_user(xorCipherString + *f_pos, buf, count);
    char chTmp; // temp char to help us
    int i = 0;

    for (i = *(f_pos); i < (count + *(f_pos)); i++)
    {
        chTmp = *(xorCipherString + i);
        chTmp = chTmp ^ ((encdec_private_date*)filp->private_data)->key;
        *(xorCipherString + i) = chTmp;// updating the xor string
    }

    *(f_pos) += count;
    return count;
}
