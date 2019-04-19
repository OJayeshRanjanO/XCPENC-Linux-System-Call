#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/cred.h>
#include "sys_cpenc.h"


asmlinkage long cpenc(void *arg)
{	
	//DECLARATIONS
	struct user_args * ag;
	unsigned long 	check_copy_user_args_return,
			check_copy_keybuf_return;
	mm_segment_t 	old_fs; 
	void * 	buffer = NULL;
	void * 	rehash = NULL;
	struct 	file * input = NULL;
	struct	file * output = NULL;
	int 	vfs_read_result,
		vfs_write_result,
		error,
	 	bytes_to_buffer,
		kern_in_return,
		kern_out_return,
		i;
	loff_t 	file_size;
	struct inode *in_inode = NULL;
	struct inode *out_inode = NULL;
	struct inode *out_parent_inode = NULL;
	struct dentry * out_dentry = NULL;
	struct filename * infile_user = NULL;
	struct filename * outfile_user = NULL;
	struct path path;
	const struct cred * cred;
	error = 0;
	
	//ALLOCATING SPACE FOR user_args STRUCT
	ag = kmalloc(sizeof(struct user_args),GFP_KERNEL);
	if (ag==NULL)
	{
		error = -ENOMEM;
		goto cpenc_out;
	}
	check_copy_user_args_return = copy_from_user(ag,((struct user_args *)arg),sizeof(struct user_args));
	if (check_copy_user_args_return != 0)
	{
		printk("Error when copying struct");
		error = -EFAULT;
		goto cpenc_out;
	}
	ag->keybuf = NULL;
	ag->infile = NULL;
	ag->outfile = NULL;


	/*Check if correct flags were sent*/
	ag->flags = ((struct user_args *)arg)->flags;
	printk("%d",ag->flags);
	if (ag->flags != 1 && ag->flags != 2 && ag->flags != 4)
	{
		error = -EINVAL;
		goto cpenc_out;
	}
	
	infile_user = getname( ((struct user_args *)arg)->infile );
	outfile_user = getname( ((struct user_args *)arg)->outfile );

	ag->infile = kmalloc(strlen(infile_user->name),GFP_KERNEL);
	strcpy(ag->infile, infile_user->name);

	ag->outfile = kmalloc(strlen(outfile_user->name),GFP_KERNEL);
	strcpy(ag->outfile, outfile_user->name);


	//CHECK IF 2 FILES ARE SAME
	/*Check to make sure two files do not have same name*/
	if (strcmp(ag->infile, ag->outfile) == 0)
	{
		printk("File names are same");
		error = -EINVAL;
		goto cpenc_out;
		
	}

	kern_in_return = kern_path(ag->infile, LOOKUP_FOLLOW, &path);
	if (kern_in_return != 0) //If the infile doesn't exist no need to go further
	{
		error = kern_in_return;
		goto cpenc_out;
	}
    	in_inode = path.dentry->d_inode;
	if (!S_ISREG(in_inode->i_mode)){
		printk("File is not regular");
		error = -EPERM;
		goto cpenc_out;
	}

	kern_out_return = kern_path(ag->outfile, LOOKUP_FOLLOW, &path);
	if (kern_out_return == 0) //If out file exists check for INODE numbers
	{	
		out_inode = path.dentry->d_inode;
		if (out_inode->i_ino == in_inode->i_ino)
		{
			printk("Input == Output");
			error = -EINVAL;
			goto cpenc_out;	
		}

		//Getting parent Inode just incase we need to delete later on
		out_parent_inode = path.dentry->d_parent->d_inode;
		out_dentry = path.dentry;
	}/*otherwise go ahead and create new file*/

	if(ag->flags == 1 || ag->flags == 2){/*If encryption and decryption is enabled*/	
		
		ag->keylen = ((struct user_args *)arg)->keylen;/*Check if keylen matches the keybuf size*/
		if ( !access_ok( VERIFY_READ , ((struct user_args *)arg)->keybuf , ag->keylen ) ){
			error = -EACCES;
			goto cpenc_out;
		}

		//ALLOCATING KERNAL ADDRESS FOR keybuf INSIDE struct user_args
		ag->keybuf = kmalloc(ag->keylen,GFP_KERNEL);
		if (ag->keybuf == NULL)
		{
			printk("Error when allocating for outfile");
			error = -ENOMEM;
			goto cpenc_out;
		}
		check_copy_keybuf_return = copy_from_user(ag->keybuf,((struct user_args *)arg)->keybuf,ag->keylen);
		if (check_copy_keybuf_return != 0)
		{
			printk("Error when copying keybuf");
			error = -EFAULT;
			goto cpenc_out;
		}


		/*Working on hash*/
		rehash = kmalloc(ag->keylen,GFP_KERNEL);
		memcpy(rehash,ag->keybuf,ag->keylen);
		/*memset(rehash,0,16);
		if (rehash == NULL)
		{
			printk("Error when allocating for rehash");
			error = -ENOMEM;
			goto cpenc_out;
		} 

		error = md5(ag->keybuf,&rehash);
		if (error != 0){
			printk("Error when rehashing");
			error = -error;
			goto cpenc_out;
		}*/
	}


	//THIS SEGMENT ALLOCATES BUFFER SPACE
	buffer = kmalloc(PAGE_SIZE,GFP_KERNEL);
 	if (buffer == NULL)
	{
		printk("Error when allocating for buffer");
		error = -ENOMEM;
		goto cpenc_out;
	}
  

	//OPENING FILES
	file_size = in_inode->i_size;
	input = filp_open(ag->infile, O_RDONLY, in_inode->i_mode);//@FILE_1_OPEN
	if (IS_ERR(input)) {
		printk("Error opening input file");
		input = NULL;
		error = -PTR_ERR(input);
		goto cpenc_out;
	}
	output = filp_open(ag->outfile,O_WRONLY|O_CREAT|O_TRUNC, in_inode->i_mode);//@FILE_2_OPEN
	if (IS_ERR(output)) 
	{
		printk("Error opening output file");
		output = NULL;
		error = -PTR_ERR(input);
		goto cpenc_out;
	}
	else/*If final can be opened*/
	{
		cred = current_cred();
		output->f_inode->i_uid = cred->uid;
		output->f_inode->i_gid = cred->gid;
	}


	//CHECKING THE ENCRYPTION KEY
	if (ag->flags == 1)
	{
		//THIS IS WHERE WE WRITE THE KEY
		old_fs = get_fs();
		set_fs(KERNEL_DS);//SETS data segment to KERNEL address so buffer __user can be KERNEL
		vfs_write_result = vfs_write(output, rehash, 16, &output->f_pos);//@FILE_2_WRITE 
		set_fs(old_fs);
		if (vfs_write_result < 0)
		{
			error = vfs_write_result;
			/* Source code taken from: https://elixir.bootlin.com/linux/v4.20.6/source/fs/namei.c#L4025*/	
			inode_lock_nested(out_parent_inode, I_MUTEX_PARENT);
			vfs_unlink(out_parent_inode, out_dentry, NULL);	
			inode_unlock(out_parent_inode);
			goto cpenc_out;
		}
	}
	else if (ag->flags == 2)
	{
		//THE FILE MUST HAVE 16 BYTES
		if (file_size < 16)
		{
			printk("Key tool small");
			error = -EINVAL;
			goto cpenc_out;
		}

		//THIS IS WHERE WE CHECK THE KEY
		memset(buffer,0,PAGE_SIZE);
		old_fs = get_fs();
		set_fs(KERNEL_DS);//SETS data segment to KERNEL address so buffer __user can be KERNEL
		vfs_read_result = vfs_read(input, buffer, 16, &input->f_pos);//@FILE_1_READ
		set_fs(old_fs);
		if (vfs_read_result < 0)
		{
			error = vfs_read_result;
			/* Source code taken from: https://elixir.bootlin.com/linux/v4.20.6/source/fs/namei.c#L4025*/	
			inode_lock_nested(out_parent_inode, I_MUTEX_PARENT);
			vfs_unlink(out_parent_inode, out_dentry, NULL);	
			inode_unlock(out_parent_inode);
			goto cpenc_out;
		}
		error = memcmp(buffer,rehash,16);
		if (error != 0)
		{
			printk("Keys don't match");
			error = -EKEYREJECTED;
			goto cpenc_out;
		}
		//SUBTRACT 16 BYTES OF KEY SIZE FROM FILE
		file_size -= 16;
	}

	//printk("File Size %llu\n",file_size);
	//printk("%d",ag->keylen);
	printk(ag->infile);
	printk(ag->outfile);

	while (file_size > 0){	
		/*No Return value required*/	
		memset(buffer,0,PAGE_SIZE);
	
		bytes_to_buffer = file_size < PAGE_SIZE ? file_size : PAGE_SIZE;
		file_size -= bytes_to_buffer;

		//THIS IS WHERE FILE WRITE HAPPENS	
		old_fs = get_fs();
		set_fs(KERNEL_DS);//SETS data segment to KERNEL address so buffer __user can be KERNEL
		vfs_read_result = vfs_read(input, buffer, bytes_to_buffer, &input->f_pos);//@FILE_1_READ
		set_fs(old_fs);				
		if (vfs_read_result < 0)
		{
			error = vfs_read_result;
			inode_lock_nested(out_parent_inode, I_MUTEX_PARENT);
			vfs_unlink(out_parent_inode, out_dentry, NULL);	
			inode_unlock(out_parent_inode);
			goto cpenc_out;
		}


		if (ag->flags == 1)
		{
			error = cipher(&buffer,bytes_to_buffer,rehash,1);
			printk("encrypt return: %d\n",error);
			if (error!=0){
				goto cpenc_out;
			}
		}
		else if (ag->flags == 2)
		{
			error = cipher(&buffer,bytes_to_buffer,rehash,0);
			printk("decrypt return: %d\n",error);
			if (error!=0){
				goto cpenc_out;
			}
		}


		//THIS IS WHERE FILE WRITE HAPPENS	
		old_fs = get_fs();
		set_fs(KERNEL_DS);//SETS data segment to KERNEL address so buffer __user can be KERNEL
		vfs_write_result = vfs_write(output, buffer, bytes_to_buffer, &output->f_pos);//@FILE_2_WRITE 
		set_fs(old_fs);
		if (vfs_write_result < 0)
		{
			error = vfs_write_result;
			inode_lock_nested(out_parent_inode, I_MUTEX_PARENT);
			vfs_unlink(out_parent_inode, out_dentry, NULL);	
			inode_unlock(out_parent_inode);
			goto cpenc_out;
		}
	}

cpenc_out:
	if (input)
		filp_close(input,0);//@FILE_1_CLOSE
	if (output)
		filp_close(output,0);//@FILE_2_CLOSE
	if (buffer)
		kfree(buffer);
	if (rehash)
		kfree(rehash);
	if (ag->keybuf)
		kfree(ag->keybuf);
	if (infile_user)
		putname(infile_user);
	if (outfile_user)
		putname(outfile_user);
	if (ag->outfile)
		kfree(ag->outfile);
	if (ag->infile)
		kfree(ag->infile);
	if (ag)
		kfree(ag);
	return error;
}

/*Source code taken from: https://www.kernel.org/doc/html/v4.11/crypto/api-samples.html*/
static unsigned int encdec(struct skcipher_def *sk,int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);

    else
        rc = crypto_skcipher_decrypt(sk->req);
    printk("encdec %d\n",rc);	
    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/*Source code taken from: https://www.kernel.org/doc/html/v4.11/crypto/api-samples.html*/
static int cipher(void ** buffer, int buffer_size, void * key,int enc_dec_flag)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *ivdata = NULL;
    int ret = 0;

    skcipher = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        ret = -PTR_ERR(skcipher);
	goto out;
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }
    /* AES 128 */
    if (crypto_skcipher_setkey(skcipher, key, 16)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
	ret = -ENOMEM;
        goto out;
    }
    strcpy(ivdata,"1234567890123456");
    

    sk.tfm = skcipher;
    sk.req = req;

    sg_init_one(&sk.sg, (char *)*buffer, buffer_size);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, buffer_size, ivdata);
    init_completion(&sk.result.completion);
    ret = (int)encdec(&sk, enc_dec_flag);
    if (ret)
        goto out;
    pr_info("Cipher triggered successfully\n");

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    return ret;
}

/*Source code taken from: https://stackoverflow.com/questions/11126027/using-md5-in-kernel-space-of-linux*/
int md5(char * string, void ** digest, int keylen) {

    struct shash_desc *desc;
    int init,update,final;	
    desc = kmalloc(sizeof(*desc), GFP_KERNEL);
    desc->tfm = crypto_alloc_shash("md5", 0, 0);
    if (IS_ERR(desc->tfm)){
	printk("could not allocate");
	return -PTR_ERR(desc->tfm);
    }

    init = crypto_shash_init(desc);
    if (init != 0){
	printk("could not init");
	return -init;
    }
    update = crypto_shash_update(desc, string, keylen);
    if (update != 0){
	printk("could not update");
	return -update;
    }
    final = crypto_shash_final(desc, (char *)(*digest));
    if (final != 0){
	printk("could not final");
	return -final;
    }
    return 0;

}



static int __init init_sys_cpenc(void)
{
	printk("installed new sys_cpenc module\n");
	if (sysptr == NULL)
		sysptr = cpenc;
	return 0;
}
static void  __exit exit_sys_cpenc(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cpenc module\n");
}
module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_LICENSE("GPL");
