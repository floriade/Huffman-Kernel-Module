/*
 * A Huffman coding kernel module
 *
 * Florian Deragisch <floriade@ee.ethz.ch>
 *
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <asm/uaccess.h>

#include <linux/spinlock.h>

#define ENGLISH		0
#define EALPHABETSZ	27
#define GERMAN 		1

#define ALPHABETSZ	50

#define MAXDEPTH	10


struct huffman_root {
	struct huffman_node *first;
	rwlock_t tree_lock;
};

struct huffman_node {
	unsigned char character;
	unsigned int frequency;
	struct huffman_node *next[2];
};

struct schedule_node {
    struct schedule_node *next;
    struct huffman_node *huffman;
};

struct language_book {
	unsigned char length;
	unsigned char character[ALPHABETSZ];
	unsigned short frequency[ALPHABETSZ];
};

struct code_book {
	unsigned char alphabetsz;
	unsigned short *code;
	unsigned char *length;
};

struct language_book english_book = {EALPHABETSZ, {'\0', 'z', 'q', 'x', 'j', 'k', 'v',
					'b', 'p', 'y', 'g', 'f', 'w', 'm', 'u', 'c',
					'l', 'd', 'r', 'h', 's', 'n', 'i', 'o', 'a',
					't', 'e'}, {3, 74, 95, 150, 153, 772, 978, 1492,
					1929, 1974, 2015, 2228, 2360, 2406, 2758, 2782,
					4025, 4253, 5987, 6094, 6327, 6749, 6966, 7507,
					8167, 9056, 12700}};

struct schedule_node *sched;
struct huffman_root *english_first;
struct code_book *code_en;

/*
 * huff_read is the function called when a process calls read() on
 * /dev/huffmod.  
 */


static ssize_t huff_read(struct file * file, char * buf, size_t count, loff_t *ppos)
{
	return 1;
}


static ssize_t huff_write(struct file *file, const char __user *in, size_t count, loff_t *off)
{
	return 1;
}

/*
 * The only file operation we care about is read and write
 */

static const struct file_operations huff_fops = {
	.owner		= THIS_MODULE,
	//.read		= huff_read,
	//.write		= huff_write,
};

static struct miscdevice huff_dev = {MISC_DYNAMIC_MINOR, "huffmod", &huff_fops};

static void struct_ctor(struct huffman_root *root, struct schedule_node *sched,
				struct code_book *book)
{
	book = kzalloc(sizeof(struct code_book), GFP_ATOMIC);
	root = kzalloc(sizeof(struct huffman_root), GFP_ATOMIC);
	sched = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);

	book->alphabetsz = EALPHABETSZ;
	book->code = kzalloc(EALPHABETSZ * sizeof(unsigned short), GFP_ATOMIC);
	book->length = kzalloc(EALPHABETSZ * sizeof(unsigned char), GFP_ATOMIC);

	root-> first = NULL;
	rwlock_init(&root->tree_lock);

	sched->huffman = NULL;
	sched->next = NULL;
}

static struct schedule_node *construct_schedule(struct language_book *book,
                                          struct schedule_node *first)
{
    struct huffman_node *tmphuff;
    struct schedule_node *tmpsched = NULL;
    struct schedule_node *tmpschedold = NULL;

    unsigned char i = 0;
	printk(KERN_ERR "Construct schedule start\n");

    for (i=0;i<book->length;i++) {
	printk(KERN_ERR "%d\n", i);
        tmpsched = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
        if (tmpsched == NULL) {
            printk(KERN_ERR "Schedule Node: Alloc failure.\n");
            return NULL;
        }
	printk(KERN_ERR "a\n");
        if (i != 0) { /* next ptr is set after 1st iteration */
            	printk(KERN_ERR "a1\n");
		tmpschedold->next = tmpsched;
	}
        else {
         	printk(KERN_ERR "a2\n");   
		first->next = tmpsched;
	}	
	printk(KERN_ERR "b\n");
        tmpsched->huffman = kzalloc(sizeof(struct huffman_node), GFP_ATOMIC);
        if (tmpsched->huffman == NULL) {
            printk(KERN_ERR "Huffman Node: Alloc failure.\n");
            return NULL;
        }
	printk(KERN_ERR "c\n");
        tmphuff = tmpsched->huffman;
        tmphuff->character = book->character[i];
        tmphuff->frequency = book->frequency[i];
        tmphuff->next[0] = NULL;
        tmphuff->next[1] = NULL;
        tmpschedold = tmpsched;
	printk(KERN_ERR "d\n");
    }
printk(KERN_ERR "eee\n");	
    tmpsched->next = NULL; /* last elem */
printk(KERN_ERR "Construct schedule finish\n");
    return tmpsched;
}

static void delete_tree(struct huffman_node *node)
{
	struct huffman_node *left, *right;

	if (node == NULL)
		return;
	left = node->next[0];
	right = node->next[1];

	kfree(node);
	
	delete_tree(left);	/* left child */
	delete_tree(right); /* right child */
}

/* To free sub-Huffman tree we need a more complex function */

static void deconstruct_schedule(struct schedule_node *first)
{
    struct schedule_node *tmpold = NULL;
    struct schedule_node *tmp = first;
    while (1) {
        if(tmp->huffman != NULL)
            delete_tree(tmp->huffman);
        tmpold = tmp;
        if(tmp->next != NULL)
		tmp = tmp->next;
        else {
		kfree(tmpold);
		break;
        }
        kfree(tmpold);
    }
}

static void traverse_tree(struct huffman_node *node, unsigned char depth, unsigned short counter)
{
	unsigned short val;
	unsigned short temp;
	unsigned char offset;

	if (node == NULL)
		return;
	if (node->next[0] == NULL && node->next[1] == NULL) {
		offset = (node->character == '\0') ? 0 : 96;
		val = counter>>(MAXDEPTH-depth);
		code_en->code[(node->character) - offset] = val;
		code_en->length[(node->character) - offset] = depth;
	}
		traverse_tree(node->next[0], depth+1, counter);	/* left child */
		temp = counter+(1<<((MAXDEPTH -1)-depth));
		traverse_tree(node->next[1], depth+1, temp); /* right child */

}
	
static int __init huff_init(void)
{
	int ret;

	struct_ctor(english_first, sched, code_en);
	printk(KERN_ERR "Ctor passed!\n");	
	//write_lock(&english_first->tree_lock);
	//printk(KERN_ERR "Locked\n");
	if (construct_schedule(&english_book, sched) == NULL) {
		printk(KERN_ERR "Scheduler failed!\n");
	//	goto scheduler_failed;
	}
	printk(KERN_ERR "Scheduler passed!\n");

	
	if ((ret = misc_register(&huff_dev))) {
		printk(KERN_ERR "Register failed!\n");
		//goto register_failed;	
	}
	printk(KERN_ERR "Register success!\n");
	//write_unlock(&english_first->tree_lock);
	//printk(KERN_ERR "Opened\n");
	
	return ret;

register_failed:
scheduler_failed:

	deconstruct_schedule(sched);
	write_unlock(&english_first->tree_lock);
	return -ENOMEM;
	}

static void __exit huff_exit(void)
{
	//write_lock(&english_first->tree_lock);
	//deconstruct_schedule(sched);	
	printk(KERN_ERR "Deregister successful\n");	
	misc_deregister(&huff_dev);
	//write_unlock(&english_first->tree_lock);
}

module_init(huff_init);
module_exit(huff_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Florian Deragisch <floriade@ee.ethz.ch>");
MODULE_DESCRIPTION("Huffman module");
MODULE_VERSION("dev");
