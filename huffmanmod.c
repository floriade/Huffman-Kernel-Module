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
#include <linux/ctype.h>
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

char *longword = "Antidisestablishmentarianism";
char longwordencode[64];
char longworddecode[64];

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
	int i;
	struct huffman_node *tmphuff;
   	struct schedule_node *tmpsched = NULL;
   	struct schedule_node *tmpschedold = NULL;
	printk(KERN_ERR "Construct schedule start\n");

    	for (i=0;i<book->length;i++) {
        	tmpsched = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
		if (tmpsched == NULL) {
		    printk(KERN_ERR "Schedule Node: Alloc failure.\n");
		    return NULL;
		}
		if (i != 0) { /* next ptr is set after 1st iteration */
			tmpschedold->next = tmpsched;
		}
		else {  
			first->next = tmpsched;
		}	
		tmpsched->huffman = kzalloc(sizeof(struct huffman_node), GFP_ATOMIC);
		if (tmpsched->huffman == NULL) {
		    printk(KERN_ERR "Huffman Node: Alloc failure.\n");
		    return NULL;
		}
		tmphuff = tmpsched->huffman;
		tmphuff->character = book->character[i];
		tmphuff->frequency = book->frequency[i];
		tmphuff->next[0] = NULL;
		tmphuff->next[1] = NULL;
		tmpschedold = tmpsched;
    	};	
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

static void insert_schedule_node(struct schedule_node *node,
                           struct schedule_node *tree)
{
	struct schedule_node *tmpold = tree;
	struct schedule_node *tmp = tree->next;

	while (node->huffman->frequency > tmp->huffman->frequency) {
		if (tmp->next == NULL) {    /* was last element */
			tmp->next = node;       /* append new element */
			return;
		}
		tmpold = tmp;
		tmp = tmp->next;		    /* continue search */
	}
    node->next = tmp;               /* insert node */
    tmpold->next = node;
}

static struct huffman_node *extract_huffman_tree(struct schedule_node *first)
{
    struct huffman_node *parent;
    struct huffman_node *ptr;
    struct huffman_node *tmp1, *tmp2;
    struct schedule_node *firstcpy = first->next;
    struct schedule_node *tmp = firstcpy;
    struct schedule_node *head = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
    head->huffman = NULL;
    while (tmp != NULL) {           /* at least 2 more elem */
        tmp1 = tmp->huffman;        /* smaller elem */
        tmp2 = tmp->next->huffman;  /* larger elem */
        parent = kzalloc(sizeof(struct huffman_node), GFP_ATOMIC);
        if (parent == NULL) {
            printk(KERN_ERR "Huffman Node: Alloc failure!\n");
            return NULL;
        }
        parent->character = 0;
        parent->next[0] = tmp1;     /* smaller is left */
        parent->next[1] = tmp2;     /* larger is right */
        parent->frequency = tmp1->frequency + tmp2->frequency;
        tmp->next->huffman = parent;/* 2nd sched points to parent now */
        if (firstcpy->next->next == NULL) {	/* schedule tree empty */
        	ptr = tmp->next->huffman;
        	kfree(tmp);
        	kfree(head);
        	return ptr;
        }
        firstcpy = firstcpy->next->next;  /* first points now to 3rd elem*/
        tmp->next->next = NULL;		/* elem is isolated */
        head->next = firstcpy;
        insert_schedule_node(tmp->next, head);
        kfree(tmp);                  /* first elem is freed */
        firstcpy = head->next;
        tmp = firstcpy;
    }
    return NULL;
}

static unsigned char append_code(unsigned short code, unsigned char length,
							unsigned char free, int *bitstream,
							unsigned char mod)
{
	unsigned char modulo, leftover;
	int mask, tempbit;
	leftover = (mod != 0) ? mod : length;
	if (length > free) {	/* code & mask (nr of bits to append), shift to position */
		mask = (1 << free) -1;
		tempbit = (code >> (length - free)) & mask;
		(*bitstream) = (*bitstream) | tempbit ;
		modulo = length - free;
	}
	else {
		mask = (1 << leftover) -1;
		tempbit = (code & mask) << (free-leftover);
		(*bitstream) = (*bitstream) | tempbit;
		modulo = (free == length) ? 255 : 0;
	}
	return modulo;
}

static void decode_huffman(char *input, char *output, struct huffman_node *node)
{
	unsigned char path;
	unsigned char iteration = 0;
	char lastchar = 1;
	char *tempin = input;
	char *tempout = output;
	int bitstream = *((int *)(tempin));
	struct huffman_node *tmpnode;
	while (lastchar != '\0') {
		tmpnode = node;
		while (tmpnode->next[0] != NULL && tmpnode->next[1] != NULL) {
			path = (bitstream >> (31 - iteration++)) & 0x1;
			tmpnode = tmpnode->next[path];
			if (iteration == 32) {
				tempin += 4;
				bitstream = *((int *)(tempin));
				iteration = 0;
			}
		}
		lastchar = tmpnode->character;
		*tempout++ = lastchar;
	}
}

static void encode_huffman(char *input, char *output)
{

	unsigned char modulo, offset, length;
	unsigned short code;
	unsigned char freebits = 32;
	int bitstream = 0;
	unsigned char cont = 1;	/* end of text */
	char *tempin = input;
	char *tempout = output;
	while ( cont) {	/* end of string not yet reached */
		if (islower(*tempin))
			offset = 96;
		else if (isupper(*tempin))
			offset = 64;
		else if (*tempin == '\0') {
			offset = 0;
			cont = 0;
		}
		code = code_en->code[(*tempin)-offset];
		length = code_en->length[(*tempin)-offset];
		modulo = append_code(code, length, freebits, &bitstream, 0);
		if (modulo == 0)
			freebits = freebits - length;
		else if (modulo == 255) {
			memcpy(tempout, &bitstream, sizeof(int));
			tempout = tempout + 4;
			freebits = 32;
			bitstream = 0;
		}
		else {
			memcpy(tempout, &bitstream, sizeof(int));
			tempout = tempout + 4;
			freebits = 32;
			bitstream = 0;
			append_code(code, length, freebits, &bitstream, modulo);
			freebits = freebits - modulo;
		}
		tempin++;
	}
	memcpy(tempout, &bitstream, sizeof(int)); /* copy ..\n sequence */
}

static int __init huff_init(void)
{
	int ret;
	code_en = kzalloc(sizeof(struct code_book), GFP_ATOMIC);
	english_first = kzalloc(sizeof(struct huffman_root), GFP_ATOMIC);
	sched = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
	printk(KERN_ERR "After kzalloc!\n");
	struct_ctor(english_first, sched, code_en);
	printk(KERN_ERR "Ctor passed!\n");	
	//write_lock(&english_first->tree_lock);
	//printk(KERN_ERR "Locked\n");
	if (construct_schedule(&english_book, sched) == NULL) {
		printk(KERN_ERR "Scheduler failed!\n");
		goto scheduler_failed;
	}
	printk(KERN_ERR "Scheduler passed!\n");

	if ((english_first->first = extract_huffman_tree(sched)) == NULL) {
        printk(KERN_ERR "Tree extraction failed!\n");
        /* deinitialization */
        goto extract_tree_failed;
    }

	traverse_tree(english_first->first, 0, 0);
	printk("Done!\n");
	encode_huffman(longword, longwordencode);
	decode_huffman(longwordencode, longworddecode, english_first->first);
	printk(KERN_ERR "%s\n", longworddecode);


	if ((ret = misc_register(&huff_dev))) {
		printk(KERN_ERR "Register failed!\n");
		goto register_failed;	
	}
	printk(KERN_ERR "Register success!\n");
	//write_unlock(&english_first->tree_lock);
	//printk(KERN_ERR "Opened\n");

	return ret;

register_failed:
scheduler_failed:

	deconstruct_schedule(sched);
	//write_unlock(&english_first->tree_lock);
	return -ENOMEM;

extract_tree_failed:
	delete_tree(english_first->first);
	kfree(english_first);
	return -ENOMEM;
	}

static void __exit huff_exit(void)
{
	//write_lock(&english_first->tree_lock);
	//deconstruct_schedule(sched);	
	delete_tree(english_first->first);
	kfree(english_first);
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
