#include <windows.h>

/* Constants for the bootstrap buddy allocator:
	- BUDDY_REGION_SIZE is 1 MiB.
	- MIN_BLOCK_SIZE is 32 bytes.
	- NUM_LEVELS is computed so that level 0 is the whole region and the
  highest level (NUM_LEVELS-1) yields blocks of MIN_BLOCK_SIZE.
*/
#define BUDDY_REGION_SIZE (1 << 20)  /* 1 MiB */
#define MIN_BLOCK_SIZE 32
#define NUM_LEVELS (20 - 5 + 1)  /* since 1 MiB=2^20 and 32=2^5, we have 16 levels */

struct FreeBlock {
	struct FreeBlock *next;
};

struct BlockHeader {
    unsigned int level;  /* which free-list level this block came from */
};

static char buddy_region[BUDDY_REGION_SIZE];

/* An array of free-lists for each block size. 
   Level 0: blocks of size BUDDY_REGION_SIZE.
   Level (NUM_LEVELS-1): blocks of size MIN_BLOCK_SIZE.
*/
static struct FreeBlock *freeLists[NUM_LEVELS];
static int initialized = 0;

static size_t block_size(int level) {
    return BUDDY_REGION_SIZE >> level;
}

static void buddy_init(void) {
    for (int i = 0; i < NUM_LEVELS; i++)
        freeLists[i] = 0;
    freeLists[0] = (struct FreeBlock*)buddy_region;
    freeLists[0]->next = nullptr;
    initialized = 1;
}

static void *buddy_alloc(int desired_level) {
    int i;
    /* start from smallest block (0) and search for desired (note: for small allocations, desired_level is high; only free block initially is at level 0) */
    for (i = 0; i <= desired_level; i++) {
        if (freeLists[i] != nullptr)
            break;
    }
    if (i > desired_level) {
        /* no block available in any larger class */
        return nullptr;
    }
    /* split the found block repeatedly until reaching desired_level */
    while (i < desired_level) {
        /* remove one block */
        struct FreeBlock *block = freeLists[i];
        freeLists[i] = block->next;
        /* split block into two buddies for level i+1 */
        size_t bs = block_size(i + 1);
        struct FreeBlock *buddy1 = block;
        struct FreeBlock *buddy2 = (struct FreeBlock*)((char*)block + bs);
        /* insert both buddies into freeLists[i+1] */
        buddy1->next = freeLists[i + 1];
        freeLists[i + 1] = buddy1;
        buddy2->next = freeLists[i + 1];
        freeLists[i + 1] = buddy2;
        i++;
    }
    /* reached desired level */
    struct FreeBlock *block = freeLists[desired_level];
    if (block) {
        freeLists[desired_level] = block->next;
        return block;
    }
    return nullptr;
}

/* Helper function to merge a free block with its buddy if possible.
   'level' is the current size class of the block pointed to by addr.
   Merging continues recursively until no merge is possible.
*/
static void buddy_free(void *addr, int level) {
    /* if largest block, merging is not possible */
    if (level == 0) {
        struct FreeBlock *block = (struct FreeBlock*)addr;
        block->next = freeLists[level];
        freeLists[level] = block;
        return;
    }
    char *base = buddy_region;
    size_t bs = block_size(level);
    size_t offset = (char*)addr - base;
    /* buddy's offset is XOR with size */
    size_t buddy_offset = offset ^ bs;
    void *buddy_addr = base + buddy_offset;
    
    /* iterate freeLists[level] for the buddy block */
    struct FreeBlock **prev = &freeLists[level];
    for (struct FreeBlock *curr = freeLists[level]; curr; curr = curr->next) {
        if ((void*)curr == buddy_addr) {
            /* found */
            *prev = curr->next;
            void *combined = (offset < buddy_offset) ? addr : buddy_addr;
            buddy_free(combined, level - 1);
            return;
        }
        prev = &curr->next;
    }
    /* not free: insert into freeLists[level]. */
    struct FreeBlock *block = (struct FreeBlock*)addr;
    block->next = freeLists[level];
    freeLists[level] = block;
}

void *__bootstrap_malloc(size_t size) {
    if (size == 0)
        return nullptr;
    
    if (!NtCurrentPeb()->ProcessHeap)
        return nullptr;
    
    if (!initialized)
        buddy_init();
    
    size_t total_size = size + sizeof(struct BlockHeader);
    
    /* smallest level L such that block_size(L) >= total_size */
    int level = -1;
    for (int L = NUM_LEVELS - 1; L >= 0; L--) {
        if (block_size(L) >= total_size) {
            level = L;
            break;
        }
    }
    if (level < 0) {
        /* size too large */
        return nullptr;
    }
    
    void *block = buddy_alloc(level);
    if (!block)
        return nullptr;
    
    struct BlockHeader *header = (struct BlockHeader*)block;
    header->level = level;
    
    /* return the LAST header (NOT current) */
    return (void*)((char*)block + sizeof(struct BlockHeader));
}

void __bootstrap_free(void *ptr) {
    if (!ptr)
        return;
    struct BlockHeader *header = (struct BlockHeader*)((char*)ptr - sizeof(struct BlockHeader));
    int level = header->level;
    void *block = (void*)header;
    buddy_free(block, level);
}

/*
   TODO Try inplace growth-shrink
*/
void *realloc(void *ptr, size_t size) {
    if (!ptr)
        return __bootstrap_malloc(size);
    if (size == 0) {
        __bootstrap_free(ptr);
        return nullptr;
    }
    struct BlockHeader *header = (struct BlockHeader*)((char*)ptr - sizeof(struct BlockHeader));
    int level = header->level;
    size_t old_block_size = block_size(level) - sizeof(struct BlockHeader);
    
    void *new_ptr = __bootstrap_malloc(size);
    if (new_ptr) {
        /* Copy the minimum of the old block size and the new size */
        size_t copy_size = (old_block_size < size) ? old_block_size : size;
        __builtin_memcpy(new_ptr, ptr, copy_size);
    }
    __bootstrap_free(ptr);
    return new_ptr;
}
