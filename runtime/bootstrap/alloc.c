#include <windows.h>

#define REGION_BITS 20       /* 1 MiB region (2^20) */
#define MIN_BLOCK_BITS 5     /* 32 bytes (2^5) */
#define BUDDY_REGION_SIZE (1 << REGION_BITS)
#define MIN_BLOCK_SIZE (1 << MIN_BLOCK_BITS)
#define NUM_LEVELS (REGION_BITS - MIN_BLOCK_BITS + 1)

struct FreeBlock {
    struct FreeBlock *next;
};

struct BlockHeader {
    unsigned int level;
};

static char buddy_region[BUDDY_REGION_SIZE];
static struct FreeBlock *freeLists[NUM_LEVELS];
static int initialized = 0;

static size_t block_size(int level) {
    return BUDDY_REGION_SIZE >> level;
}

static void buddy_init(void) {
    for (int i = 0; i < NUM_LEVELS; i++) {
        freeLists[i] = nullptr;
    }
    freeLists[0] = (struct FreeBlock*)buddy_region;
    freeLists[0]->next = nullptr;
    initialized = 1;
}

static void buddy_free_iter(void *addr, int level) {
    char *base = buddy_region;
    size_t bs;
    size_t offset, buddy_offset;
    void *buddy_addr;

    while (1) {
        if (level == 0)
            break;  /* Cannot merge further than the full region. */
        bs = block_size(level);
        offset = (char*)addr - base;
        buddy_offset = offset ^ bs;
        buddy_addr = base + buddy_offset;

        /* Search for the buddy in freeLists[level]. */
        struct FreeBlock **prev = &freeLists[level];
        struct FreeBlock *curr = freeLists[level];
        while (curr) {
            if ((void*)curr == buddy_addr)
                break;
            prev = &curr->next;
            curr = curr->next;
        }
        if (!curr)
            break;  /* Buddy is not free; merging stops. */

        /* Remove the buddy block from the free list. */
        *prev = curr->next;

        /* Select the lower address to represent the merged block. */
        if (offset > buddy_offset) {
            addr = buddy_addr;
        }
        /* Move up one level (i.e. merge to form a larger block). */
        level--;
    }
    /* Insert the (merged) block into the appropriate free list. */
    struct FreeBlock *block = (struct FreeBlock*)addr;
    block->next = freeLists[level];
    freeLists[level] = block;
}

void MemoryFree(void *ptr) {
    if (!ptr)
        return;
    struct BlockHeader *header = (struct BlockHeader*)((char*)ptr - sizeof(struct BlockHeader));

    int level = header->level;
    void *block_addr = (void*)header;
    buddy_free_iter(block_addr, level);
}

static void *buddy_alloc_level(int desired_level) {
    int i;
    for (i = 0; i <= desired_level; i++) {
        if (freeLists[i] != nullptr)
            break;
    }
    if (i > desired_level)
        return nullptr;  /* No sufficiently large block available. */
    
    /* Split blocks until reaching the desired level. */
    while (i < desired_level) {
        struct FreeBlock *block = freeLists[i];
        freeLists[i] = block->next;
        size_t bs = block_size(i + 1);
        /* Split the block into two buddies. */
        struct FreeBlock *buddy1 = block;
        struct FreeBlock *buddy2 = (struct FreeBlock*)((char*)block + bs);
        /* Insert both buddies into the next free list. */
        buddy1->next = freeLists[i + 1];
        freeLists[i + 1] = buddy1;
        buddy2->next = freeLists[i + 1];
        freeLists[i + 1] = buddy2;
        i++;
    }
    /* Remove and return a block at the desired level. */
    struct FreeBlock *block = freeLists[desired_level];
    if (block) {
        freeLists[desired_level] = block->next;
        return block;
    }
    return nullptr;
}

void *MemoryAllocate(size_t size) {
    if (size == 0)
        return nullptr;
    if (!initialized)
        buddy_init();

    /* Compute total block size needed (user size + header). */
    size_t total_size = size + sizeof(struct BlockHeader);
    int level = -1;
    /* Find the smallest level (i.e. smallest block) where the block size is sufficient. */
    for (int L = NUM_LEVELS - 1; L >= 0; L--) {
        if (block_size(L) >= total_size) {
            level = L;
            break;
        }
    }
    if (level < 0)
        return nullptr;  /* Request too large. */

    void *block = buddy_alloc_level(level);
    if (!block)
        return nullptr;

    /* Initialize header and return a pointer past the header. */
    struct BlockHeader *header = (struct BlockHeader*)block;
    header->level = level;
    return (void*)((char*)block + sizeof(struct BlockHeader));
}

static void buddy_shrink(void *block, int current_level, int target_level) {
    struct BlockHeader *header = (struct BlockHeader*)block;
    while (current_level < target_level) {
        size_t bs = block_size(current_level + 1);
        void *buddy_addr = (void*)((char*)block + bs);
        /* Free the buddy block (which is now not in use). */
        buddy_free_iter(buddy_addr, current_level + 1);
        current_level++;
        header->level = current_level;
        /* The primary block remains at 'block'. */
    }
}

void *buddy_realloc(void *ptr, size_t size) {
    if (ptr == nullptr)
        return MemoryAllocate(size);
    if (size == 0) {
        MemoryFree(ptr);
        return nullptr;
    }
    
    struct BlockHeader *header = (struct BlockHeader*)((char*)ptr - sizeof(struct BlockHeader));
    int current_level = header->level;
    size_t current_usable = block_size(current_level) - sizeof(struct BlockHeader);
    size_t new_total = size + sizeof(struct BlockHeader);
    
    int required_level = -1;
    for (int L = NUM_LEVELS - 1; L >= 0; L--) {
        if (block_size(L) >= new_total) {
            required_level = L;
            break;
        }
    }
    if (required_level < 0)
        return nullptr;  /* Requested size too large. */
    
    /* If the current block is large enough for the new request... */
    if (new_total <= block_size(current_level)) {
        /* For shrinkage, if the target level is higher (meaning a smaller block),
         * perform an in-place split.
         */
        if (required_level > current_level) {
            buddy_shrink((void*)header, current_level, required_level);
        }
        return ptr;
    }
    
    /* Otherwise, for growth, allocate a new block, copy the data, then free the old block. */
    void *new_ptr = MemoryAllocate(size);
    if (new_ptr) {
        size_t copy_size = (current_usable < size) ? current_usable : size;
        __builtin_memcpy(new_ptr, ptr, copy_size);
    }
    MemoryFree(ptr);
    return new_ptr;
}