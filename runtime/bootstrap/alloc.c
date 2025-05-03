#include "core.h"
#include "dbgio.h"
#include "windows.h"
#include <windows.h>
#include <winifnc.h>
#include <hash/ntdll.h>
#include <stdlib.h>
#include <string.h>

#define ALIGNMENT               8
#define DEFAULT_SEGMENT_SIZE   (64 * 1024)

typedef struct BlockHeader {
    size_t size;
    int free;
    struct BlockHeader *next;
    struct BlockHeader *prev;
} BlockHeader;

typedef struct HeapSegment {
    struct HeapSegment *next;
    size_t size;
    BlockHeader *first_block;
} HeapSegment;

static HeapSegment *heap_segments = NULL;

static size_t align_size(size_t size) {
    return (size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
}

static HeapSegment* allocate_segment(size_t seg_size) {
    SIZE_T regionSize = seg_size;
    void *base = NULL;
    
    NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }
    
    HeapSegment *seg = (HeapSegment*) base;
    seg->next = NULL;
    seg->size = regionSize;
    BlockHeader *block = (BlockHeader*)((char*)base + sizeof(HeapSegment));
    block->size = regionSize - sizeof(HeapSegment);
    block->free = 1;
    block->next = NULL;
    block->prev = NULL;
    seg->first_block = block;
    
    return seg;
}

static BlockHeader* find_free_block(size_t total_size) {
    HeapSegment *seg = heap_segments;
    while (seg) {
        BlockHeader *blk = seg->first_block;
        while (blk) {
            if (blk->free && blk->size >= total_size)
                return blk;
            blk = blk->next;
        }
        seg = seg->next;
    }
    return NULL;
}

static void split_block(BlockHeader *blk, size_t total_size) {
    if (blk->size >= total_size + sizeof(BlockHeader) + ALIGNMENT) {
        BlockHeader *new_blk = (BlockHeader*)((char*)blk + total_size);
        new_blk->size = blk->size - total_size;
        new_blk->free = 1;
        new_blk->next = blk->next;
        new_blk->prev = blk;
        if (blk->next)
            blk->next->prev = new_blk;
        blk->next = new_blk;
        blk->size = total_size;
    }
}

void *MemoryAllocate(size_t size) {
    if (size == 0)
        return NULL;
    
    size_t aligned_size = align_size(size);
    size_t total_size = aligned_size + sizeof(BlockHeader);
    
    BlockHeader *blk = find_free_block(total_size);
    if (!blk) {
        size_t seg_size = (total_size + sizeof(HeapSegment) > DEFAULT_SEGMENT_SIZE) ? 
                          (total_size + sizeof(HeapSegment)) : DEFAULT_SEGMENT_SIZE;
        HeapSegment *new_seg = allocate_segment(seg_size);
        if (!new_seg)
            return NULL;
        new_seg->next = heap_segments;
        heap_segments = new_seg;
        blk = new_seg->first_block;
    }
    
    split_block(blk, total_size);
    blk->free = 0;
    
    return (void *)((char*)blk + sizeof(BlockHeader));
}

static void coalesce(BlockHeader *blk) {
    if (blk->next && blk->next->free) {
        blk->size += blk->next->size;
        blk->next = blk->next->next;
        if (blk->next)
            blk->next->prev = blk;
    }
    
    if (blk->prev && blk->prev->free) {
        blk->prev->size += blk->size;
        blk->prev->next = blk->next;
        if (blk->next)
            blk->next->prev = blk->prev;
        blk = blk->prev;
    }
}

void MemoryFree(void *ptr) {
    if (!ptr)
        return;
    
    BlockHeader *blk = (BlockHeader*)((char*)ptr - sizeof(BlockHeader));
    blk->free = 1;
    coalesce(blk);
    
    HeapSegment *prev_seg = NULL;
    HeapSegment *seg = heap_segments;
    while (seg) {
        if ((char*)blk >= (char*)seg && (char*)blk < (char*)seg + seg->size) {
            BlockHeader *first = seg->first_block;
            if (first->free && first->prev == NULL &&
                first->next == NULL &&
                first->size == seg->size - sizeof(HeapSegment))
            {
                if (prev_seg)
                    prev_seg->next = seg->next;
                else
                    heap_segments = seg->next;
                
                SIZE_T regionSize = seg->size;
                void *base = seg;
                NTSTATUS status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &regionSize, MEM_RELEASE);
                if (!NT_SUCCESS(status)) { /* todo error */ }
            }
            break;
        }
        prev_seg = seg;
        seg = seg->next;
    }
}

void *MemoryReallocate(void *ptr, size_t size) {
    if (ptr == NULL)
        return MemoryAllocate(size);
    if (size == 0) {
        MemoryFree(ptr);
        return NULL;
    }
    
    BlockHeader *blk = (BlockHeader*)((char*)ptr - sizeof(BlockHeader));
    size_t aligned_size = align_size(size);
    size_t total_size = aligned_size + sizeof(BlockHeader);
    
    if (blk->size >= total_size) {
        split_block(blk, total_size);
        return ptr;
    }
    
    void *new_ptr = MemoryAllocate(size);
    if (new_ptr) {
        size_t copy_size = blk->size - sizeof(BlockHeader);
        if (copy_size > size)
            copy_size = size;
        memcpy(new_ptr, ptr, copy_size);
        MemoryFree(ptr);
    }
    
    return new_ptr;
}


void HeapDestroy(void) {
    HeapSegment *seg = heap_segments;
    while (seg) {
        HeapSegment *next = seg->next;
        SIZE_T regionSize = seg->size;
        void *base = seg;
        NTSTATUS status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &regionSize, MEM_RELEASE);
        if (!NT_SUCCESS(status)) { /* todo error */ }
        seg = next;
    }
    heap_segments = NULL;
}
