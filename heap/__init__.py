"""Heap allocator awareness: chunk layouts, free lists and byte roles.

Public data model (:mod:`.model`), platform / memory-map discovery
(:mod:`.platform`), VA-addressed reads over any dump source
(:mod:`.memory`), the allocator registry (:mod:`.registry`), allocator
detection (:mod:`.detect`) and the one analysis facade every caller uses
(:func:`.analyze.analyze_heap`).
"""

from .analyze import (analyze_heap, clear_heap_cache, heap_cache_size,
                      parse_allocator_hint)
from .detect import DetectionResult, detect_allocator
from .memory import VaMemory, strip_tag
from .model import (ARENA_MAIN, ARENA_MMAP, ARENA_THREAD, REGION_MAIN_HEAP,
                    REGION_MMAPPED_CHUNK, REGION_THREAD_HEAP, AllocatorKind,
                    ChunkState, Evidence, FreeList, HeapArena, HeapChunk,
                    HeapLayout, HeapRegion, HeapRole)
from .platform import (ASSUMED_PLATFORM, MappedRegion, TargetPlatform,
                       memory_map_of, module_paths, platform_of)
from .registry import (AllocatorDescriptor, DetectContext, DetectScore,
                       ParseOptions, get_allocator, register_allocator,
                       reduce_ready_kinds, registered_allocators,
                       unregister_allocator)
from .segments import ChunkBudget, HeapSegment, LayoutAssembler

__all__ = [
    "AllocatorKind", "ChunkState", "HeapRole", "HeapChunk", "HeapRegion",
    "FreeList", "Evidence", "HeapLayout", "HeapArena",
    "ARENA_MAIN", "ARENA_THREAD", "ARENA_MMAP",
    "REGION_MAIN_HEAP", "REGION_THREAD_HEAP", "REGION_MMAPPED_CHUNK",
    "HeapSegment", "ChunkBudget", "LayoutAssembler",
    "TargetPlatform", "ASSUMED_PLATFORM", "MappedRegion", "platform_of",
    "memory_map_of", "module_paths",
    "VaMemory", "strip_tag",
    "AllocatorDescriptor", "DetectContext", "DetectScore", "ParseOptions",
    "register_allocator", "unregister_allocator", "registered_allocators",
    "get_allocator", "reduce_ready_kinds",
    "DetectionResult", "detect_allocator",
    "analyze_heap", "clear_heap_cache", "heap_cache_size",
    "parse_allocator_hint",
]
