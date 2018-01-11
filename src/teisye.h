/* Copyright (C) 2010 Daiqian Huang <daiqian.huang@outlook.com>
 *
 * teisye is free software; you can redistribute it and/or modify it 
 * under the terms of the MIT License.
 */

/**
 * @file teisye.h
 *
 * The API definitions of teisye memory allocator.
 */
#pragma once

/* tsalloc
Allocates size bytes of uninitialized storage.

On success, returns the pointer to the beginning of newly allocated memory. To avoid a memory leak, 
the returned pointer must be deallocated with tsfree() or tsrealloc().

On failure, returns a null pointer.
*/
extern "C" void* tsalloc(size_t size);

/* tsfree
Deallocates the space previously allocated by tsalloc() or tsrealloc().

If ptr is a null pointer, the function does nothing.

If the value of ptr does not equal a value returned earlier by tsalloc() or tsrealloc(), the function 
very likely does nothing, but not guaranteed.

If the memory area referred to by ptr has already been deallocated by tsfree() or tsrealloc(), the function
very likely does nothing, but not guaranteed.
*/
extern "C" void tsfree(void* ptr);

/* tsrealloc
Reallocates a new memory block with new size, and copy the contents to the new memory block.

On success, returns the pointer to the beginning of newly allocated memory. To avoid a memory leak, 
the returned pointer must be deallocated with tsfree() or tsrealloc(). The original pointer ptr is 
invalidated and any access to it is undefined behavior.

On failure, returns a null pointer. The original pointer ptr remains valid and may need to be 
deallocated with free() or realloc().
*/
extern "C" void* tsrealloc(void* ptr, size_t newSize);
