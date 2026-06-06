
#include <stdio.h>  // fprintf()
#include <stdlib.h> // malloc()/realloc()/free()
#include <stdint.h> // uint8_t

#include "memory.h"
#include "mmt_core.h"

// B5 (remote-DoS hardening): allocation failure used to call abort(), which
// tears down the entire host process from inside a shared library - a packet
// that provokes a huge allocation could therefore crash the host (remote DoS).
//
// Contract (documented): mmt_malloc()/mmt_realloc() now RETURN NULL on
// allocation failure instead of aborting. Callers are expected to check for
// NULL and fail gracefully (e.g. drop the packet). This mirrors the standard
// malloc()/realloc() contract; existing callers such as load_plugin() and
// init_extraction() already test the result. On realloc failure the original
// block is left untouched (standard realloc semantics).


// static uint64_t allocated = 0;
// static uint64_t freed     = 0;


//  - - - - - - - - - - - - - -  //
//  P U B L I C   M E T H O D S  //
//  - - - - - - - - - - - - - -  //

void *mmt_malloc( size_t size )
{
   uint8_t *x0 = (uint8_t*)malloc( size + sizeof( size_t ));

   if( unlikely( x0 == NULL )) {
      // OOM: log and return NULL (do NOT abort the host). The caller must
      // tolerate a NULL result and fail gracefully (drop the packet).
      (void)fprintf( stderr, "mmt_malloc: not enough memory (%zu bytes)\n", size );
      return NULL;
   }

   *((size_t*)x0) = size;
   // allocated     += size;

   return (void*)( x0 + sizeof( size_t ));
}


void *mmt_realloc( void *x, size_t size )
{
   if( x == NULL ) {
      if( size == 0 ) return NULL; // nothig to do
      return mmt_malloc( size );
   }

   // x != NULL

   if( size == 0 ) {
      mmt_free( x );
      return NULL;
   }

   // ( x != NULL ) && ( size != 0 )

   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   size_t  psz = *((size_t*)x0);

   if( size <= psz ) return x; // nothing to do, existing block is large enough

   // ( x != NULL ) && ( size > psz )

   uint8_t *x1 = (uint8_t*)realloc( x0, size + sizeof( size_t ));

   if( x1 == NULL ) {
      // OOM: log and return NULL (do NOT abort the host). The original block
      // (x0) is left intact per standard realloc() semantics; the caller must
      // tolerate a NULL result and fail gracefully.
      (void)fprintf( stderr, "mmt_realloc: not enough memory (%zu bytes)\n", size );
      return NULL;
   }

   *((size_t*)x1) = size;
   // allocated     += ( size - psz );

   return (void*)( x1 + sizeof( size_t ));
}


void mmt_free( void *x )
{
   if( unlikely( x == NULL )) return; // nothing to do

   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   // freed += *((size_t*)x0);
   free( x0 );
}


// void mmt_meminfo( mmt_meminfo_t *m )
// {
//    m->allocated = allocated;
//    m->freed     = freed;
// }


//  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  //
//  P E R - F L O W   A R E N A   ( S L A B )   A L L O C A T O R            //
//  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  //
//
// Issue #20 (P2): collapse per-packet/per-session malloc/free churn into one
// create/destroy pair per flow. A bump-pointer block allocator: each request is
// carved (aligned) from the current block; when it no longer fits a fresh block
// is allocated and chained. Individual allocations are NEVER freed - the whole
// arena is released in one shot by mmt_arena_destroy() on session teardown.
//
// Unlike mmt_malloc(), arena allocations carry NO 8-byte size prefix and are
// returned aligned to MMT_ARENA_ALIGN (16) - they are fixed-size scratch blocks
// (TCP segment nodes + their payload copies) that are never realloc()'d.

#define MMT_ARENA_ALIGN        16u
#define MMT_ARENA_DEFAULT_BLK  ( 16u * 1024u )   // 16 KiB default block payload

#define MMT_ARENA_ALIGN_UP(n)  ( ( (n) + (MMT_ARENA_ALIGN - 1u) ) & ~(size_t)(MMT_ARENA_ALIGN - 1u) )

typedef struct mmt_arena_block_s {
   struct mmt_arena_block_s *next;  // next (older) block in the chain
   size_t                    capacity; // usable payload bytes in this block
   size_t                    used;      // payload bytes consumed so far
} mmt_arena_block_t;

struct mmt_arena_s {
   mmt_arena_block_t *current;     // head == block we are bumping from
   size_t             block_size;  // default payload size for fresh blocks
};

// Aligned size of the block header so the carved payload always starts aligned
// (malloc() itself returns suitably-aligned memory).
static const size_t MMT_ARENA_HDR = MMT_ARENA_ALIGN_UP( sizeof( mmt_arena_block_t ) );

static inline uint8_t *mmt_arena_block_data( mmt_arena_block_t *b )
{
   return (uint8_t*)b + MMT_ARENA_HDR;
}

mmt_arena_t *mmt_arena_create( size_t block_size )
{
   mmt_arena_t *a = (mmt_arena_t*)malloc( sizeof( mmt_arena_t ) );
   if( unlikely( a == NULL )) {
      (void)fprintf( stderr, "mmt_arena_create: not enough memory\n" );
      return NULL;
   }
   a->current    = NULL;
   a->block_size = ( block_size > 0 ) ? MMT_ARENA_ALIGN_UP( block_size )
                                      : MMT_ARENA_DEFAULT_BLK;
   return a;
}

void *mmt_arena_alloc( mmt_arena_t *a, size_t size )
{
   if( unlikely( a == NULL )) return NULL;
   if( size == 0 ) size = 1;

   size_t need = MMT_ARENA_ALIGN_UP( size );
   mmt_arena_block_t *b = a->current;

   if( b == NULL || ( b->used + need ) > b->capacity ) {
      // Grow: a fresh block big enough for this request (oversized requests get
      // their own dedicated block sized exactly to the request).
      size_t cap = ( need > a->block_size ) ? need : a->block_size;
      mmt_arena_block_t *nb = (mmt_arena_block_t*)malloc( MMT_ARENA_HDR + cap );
      if( unlikely( nb == NULL )) {
         (void)fprintf( stderr, "mmt_arena_alloc: not enough memory (%zu bytes)\n", size );
         return NULL;
      }
      nb->capacity = cap;
      nb->used     = 0;
      nb->next     = a->current; // prepend; current is always the chain head
      a->current   = nb;
      b            = nb;
   }

   void *p   = mmt_arena_block_data( b ) + b->used;
   b->used  += need;
   return p;
}

void mmt_arena_reset( mmt_arena_t *a )
{
   if( unlikely( a == NULL )) return;
   // Keep the head block (typically the largest, recently grown) for reuse and
   // release the rest, so a long-lived arena does not thrash malloc on reset.
   mmt_arena_block_t *head = a->current;
   if( head != NULL ) {
      mmt_arena_block_t *b = head->next;
      while( b != NULL ) {
         mmt_arena_block_t *nx = b->next;
         free( b );
         b = nx;
      }
      head->next = NULL;
      head->used = 0;
   }
}

void mmt_arena_destroy( mmt_arena_t *a )
{
   if( unlikely( a == NULL )) return;
   mmt_arena_block_t *b = a->current;
   while( b != NULL ) {
      mmt_arena_block_t *nx = b->next;
      free( b );
      b = nx;
   }
   free( a );
}

/*EoF*/
