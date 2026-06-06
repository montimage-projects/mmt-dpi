
#include <stdio.h>  // fprintf()
#include <stdlib.h> // malloc()/realloc()/free()

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

/*EoF*/
