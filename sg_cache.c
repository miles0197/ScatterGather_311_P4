////////////////////////////////////////////////////////////////////////////////
//  File           : sg_driver.c

// Include Files
#include <stdlib.h>
#include <string.h>
#include <cmpsc311_log.h>

// Project Includes
#include <sg_cache.h>

// Defines
struct entry {
  unsigned int last_used;

  SG_Node_ID rem;
  SG_Block_ID blkid;
  SGDataBlock datablock;
};

static struct entry * entries = NULL;
static unsigned int entries_size = 0;
static unsigned int cache_hit = 0, cache_miss = 0;

// Functional Prototypes

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : initSGCache
// Description  : Initialize the cache of block elements
//
// Inputs       : maxElements - maximum number of elements allowed
// Outputs      : 0 if successful, -1 if failure

int initSGCache( uint16_t maxElements ) {
  int i;

  entries_size = maxElements;

  //allocate space for entries
  entries = (struct entry*) malloc(sizeof(struct entry)*entries_size);
  if(entries == NULL){
    logMessage(LOG_ERROR_LEVEL, "initSGCache: malloc failed");
    return -1;
  }

  //clear the cache
  for(i=0; i < entries_size; i++){
    entries[i].rem = SG_NODE_UNKNOWN;
    entries[i].blkid = SG_BLOCK_UNKNOWN;
    entries[i].last_used = 0;
  }
  cache_hit = cache_miss = 0;

  // Return successfully
  return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : closeSGCache
// Description  : Close the cache of block elements, clean up remaining data
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int closeSGCache( void ) {

  if(entries){
    free(entries);
  }

  logMessage(LOG_INFO_LEVEL, "closeSGCache: Cache miss: %u", cache_miss);
  logMessage(LOG_INFO_LEVEL, "closeSGCache: Cache hit: %u", cache_hit);
  logMessage(LOG_INFO_LEVEL, "closeSGCache: Hit ratio: %.2f", (float) cache_hit / (float)(cache_hit + cache_miss));

  // Return successfully
  return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : getSGDataBlock
// Description  : Get the data block from the block cache
//
// Inputs       : nde - node ID to find
//                blk - block ID to find
// Outputs      : pointer to block or NULL if not found

char * getSGDataBlock( SG_Node_ID nde, SG_Block_ID blk ) {
  int i;

  //linear search over cache
  for(i=0; i < entries_size; i++){
    //on match
    if( (entries[i].rem == nde) &&
        (entries[i].blkid == blk)){
      break;  //stop
    }
  }

  //if packet wasn't found
  if(i == entries_size){
    ++cache_miss;
    return NULL;
  }else{
    ++cache_hit;

    //update the last_used for each entry, except the one we hit
    entries[i].last_used--;
    for(i=0; i < entries_size; i++){
      entries[i].last_used++;
    }

    //return pointer to block data
    return entries[i].datablock;
  }

  // Return successfully
  return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : putSGDataBlock
// Description  : Get the data block from the block cache
//
// Inputs       : nde - node ID to find
//                blk - block ID to find
//                block - block to insert into cache
// Outputs      : 0 if successful, -1 if failure

int putSGDataBlock( SG_Node_ID nde, SG_Block_ID blk, char *block ) {
  int i;

  //linear search over cache to find if packet is inside
  for(i=0; i < entries_size; i++){
    //on match
    if( (entries[i].rem == nde) &&
        (entries[i].blkid == blk)){
      break;  //stop
    }
  }

  //if packet wasn't found
  if(i == entries_size){
    //packet is new, search for a free entry
    for(i=0; i < entries_size; i++){
      //on match
      if( (entries[i].rem == SG_NODE_UNKNOWN) &&
          (entries[i].blkid == SG_BLOCK_UNKNOWN)){
        break;  //stop
      }
    }

    //if packet wasn't found
    if(i == entries_size){
      unsigned int least_recently_used = 0;
      //evict "least recently used" packet from cache
      for(i=0; i < entries_size; i++){
        if(entries[i].last_used < entries[least_recently_used].last_used){
          least_recently_used = i;
        }
      }

      i = least_recently_used;
      //save the new block/node ids
      entries[i].rem = nde;
      entries[i].blkid = blk;
    }

  }else{
    //packet is inside the cache, just reset its age
    entries[i].last_used = 0;
  }

  //put the datablock in cache
  memcpy(entries[i].datablock, block, SG_BLOCK_SIZE);

  // Return successfully
  return( 0 );
}
