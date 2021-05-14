#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

////////////////////////////////////////////////////////////////////////////////
//  File           : sg_driver.c
// Include Files

// Project Includes
#include <sg_driver.h>
#include <sg_service.h>
#include <sg_cache.h>

// Defines
struct SgFHandleInfo {
  SgFHandle fh;
  char * name;
  size_t length;
  off_t offset;

  SG_Block_ID blocks_ids[SG_MAX_BLOCKS_PER_FILE];
  SG_Node_ID  node_ids[SG_MAX_BLOCKS_PER_FILE];
  int blk_offset[SG_MAX_BLOCKS_PER_FILE];  //offset for the specified block
  int num_blocks;
};

//
// Global Data
struct SgFHandleInfo ** fht = NULL;
int fht_size = 0, fht_len = 0;
unsigned int fh_id = 4;

// Driver file entry

// Global data
int sgDriverInitialized = 0; // The flag indicating the driver initialized
SG_Block_ID sgLocalNodeId;   // The local node identifier
SG_SeqNum sgLocalSeqno;      // The local sequence number

// Driver support functions
int sgInitEndpoint( void ); // Initialize the endpoint
int sgStopEndpoint( void ); // Stop the endpoint

//
// Functions
int init_fht(){
  int i;

  fht_size = 40;
  fht = (struct SgFHandleInfo **) malloc(sizeof(struct SgFHandleInfo *)*fht_size);
  if(fht == NULL){
    perror("malloc");
    return -1;
  }

  for(i=0; i < fht_size; i++){
    fht[i] = NULL;
  }

  return 0;
}

int fht_find(const SgFHandle fh){

  //if file handle is invalid
  if(fh < 0){
    return -1;
  }

  int i;
  for(i=0; i < fht_len; i++){
    if(fht[i]->fh == fh){
      return i; //fh is open in file handle table
    }
  }
  return -1;  //not found
}

int fht_idi(struct SgFHandleInfo * info){
  //find the block, which holds pos
	for (int i = 0; i < info->num_blocks; i++) {
		if( (info->offset >= info->blk_offset[i]) &&
        (info->offset < (info->blk_offset[i] + SG_BLOCK_SIZE))	){
			return i;
		}
	}
	return -1;
}

//Add a file handle to FHT
int fht_add(struct SgFHandleInfo * info){

  //if we have no space left in table
  if(fht_len >= fht_size){
    int i;

    //reallocate the array
    fht_size += 10;
    fht = (struct SgFHandleInfo **) realloc(fht, sizeof(struct SgFHandleInfo *)*fht_size);
    if(fht == NULL){
      perror("realloc");
      return -1;
    }

    for(i=0; i < fht_size; i++){
      fht[i] = NULL;
    }
  }

  //save handle in table
  fht[fht_len++] = info;

  return fht_len - 1;
}

void free_info(struct SgFHandleInfo * info){
  free(info->name);
  free(info);
}

//Close all file handles and clear FHT
int fht_clear(){

  //free each table entry
  int i;
  for(i=0; i < fht_len; i++){
    free_info(fht[i]);
    fht[i] = NULL;
  }

  //free the table
  free(fht);
  fht = NULL;

  fht_size = 0;
  fht_len = 0;

  return 0;
}

//
// File system interface implementation

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgopen
// Description  : Open the file for for reading and writing
//
// Inputs       : path - the path/filename of the file to be read
// Outputs      : file handle if successful test, -1 if failure

SgFHandle sgopen(const char *path) {

    // First check to see if we have been initialized
    if (!sgDriverInitialized) {

        // Call the endpoint initialization
        if ( sgInitEndpoint() ) {
            logMessage( LOG_ERROR_LEVEL, "sgopen: Scatter/Gather endpoint initialization failed." );
            return( -1 );
        }

        if(init_fht() == -1){
          logMessage( LOG_ERROR_LEVEL, "sgopen: Scatter/Gather FHT initialization failed." );
          return (-1);
        }

        // Set to initialized
        sgDriverInitialized = 1;
    }

    //create a handle info table entry
    struct SgFHandleInfo * info = (struct SgFHandleInfo *) malloc(sizeof(struct SgFHandleInfo));
    if(info == NULL){
      logMessage( LOG_ERROR_LEVEL, "sgopen: malloc failed." );
      return (-1);
    }

    info->fh = fh_id++;
    info->name = strdup(path);
    info->length = 0;
    info->offset = 0;
    info->num_blocks = 0;
    memset(info->blocks_ids, SG_BLOCK_UNKNOWN, sizeof(SG_Block_ID)*SG_MAX_BLOCKS_PER_FILE);
    memset(info->node_ids,   SG_NODE_UNKNOWN,  sizeof(SG_Node_ID)*SG_MAX_BLOCKS_PER_FILE);
    memset(info->blk_offset, 0, sizeof(int)*SG_MAX_BLOCKS_PER_FILE);

    //add handle to table

    if(fht_add(info) == -1){
      logMessage(LOG_ERROR_LEVEL, "FHT failed to add file [%s] with file handle [%d]", info->name, info->fh);
      free_info(info);
      return (-1);
    }

    logMessage(SGDriverLevel, "Opened file [%s] with file handle [%d]", info->name, info->fh);

    // Return the file handle
    return (info->fh);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgread
// Description  : Read data from the file
//
// Inputs       : fh - file handle for the file to read from
//                buf - place to put the data
//                len - the length of the read
// Outputs      : number of bytes read, -1 if failure

int sgread(SgFHandle fh, char *buf, size_t len) {

  char readPacket[SG_BASE_PACKET_SIZE], recvPacket[SG_DATA_PACKET_SIZE];
  char * pkt; //pointer to packet data - cache or datablock
  SGDataBlock datablock;
  size_t pktlen, rpktlen;
  SG_Node_ID loc, rem;
  SG_Block_ID blkid;
  SG_SeqNum sloc, srem;
  SG_System_OP op;
  SG_Packet_Status ret;

  const int index = fht_find(fh);
  if(index == -1){
    logMessage( LOG_ERROR_LEVEL, "sgread: fh %d not opened.",fh);
    return -1;
  }
  struct SgFHandleInfo * info = fht[index];

  if(info->offset >= info->length){
    logMessage( LOG_ERROR_LEVEL, "sgread: read after EOF on fh %d", fh);
    return -1;
  }

  //figure out which packet to read
  const int idi = fht_idi(info);

  //try to get packet from cache
  pkt = getSGDataBlock(info->node_ids[idi], info->blocks_ids[idi]);

  if(pkt == NULL){  //if packet is not in cache

    memset(readPacket, 0, SG_BASE_PACKET_SIZE);
    memset(recvPacket, 0, SG_DATA_PACKET_SIZE);

    // Setup the packet
    pktlen = SG_BASE_PACKET_SIZE;
    if ( (ret = serialize_sg_packet( sgLocalNodeId, // Local ID
                                    info->node_ids[idi],  // Remote ID
                                    info->blocks_ids[idi], // Block ID
                                    SG_OBTAIN_BLOCK,  // Operation
                                    SG_SEQNO_UNKNOWN, // Sender sequence number
                                    SG_SEQNO_UNKNOWN, // Receiver sequence number
                                    NULL, readPacket, &pktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgread: failed serialization of packet [%d].", ret );
        return( -1 );
    }

    // Send the packet
    rpktlen = SG_DATA_PACKET_SIZE;
    if ( sgServicePost(readPacket, &pktlen, recvPacket, &rpktlen) ) {
        logMessage( LOG_ERROR_LEVEL, "sgread: failed packet post" );
        return( -1 );
    }

    // Unpack the recieived data
    if ( (ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc,
                                    &srem, datablock, recvPacket, rpktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgread: failed deserialization of packet [%d]", ret );
        return( -1 );
    }
    //packet is deserialize in datablock, update pointer
    pkt = datablock;


    logMessage(SGDriverLevel, "sgDriverObtainBlock: Obtained block [%u] from node [%u]",blkid, rem);

    // Sanity check the return value
    if ( loc !=  sgLocalNodeId) {
        logMessage( LOG_ERROR_LEVEL, "sgread: bad local ID returned [%ul]", loc );
        return( -1 );
    }

    logMessage(SGDriverLevel, "Read %s (%d bytes at offset %u)", info->name, len, info->offset);
  }

  //determine, where we read from - start or middle of block
  const int pos = info->offset - info->blk_offset[idi];
  // do a simple check where we read from
  if((pos != 0) && (pos != (SG_BLOCK_SIZE / 2)) ){
    //if its not astart of block, or middle
    logMessage( LOG_ERROR_LEVEL, "sgread: pos != 0/512");
  }

  //do the reading by copying data from ptr -> buf
  memcpy(buf, &pkt[pos], len);

  //update file position
  info->offset += len;

  // Return the bytes processed
  return ( len );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgwrite
// Description  : write data to the file
//
// Inputs       : fh - file handle for the file to write to
//                buf - pointer to data to write
//                len - the length of the write
// Outputs      : number of bytes written if successful test, -1 if failure

int sgwrite(SgFHandle fh, char *buf, size_t len) {

  char writePacket[SG_DATA_PACKET_SIZE], recvPacket[SG_BASE_PACKET_SIZE];
  char * pkt; //pointer to packet data - cache or datablock
  SGDataBlock datablock;
  size_t pktlen, rpktlen;
  SG_Node_ID loc, rem;
  SG_Block_ID blkid;
  SG_SeqNum sloc, srem;
  SG_System_OP op;
  SG_Packet_Status ret;
  int idi = 0;  //id index in file info

  const int index = fht_find(fh);
  if(index == -1){
    logMessage( LOG_ERROR_LEVEL, "sgwrite: fh %d not opened.",fh);
    return -1;
  }
  struct SgFHandleInfo * info = fht[index];

  memset(writePacket, 0, SG_DATA_PACKET_SIZE);
  memset(recvPacket, 0, SG_BASE_PACKET_SIZE);
  memset(datablock, 0, SG_BLOCK_SIZE);

  pkt = datablock;

  idi = fht_idi(info);

  //if file pointer points within file
  if((idi >= 0) && (idi < info->num_blocks)){
    op = SG_UPDATE_BLOCK;

    blkid = info->blocks_ids[idi];
    rem = info->node_ids[idi];

    //check the cache for packet
    pkt = getSGDataBlock(info->node_ids[idi], info->blocks_ids[idi]);
    if(pkt == NULL){  //if packet is not in cache

      //return to block offset, so we can read whole block
      int orig_offset = info->offset;
      info->offset = info->blk_offset[idi];

      //get the old packet with sgread()
      if(sgread(fh, datablock, SG_BLOCK_SIZE) == -1){
        logMessage( LOG_ERROR_LEVEL, "sgwrite: failed to read existing block");
      }

      pkt = datablock;

      //return to the original file position
      info->offset = orig_offset;
    }

  }else{
    op = SG_CREATE_BLOCK;
    blkid = SG_BLOCK_UNKNOWN;
    rem = SG_NODE_UNKNOWN;

    //node/block ids are saved later, when we get them
    //save the offset of this new block
    idi = info->num_blocks++;
    info->blk_offset[idi] = info->offset;
  }

  //now we have the block data (old or new) and we copy the buf data to it

  //determine, where we read from - start or middle of block
  const int pos = info->offset - info->blk_offset[idi];
  // do a simple check where we read from
  if((pos != 0) && (pos != (SG_BLOCK_SIZE / 2)) ){
    //if its not astart of block, or middle
    logMessage( LOG_ERROR_LEVEL, "sgread: pos != 0/512");
  }

  //do the reading by copying data from buf -> ptr
  memcpy(&pkt[pos], buf, len);

  // Setup the packet
  pktlen = SG_DATA_PACKET_SIZE;
  if ( (ret = serialize_sg_packet( sgLocalNodeId, // Local ID
                                  rem,  // Remote ID
                                  blkid, // Block ID
                                  op,  // Operation
                                  SG_SEQNO_UNKNOWN, // Sender sequence number
                                  SG_SEQNO_UNKNOWN, // Receiver sequence number
                                  pkt, writePacket, &pktlen)) != SG_PACKT_OK ) {
      logMessage( LOG_ERROR_LEVEL, "sgwrite: failed serialization of packet [%d].", ret );
      return( -1 );
  }

  // Send the packet
  rpktlen = SG_BASE_PACKET_SIZE;
  if ( sgServicePost(writePacket, &pktlen, recvPacket, &rpktlen) ) {
      logMessage( LOG_ERROR_LEVEL, "sgwrite: failed packet post" );
      return( -1 );
  }

  // Unpack the recieived data
  if ( (ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc,
                                  &srem, NULL, recvPacket, rpktlen)) != SG_PACKT_OK ) {
      logMessage( LOG_ERROR_LEVEL, "sgwrite: failed deserialization of packet [%d]", ret );
      return( -1 );
  }

  // Sanity check the return value
  if ( loc != sgLocalNodeId) {
      logMessage( LOG_ERROR_LEVEL, "sgwrite: bad local ID returned [%ul]", loc );
      return( -1 );
  }

  //increase file size only only create
  if(op == SG_CREATE_BLOCK){
    //save the block id and remote node id
    if(info->num_blocks < (SG_MAX_BLOCKS_PER_FILE-1) ){

      logMessage(SGDriverLevel, "sgDriverCreateBlock: Created block [%ul] on node [%ul]", blkid, rem );

      //save rest of block info
      info->blocks_ids[idi] = blkid;
      info->node_ids[idi]   = rem;
    }else{
      logMessage( LOG_ERROR_LEVEL, "sgwrite: SG_MAX_BLOCKS_PER_FILE reached for file %s", info->name );
      return (-1);
    }

    info->length += SG_BLOCK_SIZE;
  }

  info->offset += len;
  logMessage(SGDriverLevel, "Wrote %s (fh=%d, %d bytes at offset %u)", info->name, info->fh, info->length, info->offset);

  //put the new packet in cache, only on create
  //the update is write-through ( pkt points to block data in cache)
  putSGDataBlock(rem, blkid, pkt);

  // Return the bytes written
  return ( len );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgseek
// Description  : Seek to a specific place in the file
//
// Inputs       : fh - the file handle of the file to seek in
//                off - offset within the file to seek to
// Outputs      : new position if successful, -1 if failure

int sgseek(SgFHandle fh, size_t off) {

  const int index = fht_find(fh);
  if(index == -1){
    logMessage( LOG_ERROR_LEVEL, "sgread: fh %d not opened.",fh);
    return -1;
  }
  struct SgFHandleInfo * info = fht[index];

  if(off > info->length){
    logMessage( LOG_ERROR_LEVEL, "sgseek: seek past EOF for %s", info->name);
    return (-1);
  }


  //set file position to seek position
  info->offset = off;

  logMessage( SGDriverLevel, "Seeked file %s with fh=%d to offset %d",info->name, info->fh, info->offset
);
  // Return new position
  return( off );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgclose
// Description  : Close the file
//
// Inputs       : fh - the file handle of the file to close
// Outputs      : 0 if successful test, -1 if failure

int sgclose(SgFHandle fh) {

  const int index = fht_find(fh);

  if(index == -1){
    logMessage( LOG_ERROR_LEVEL, "sgclose: fh %d not opened.",fh);
    return -1;
  }

  struct SgFHandleInfo * info = fht[index];

  //remove closed file from table
  fht[index] = NULL;

  //put on its place the last opened handle
  if(index < (fht_len-1)){
    fht[index] = fht[fht_len-1];
  }
  fht_len--;

  logMessage( SGDriverLevel, "Closed file %s with fh=%d ",info->name, info->fh);

  free_info(info);

    // Return successfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgshutdown
// Description  : Shut down the filesystem
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

int sgshutdown(void) {

  fht_clear();
  sgStopEndpoint();
  closeSGCache();

    // Log, return successfully
    logMessage( LOG_INFO_LEVEL, "Shut down Scatter/Gather driver." );
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : validate_sg_packet
// Description  : Validates the SG packet fields
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
// Outputs      : 0 if successfully created, -1 if failure
static SG_Packet_Status validate_sg_packet( SG_Node_ID loc, SG_Node_ID rem, SG_Block_ID blk,
        SG_System_OP op, SG_SeqNum sseq, SG_SeqNum rseq){
    //validate the input
    if(loc == 0){
      return SG_PACKT_LOCID_BAD;
    }

    if(rem == 0){
      return SG_PACKT_REMID_BAD;
    }

    if(blk == 0){
      return SG_PACKT_BLKID_BAD;
    }

    if(op >= SG_MAXVAL_OP){
      return SG_PACKT_OPERN_BAD;
    }

    if(sseq == 0){
      return SG_PACKT_SNDSQ_BAD;
    }

    if(rseq == 0){
      return SG_PACKT_RCVSQ_BAD;
    }

    return SG_PACKT_OK;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : serialize_sg_packet
// Description  : Serialize a ScatterGather packet (create packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status serialize_sg_packet(SG_Node_ID loc, SG_Node_ID rem, SG_Block_ID blk,
                                     SG_System_OP op, SG_SeqNum sseq, SG_SeqNum rseq, char *data,
                                     char *packet, size_t *plen) {

    SG_Packet_Status validation = validate_sg_packet(loc, rem, blk, op, sseq, rseq);
    if( validation != SG_PACKT_OK){
      return validation;
    }

    //start serializing the packet

    //set the magic field
    uint32_t * magic = (uint32_t*) packet;
    *magic = SG_MAGIC_VALUE;

    packet += 4;  //move to the next field  Sndr ID

    uint64_t * sndr_id = (uint64_t *)packet;
    *sndr_id = loc;

    packet += 8;  //move to the next field  Rcvr ID
    uint64_t * rcvr_id = (uint64_t *)packet;
    *rcvr_id = rem;

    packet += 8;  //move to the next field  Blk ID
    uint64_t * blk_id = (uint64_t *)packet;
    *blk_id = blk;

    packet += 8;  //move to the next field  Op
    uint32_t * opp = (uint32_t *)packet;
    *opp = op;

    packet += 4;  //move to the next field  Sndr Seq
    uint16_t * sndr_seq = (uint16_t *)packet;
    *sndr_seq = sseq;

    packet += 2;  //move to the next field  Rcvr Seq
    uint16_t * rcvr_seq = (uint16_t *)packet;
    *rcvr_seq = rseq;

    packet += 2;  //move to the next field  Dat
    char * dat = (char *)packet;
    *dat = (data == NULL) ? 0 : 1;

    packet += 1;  //move to the data block field
    if(*dat == 1){  //if we have data
      //copy the data to packet buffer
      char * data_block = (char*) packet;
      memcpy(data_block, data, SG_BLOCK_SIZE);

      packet += SG_BLOCK_SIZE;  //move to the magic field at end of packet

      *plen = SG_BASE_PACKET_SIZE + SG_BLOCK_SIZE;
    }else{
      *plen = SG_BASE_PACKET_SIZE;
    }

    magic = (uint32_t*) packet;
    *magic = SG_MAGIC_VALUE;

    return SG_PACKT_OK;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : deserialize_sg_packet
// Description  : De-serialize a ScatterGather packet (unpack packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status deserialize_sg_packet(SG_Node_ID *loc, SG_Node_ID *rem, SG_Block_ID *blk,
                                       SG_System_OP *op, SG_SeqNum *sseq, SG_SeqNum *rseq, char *data,
                                       char *packet, size_t plen) {

    //start deserializing the packet

    //set the magic field
    uint32_t * magic = (uint32_t*) packet;
    if(*magic != SG_MAGIC_VALUE){
      //there is no value for bad magic!
      return SG_PACKT_LOCID_BAD;
    }

    packet += 4;  //move to the next field  Sndr ID

    const uint64_t * sndr_id = (uint64_t *)packet;
    *loc = *sndr_id;

    packet += 8;  //move to the next field  Rcvr ID
    const uint64_t * rcvr_id = (uint64_t *)packet;
    *rem = *rcvr_id;

    packet += 8;  //move to the next field  Blk ID
    const uint64_t * blk_id = (uint64_t *)packet;
    *blk = *blk_id;

    packet += 8;  //move to the next field  Op
    const uint32_t * opp = (uint32_t *)packet;
    *op = *opp;

    packet += 4;  //move to the next field  Sndr Seq
    const uint16_t * sndr_seq = (uint16_t *)packet;
    *sseq = *sndr_seq;

    packet += 2;  //move to the next field  Rcvr Seq
    const uint16_t * rcvr_seq = (uint16_t *)packet;
    *rseq = *rcvr_seq;

    packet += 2;  //move to the next field  Dat
    const char * dat = (char *)packet;

    packet += 1;  //move to the data block field

    if(*dat == 1){  //if we have data

      //check if we have space for the block data
      if(plen < SG_BLOCK_SIZE + SG_BASE_PACKET_SIZE){
        return SG_PACKT_BLKLN_BAD;
      }

      //copy the data to packet buffer
      char * data_block = (char*) packet;

      int i;
      for(i=0; i < SG_BLOCK_SIZE; ++i){
        data[i] = data_block[i];
      }
      packet += SG_BLOCK_SIZE;  //move to the magic field at end of packet
    }

    magic = (uint32_t*) packet;
    if(*magic != SG_MAGIC_VALUE){
      return SG_PACKT_BLKDT_BAD;
    }

  return validate_sg_packet(*loc, *rem, *blk, *op, *sseq, *rseq);
}

//
// Driver support functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgInitEndpoint
// Description  : Initialize the endpoint
//
// Inputs       : none
// Outputs      : 0 if successfull, -1 if failure

int sgInitEndpoint( void ) {

    // Local variables
    char initPacket[SG_BASE_PACKET_SIZE], recvPacket[SG_BASE_PACKET_SIZE];
    size_t pktlen, rpktlen;
    SG_Node_ID loc, rem;
    SG_Block_ID blkid;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    // Local and do some initial setup
    logMessage( LOG_INFO_LEVEL, "Initializing local endpoint ..." );
    sgLocalSeqno = SG_INITIAL_SEQNO;

    // Setup the packet
    pktlen = SG_BASE_PACKET_SIZE;
    if ( (ret = serialize_sg_packet( SG_NODE_UNKNOWN, // Local ID
                                    SG_NODE_UNKNOWN,   // Remote ID
                                    SG_BLOCK_UNKNOWN,  // Block ID
                                    SG_INIT_ENDPOINT,  // Operation
                                    sgLocalSeqno++,    // Sender sequence number
                                    SG_SEQNO_UNKNOWN,  // Receiver sequence number
                                    NULL, initPacket, &pktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: failed serialization of packet [%d].", ret );
        return( -1 );
    }

    // Send the packet
    rpktlen = SG_BASE_PACKET_SIZE;
    if ( sgServicePost(initPacket, &pktlen, recvPacket, &rpktlen) ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: failed packet post" );
        return( -1 );
    }

    // Unpack the recieived data
    if ( (ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc,
                                    &srem, NULL, recvPacket, rpktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: failed deserialization of packet [%d]", ret );
        return( -1 );
    }

    // Sanity check the return value
    if ( loc == SG_NODE_UNKNOWN ) {
        logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: bad local ID returned [%ul]", loc );
        return( -1 );
    }

    // Set the local node ID, log and return successfully
    sgLocalNodeId = loc;
    logMessage( LOG_INFO_LEVEL, "Completed initialization of node (local node ID %lu", sgLocalNodeId );

    if(initSGCache(SG_MAX_CACHE_ELEMENTS) == -1){
      logMessage( LOG_ERROR_LEVEL, "sgInitEndpoint: cache failed to init");
    }

    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgStopEndpoint
// Description  : Stop the endpoint
//
// Inputs       : none
// Outputs      : 0 if successfull, -1 if failure

int sgStopEndpoint( void ) {

    // Local variables
    char stopPacket[SG_BASE_PACKET_SIZE], recvPacket[SG_BASE_PACKET_SIZE];
    size_t pktlen, rpktlen;
    SG_Node_ID loc, rem;
    SG_Block_ID blkid;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    // Local and do some initial setup
    logMessage( LOG_INFO_LEVEL, "Stopping local endpoint ..." );

    // Setup the packet
    pktlen = SG_BASE_PACKET_SIZE;
    if ( (ret = serialize_sg_packet( sgLocalNodeId, // Local ID
                                    SG_NODE_UNKNOWN,   // Remote ID
                                    SG_BLOCK_UNKNOWN,  // Block ID
                                    SG_STOP_ENDPOINT,  // Operation
                                    sgLocalSeqno++,    // Sender sequence number
                                    SG_SEQNO_UNKNOWN,  // Receiver sequence number
                                    NULL, stopPacket, &pktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgStopEndpoint: failed serialization of packet [%d].", ret );
        return( -1 );
    }

    // Send the packet
    rpktlen = SG_BASE_PACKET_SIZE;
    if ( sgServicePost(stopPacket, &pktlen, recvPacket, &rpktlen) ) {
        logMessage( LOG_ERROR_LEVEL, "sgStopEndpoint: failed packet post" );
        return( -1 );
    }

    // Unpack the recieived data
    if ( (ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc,
                                    &srem, NULL, recvPacket, rpktlen)) != SG_PACKT_OK ) {
        logMessage( LOG_ERROR_LEVEL, "sgStopEndpoint: failed deserialization of packet [%d]", ret );
        return( -1 );
    }

    // Sanity check the return value
    if ( loc == SG_NODE_UNKNOWN ) {
        logMessage( LOG_ERROR_LEVEL, "sgStopEndpoint: bad local ID returned [%ul]", loc );
        return( -1 );
    }

    logMessage( LOG_INFO_LEVEL, "Stopped local node (local node ID %lu", sgLocalNodeId );
    return( 0 );
}
