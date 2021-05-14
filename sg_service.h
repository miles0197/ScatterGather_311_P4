#ifndef SG_SERVICE_INCLUDED
#define SG_SERVICE_INCLUDED

////////////////////////////////////////////////////////////////////////////////
//
//  File           : sg_service.h
//  Description    : This is the declaration of the interface to the 
//                   base functions for the ScatterGather service.

// Includes
#include <sg_defs.h>

// Defines 

// Type definitions

// Global interface definitions

int sgServicePost( char *packet, size_t *len, char *rpacket, size_t *rlen );
    // Post a packet to the ScatterGather service

#endif