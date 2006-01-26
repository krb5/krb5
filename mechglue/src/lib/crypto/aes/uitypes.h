/*
 -------------------------------------------------------------------------
 Copyright (c) 2001, Dr Brian Gladman <brg@gladman.uk.net>, Worcester, UK.
 All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary 
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright 
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products 
      built using this software without specific written permission. 

 DISCLAIMER

 This software is provided 'as is' with no explcit or implied warranties
 in respect of any properties, including, but not limited to, correctness 
 and fitness for purpose.
 -------------------------------------------------------------------------
 Issue Date: 01/02/2002

 This file contains code to obtain or set the definitions for fixed length 
 unsigned integer types.
*/

#ifndef _UITYPES_H
#define _UITYPES_H

#if defined(__GNU_LIBRARY__)
#define HAS_INTTYPES_H
#elif !defined(_MSC_VER)
#include <limits.h>
#if ULONG_MAX > 0xFFFFFFFFUL
  #define MODEL_64
#else
  #define MODEL_32
#endif
#endif

#if defined HAS_INTTYPES_H || defined HAVE_INTTYPES_H
#include <inttypes.h>
#define s_u32     u
#define s_u64   ull
#elif defined MODEL_32
typedef unsigned char            uint8_t;
typedef unsigned short int      uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long long int  uint64_t;
#define s_u32     u
#define s_u64   ull
#elif defined MODEL_64
typedef unsigned char            uint8_t;
typedef unsigned short int      uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long int       uint64_t;
#define s_u32     u
#define s_u64    ul
#elif defined(_MSC_VER)
typedef unsigned  __int8         uint8_t;
typedef unsigned __int16        uint16_t;
typedef unsigned __int32        uint32_t;
typedef unsigned __int64        uint64_t;
#define s_u32    ui32
#define s_u64    ui64
#else
#error You need to define fixed length types in uitypes.h
#endif

#define sfx_lo(x,y) x##y
#define sfx_hi(x,y) sfx_lo(x,y)
#define x_32(p)     sfx_hi(0x##p,s_u32)
#define x_64(p)     sfx_hi(0x##p,s_u64)

#endif
