/**

	@file		blowfish.h

	@brief		Public interface for Bruce Schneier's 64-bit symmetric block
				cipher, Blowfish.

	@author		Tom Bonner (tom.bonner@gmail.com)

	@date		15-June-2008

	Copyright (c) 2008, Tom Bonner.

	Permission is hereby granted, free of charge, to any person obtaining a
	copy of this software and associated documentation files (the "Software"),
	to deal in the Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute, sublicense,
	and/or sell copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	Except as contained in this notice, the name(s) of the above copyright
	holders shall not be used in advertising or otherwise to promote the sale,
	use or other dealings in this Software without prior written authorisation.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
	DEALINGS IN THE SOFTWARE.

  */ 

#ifndef __BLOWFISH_H__
#define __BLOWFISH_H__

/**

	@ingroup blowfish
	@defgroup blowfish_api Blowfish API
	@{

*/ 

#ifdef  __cplusplus
extern "C"
{
#endif

/* Definitions for fixed sized types required by Blowfish, to be redefined where necessary. */ 

typedef unsigned char BLOWFISH_UCHAR;				/*!< Must be an 8-bit unsigned type. */ 
typedef BLOWFISH_UCHAR * BLOWFISH_PUCHAR;			/*!< Must be a pointer to an 8-bit unsigned type. */ 
typedef const BLOWFISH_UCHAR * BLOWFISH_PCUCHAR;	/*!< Must be a pointer to a constant 8-bit unsigned type */ 

typedef unsigned int BLOWFISH_ULONG;				/*!< Must be a 32-bit unsigned type. */ 
typedef BLOWFISH_ULONG * BLOWFISH_PULONG;			/*!< Must be a pointer to a 32-bit unsigned type. */ 
typedef const BLOWFISH_ULONG * BLOWFISH_PCULONG;	/*!< Must be a pointer to a constant 32-bit unsigned type. */ 

/* Note! Altering the size and/or signedness of BLOWFISH_SIZE_T will affect the amount of data that can be enciphed/deciphered! */ 

#ifdef _OPENMP

typedef signed long BLOWFISH_SIZE_T;				/*!< Must be a signed 32 or 64-bit type for use with OpenMP. */ 

#else

typedef unsigned long BLOWFISH_SIZE_T;				/*!< Must be an unsigned 32 or 64-bit type. */ 

#endif

/** Blowfish block cipher modes. */ 

typedef enum _BLOWFISH_MODE
{
	BLOWFISH_MODE_CURRENT = 0,						/*!< For use only with #BLOWFISH_Reset to re-use the mode that the context record was initialised with. */ 
	BLOWFISH_MODE_ECB,								/*!< Electronic codebook mode. Encipher/Decipher data in 8-byte blocks. This mode is weak at masking repeating patterns, and therefore insecure, but can be parallelised. */ 
	BLOWFISH_MODE_CBC,								/*!< Cipher block chaining mode (recommended). XOR plaintext block with previous cipher text block before encrypting. This mode cannot be parallelised for encryption. */ 
	BLOWFISH_MODE_CFB,								/*!< Cipher feedback mode. Plaintext is XOR encrypted with previous block of ciphertext. This mode cannot be parallelised for encryption. */ 
	BLOWFISH_MODE_OFB,								/*!< Ouput feedback mode. Plaintext is XOR encrypted with enciphered initialisation vector. This mode cannot be parallelised. */ 
	BLOWFISH_MODE_CTR								/*!< Counter mode. Plaintext is XOR encrypted with enciphered initialisation vector added with a counter. This mode can be parallelised for encryption/decryption. */ 

} BLOWFISH_MODE;

/** Blowfish return codes. */ 

typedef enum _BLOWFISH_RC
{
	BLOWFISH_RC_SUCCESS = 0,						/*!< Function completed successfully. */ 
	BLOWFISH_RC_INVALID_PARAMETER,					/*!< One of the parameters suppied to the function is invalid (null pointer). */ 
	BLOWFISH_RC_INVALID_KEY,						/*!< The length of the key supplied to the #BLOWFISH_Init/#BLOWFISH_Reset function is either greater than #BLOWFISH_MAX_KEY_LENGTH or less than #BLOWFISH_MIN_KEY_LENGTH. */ 
	BLOWFISH_RC_WEAK_KEY,							/*!< The key supplied to the #BLOWFISH_Init/#BLOWFISH_Reset function has been deemed to be weak, and should not be used. */ 
	BLOWFISH_RC_BAD_BUFFER_LENGTH,					/*!< The size of the buffer supplied to one of the encipher/decipher buffer/stream functions is not a multiple of 8. */ 
	BLOWFISH_RC_INVALID_MODE,						/*!< The mode specified to the #BLOWFISH_Init/#BLOWFISH_Reset function is not supported. */ 
	BLOWFISH_RC_TEST_FAILED,						/*!< Self test failed. For more information see stdout (only used by test applications). */ 
	BLOWFISH_RC_ERROR,								/*!< Generic error (only used by test applications). */ 

} BLOWFISH_RC;

/* Various static array/buffer lengths (do not modify!). */ 

#define BLOWFISH_SUBKEYS				18			/*!< Number of subkeys in the P-Array. */ 
#define BLOWFISH_SBOXES					4			/*!< Number of S-Boxes. */ 
#define BLOWFISH_SBOX_ENTRIES			256			/*!< Number of entries in each S-Box. */ 

#define BLOWFISH_MIN_KEY_LENGTH			4			/*!< Maximum length of a key (4-bytes, or 32-bits). */ 
#define BLOWFISH_MAX_KEY_LENGTH			56			/*!< Maximum length of a key (56-bytes, or 448-bits). */ 

/** Blowfish context record. */ 

typedef struct _BLOWFISH_CONTEXT
{
	BLOWFISH_ULONG	PArray [ BLOWFISH_SUBKEYS ];						/*!< Original P-Array which has been XOR'd with the key, and overwritten with output from #BLOWFISH_Encipher. */ 
	BLOWFISH_ULONG	SBox [ BLOWFISH_SBOXES ] [ BLOWFISH_SBOX_ENTRIES ];	/*!< Original S-Boxes which have been overwritten with output from #BLOWFISH_Encipher. */ 
	BLOWFISH_ULONG	OriginalIvHigh32;									/*!< Original high 32-bytes of the initialisation vector. */ 
	BLOWFISH_ULONG	OriginalIvLow32;									/*!< Original low 32-bytes of the initialisation vector. */ 
	BLOWFISH_ULONG	IvHigh32;											/*!< Current high 32-bytes of the initialisation vector (used for stream operations). */ 
	BLOWFISH_ULONG	IvLow32;											/*!< Current low 32-bytes of the initialisation vector (used for stream operations). */ 
	void			( *EncipherStream ) ( );							/*!< Pointer to a callback function to perform the encipher based on the block cipher mode */ 
	void			( *DecipherStream ) ( );							/*!< Pointer to a callback function to perform the decipher based on the block cipher mode */ 
 
} BLOWFISH_CONTEXT, *BLOWFISH_PCONTEXT;

/* Function prototypes. */ 

/**

	Initialise a Blowfish context record.

	@param Context		Pointer to a Blowfish context record to initialise.

	@param Key			Pointer to a key to use for enciphering/deciphering data.

	@param KeyLength	Length of the key, which cannot exceed #BLOWFISH_MAX_KEY_LENGTH bytes (sizeof(#BLOWFISH_CONTEXT::PArray)), or be less than #BLOWFISH_MIN_KEY_LENGTH bytes.

	@param Mode			Mode to use when enciphering/decipering blocks. For supported modes see #BLOWFISH_MODE

	@param IvHigh32		High 32-bits of the initialisation vector. Required if the Mode parameter is not #BLOWFISH_MODE_ECB.

	@param IvLow32		Low 32-bits of the initialisation vector. Required if the Mode parameter is not #BLOWFISH_MODE_ECB.

	@remarks For stream based enciphering/deciphering, call #BLOWFISH_BeginStream/#BLOWFISH_EndStream before/afer processing the stream.

	@remarks Operations performed on a blowfish context record are not thread safe. Use #BLOWFISH_CloneContext to create a copy of a context record that can be safely used by another thread.

	@return #BLOWFISH_RC_SUCCESS			Initialised context record successfully.

	@return #BLOWFISH_RC_INVALID_PARAMETER	Either the context record or key pointer is null.

	@return #BLOWFISH_RC_INVALID_KEY		The key is either too short or too long.

	@return #BLOWFISH_RC_WEAK_KEY			The key has been deemed to be weak.

	@return #BLOWFISH_RC_INVALID_MODE		The specified mode is not supported.

  */ 

BLOWFISH_RC BLOWFISH_Init ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR Key, BLOWFISH_SIZE_T KeyLength, BLOWFISH_MODE Mode, BLOWFISH_ULONG IvHigh32, BLOWFISH_ULONG IvLow32 );

/**

	Reinitialise either the key and/or mode and initialisation vector in a Blowfish context record.

	@param Context		Pointer to an initialised Blowfish context record to reinitialise.

	@param Key			Pointer to a new key to use for enciphering/deciphering data. (May be null to re-use the current key).

	@param KeyLength	Length of the new key, which cannot exceed #BLOWFISH_MAX_KEY_LENGTH bytes (sizeof(#BLOWFISH_CONTEXT::PArray)), or be less than #BLOWFISH_MIN_KEY_LENGTH bytes. (May be 0 if Key is null).

	@param Mode			New mode to use when enciphering/decipering blocks. Use #BLOWFISH_MODE_CURRENT to re-use the current mode and initialisation vector. For supported modes see #BLOWFISH_MODE.

	@param IvHigh32		High 32-bits of the new initialisation vector. Required if the Mode parameter is not #BLOWFISH_MODE_ECB or #BLOWFISH_MODE_CURRENT.

	@param IvLow32		Low 32-bits of the new initialisation vector. Required if the Mode parameter is not #BLOWFISH_MODE_ECB or #BLOWFISH_MODE_CURRENT.

	@remarks See #BLOWFISH_Init remarks.

	@return #BLOWFISH_RC_SUCCESS			Reinitialised the context record successfully.

	@return #BLOWFISH_RC_INVALID_PARAMETER	The context record pointer is null.

	@return #BLOWFISH_RC_INVALID_KEY		The key is either too short or too long.

	@return #BLOWFISH_RC_WEAK_KEY			The key has been deemed to be weak.

	@return #BLOWFISH_RC_INVALID_MODE		The specified mode is not supported.

  */ 

BLOWFISH_RC BLOWFISH_Reset ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR Key, BLOWFISH_SIZE_T KeyLength, BLOWFISH_MODE Mode, BLOWFISH_ULONG IvHigh32, BLOWFISH_ULONG IvLow32 );

/**

	Copy an initialised context record into an uninitialised context record for use in another thread.

	@param InContext	Pointer to an initialised context record.

	@param OutContext	Pointer to an uninitialised context record.

	@remarks Destroy the cloned context record using #BLOWFISH_Exit.

	@return BLOWFISH_RC_SUCCESS				The context record was cloned successfully.

	@return BLOWFISH_RC_INVALID_PARAMETER	One of the context record pointers is null.

  */ 

BLOWFISH_RC BLOWFISH_CloneContext ( BLOWFISH_PCONTEXT InContext, BLOWFISH_PCONTEXT OutContext );

/**

	Clear a blowfish context record.

	@param Context	Pointer to an initialised context record to overwrite.

	@remarks Call this function regardless of whether #BLOWFISH_Init succeeds.

	@remarks It is a security risk to not call this function once you have finished enciphering/deciphering data!

	@remarks The context record may not be used again after this call without first calling #BLOWFISH_Init.

	@return #BLOWFISH_RC_SUCCESS			The context record was overwritten successfully.

	@return #BLOWFISH_RC_INVALID_PARAMETER	The supplied context record pointer is null.

  */ 

BLOWFISH_RC BLOWFISH_Exit ( BLOWFISH_PCONTEXT Context );

/**

	Initialise a context record for stream based enciphering/deciphering.

	@param Context	Pointer to an initialised context record.

	@remarks Before re-using the context record to process another stream, be sure to end and begin a new stream using #BLOWFISH_EndStream and BLOWFISH_BeginStream.

	@remarks After calling BLOWFISH_BeginStream, the context will become corrupt if it is passed to any function other than #BLOWFISH_EncipherStream/#BLOWFISH_DecipherStream before calling #BLOWFISH_EndStream.

	@return #BLOWFISH_RC_SUCCESS			The context record was initialised for stream ciphering successfully.

	@return #BLOWFISH_RC_INVALID_PARAMETER	The supplied context record pointer is null.

  */ 

BLOWFISH_RC BLOWFISH_BeginStream ( BLOWFISH_PCONTEXT Context );

/**

	Clear sensitive data from a context record after performing stream based enciphering/deciphering.

	@param Context	Pointer to an initialised context record.

	@remarks The context record may be re-used after this call without needing to call #BLOWFISH_Init again.

	@remarks After calling BLOWFISH_EndStream, the context record may be used in non-stream based functions without risking corruption. (See #BLOWFISH_BeginStream remarks)

	@return #BLOWFISH_RC_SUCCESS			Sensitive data was cleared from the context record successfully.

	@return #BLOWFISH_RC_INVALID_PARAMETER	The supplied context record pointer is null.

  */ 

BLOWFISH_RC BLOWFISH_EndStream ( BLOWFISH_PCONTEXT Context );

/**

	Encipher an 8-byte block of data.

	@param Context	Pointer to an initialised context record.

	@param High32	Pointer to the high 32 bits of data to encipher.

	@param Low32	Pointer to the low 32 bits of data to encipher.

	@remarks It is an unchecked runtime error to supply a null parameter to this function.

  */ 

void BLOWFISH_Encipher ( BLOWFISH_PCONTEXT Context, BLOWFISH_PULONG High32, BLOWFISH_PULONG Low32 );

/**

	Encipher a buffer of data as part of a stream.

	@param Context			Pointer to an initialised context record.

	@param PlainTextStream	Pointer to a buffer of data to encipher within the stream.

	@param CipherTextStream	Pointer to a buffer within the stream to receive the enciphered data.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers. Must be a multiple of 8.

	@remarks The PlainTextStream and CipherTextStream pointers may overlap if the mode used to initialise the context was either #BLOWFISH_MODE_ECB or #BLOWFISH_MODE_CTR.

	@remarks The PlainTextStream and CipherTextStream pointers must point to an offset within the stream that is a multiple of 8.

	@return #BLOWFISH_RC_SUCCESS			Successfully enciphered data.

	@return #BLOWFISH_RC_INVALID_PARAMETER	Either the context record or one of the stream buffer pointer is null.

	@return #BLOWFISH_RC_BAD_BUFFER_LENGTH	The size of the stream buffer is not a multiple of 8.

  */ 

BLOWFISH_RC BLOWFISH_EncipherStream ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR PlainTextStream, BLOWFISH_PUCHAR CipherTextStream, BLOWFISH_SIZE_T StreamLength );

/**

	Encipher a buffer of data.

	@param Context			Pointer to an initialised context record.

	@param PlainTextBuffer	Pointer to a buffer of data to encipher.

	@param CipherTextBuffer	Pointer to a buffer to receive the enciphered data.

	@param BufferLength		Length of the plaintext and ciphertext buffers. Must be a multiple of 8.

	@remarks The PlainTextBuffer and CipherTextBuffer pointers may overlap if the mode used to initialise the context was either #BLOWFISH_MODE_ECB or #BLOWFISH_MODE_CTR.

	@return #BLOWFISH_RC_SUCCESS			Successfully enciphered data.

	@return #BLOWFISH_RC_INVALID_PARAMETER	Either the context record or one of the buffer pointer is null.

	@return #BLOWFISH_RC_BAD_BUFFER_LENGTH	The size of the buffer is not a multiple of 8.

  */ 

BLOWFISH_RC BLOWFISH_EncipherBuffer ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR PlainTextBuffer, BLOWFISH_PUCHAR CipherTextBuffer, BLOWFISH_SIZE_T BufferLength );

/**

	Decipher an 8-byte block of data.

	@param Context	Pointer to an initialised context record.

	@param High32	Pointer to the high 32 bits of data to decipher.

	@param Low32	Pointer to the low 32 bits of data to decipher.

	@remarks It is an unchecked runtime error to supply a null parameter to this function.

  */ 

void BLOWFISH_Decipher ( BLOWFISH_PCONTEXT Context, BLOWFISH_PULONG High32, BLOWFISH_PULONG Low32 );

/**

	Decipher a buffer of data as part of a stream.

	@param Context			Pointer to an initialised context record.

	@param CipherTextStream	Pointer to a buffer of data to decipher within the stream.

	@param PlainTextStream	Pointer to a buffer within the stream to receive the deciphered data.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers. Must be a multiple of 8.

	@remarks The PlainTextStream and CipherTextStream pointers may overlap if the mode used to initialise the context was either #BLOWFISH_MODE_ECB or #BLOWFISH_MODE_CTR.

	@remarks The PlainTextStream and CipherTextStream pointers must point to an offset within the stream that is a multiple of 8.

	@return #BLOWFISH_RC_SUCCESS			Successfully enciphered data.

	@return #BLOWFISH_RC_INVALID_PARAMETER	Either the context record or one of the stream buffer pointer is null.

	@return #BLOWFISH_RC_BAD_BUFFER_LENGTH	The size of the stream buffer is not a multiple of 8.

  */ 

BLOWFISH_RC BLOWFISH_DecipherStream ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR CipherTextStream, BLOWFISH_PUCHAR PlainTextStream, BLOWFISH_SIZE_T StreamLength );

/**

	Decipher a buffer of data.

	@param Context			Pointer to an initialised context record.

	@param CipherTextBuffer	Pointer to a buffer of data to decipher.

	@param PlainTextBuffer	Pointer to a buffer to receive the deciphered data.

	@param BufferLength		Length of the ciphertext and plaintext buffers. Must be a multiple of 8.

	@remarks The PlainTextBuffer and CipherTextBuffer pointers may overlap if the mode used to initialise the context was either #BLOWFISH_MODE_ECB or #BLOWFISH_MODE_CTR.

	@return #BLOWFISH_RC_SUCCESS			Successfully enciphered data.

	@return #BLOWFISH_RC_INVALID_PARAMETER	Either the context record or one of the buffer pointer is null.

	@return #BLOWFISH_RC_BAD_BUFFER_LENGTH	The size of the buffer is not a multiple of 8.

  */ 

BLOWFISH_RC BLOWFISH_DecipherBuffer ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR CipherTextBuffer, BLOWFISH_PUCHAR PlainTextBuffer, BLOWFISH_SIZE_T BufferLength );

#ifdef  __cplusplus
}
#endif

/** @} */ 

#endif /* __BLOWFISH_H__ */ 
