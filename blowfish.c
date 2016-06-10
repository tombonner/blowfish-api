/**

	@file		blowfish.c

	@brief		Portable, optimised implementation of Bruce Schneier's 64-bit
				symmetric block cipher, Blowfish. Includes support for multiple
				block cipher modes, including electronic codebook (ECB), cipher
				block chaining (CBC), cipher feedback (CFB), output feedback 
				(OFB) and counter (CTR), as well as support for weak key 
				detection and parallelisation using OpenMP.

				For more information on the Blowfish block cipher algorithm see 
				http://www.schneier.com/blowfish.html

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

#include <blowfish.h>

/**

	@ingroup blowfish
	@defgroup blowfish_api Blowfish API
	@{ 

	@details	See description for @ref blowfish.c

	@todo		Include support for little-endian systems.

	@todo		Remove restrictions on buffer lengths being a multiple of 8 by either padding input buffers, or truncating enciphered data, depending on the selected block cipher mode.

  */ 

/**

	@internal

	@page glossary Glossary of symbols

	@param Iv	8-byte initialisation vector.

	@param xL	High 4-bytes of block to encipher/decipher.

	@param xR	Low 4-bytes of block to encipher/decipher.

	@param C	8-byte block of ciphertext.

	@param P	PArray or 8-byte block of plaintext.

	@param S	Sbox.

	@param k	Key.

	@param E	Blowfish encipher.

	@param D	Blowfish decipher.

	@param n	Round number.

  */ 

/* Internal function prototypes (Encipher/Decipher stream callbacks) */ 

static void _BLOWFISH_EncipherStream_ECB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG PlainTextStream, BLOWFISH_PULONG CipherTextStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_DecipherStream_ECB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG CipherTextStream, BLOWFISH_PULONG PlainTextStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_EncipherStream_CBC ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG PlainTextStream, BLOWFISH_PULONG CipherTextStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_DecipherStream_CBC ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG CipherTextStream, BLOWFISH_PULONG PlainTextStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_EncipherStream_CFB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG PlainTextStream, BLOWFISH_PULONG CipherTextStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_DecipherStream_CFB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG CipherTextStream, BLOWFISH_PULONG PlainTextStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_EncipherDecipherStream_OFB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG InStream, BLOWFISH_PULONG OutStream, BLOWFISH_SIZE_T StreamLength );
static void _BLOWFISH_EncipherDecipherStream_CTR ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG InStream, BLOWFISH_PULONG OutStream, BLOWFISH_SIZE_T StreamLength );

/** @internal Original S-Boxes (hexdigits of pi). */ 

static const BLOWFISH_ULONG _BLOWFISH_SBox [ BLOWFISH_SBOXES ] [ BLOWFISH_SBOX_ENTRIES ] =
{
	{
		0xd1310ba6l, 0x98dfb5acl, 0x2ffd72dbl, 0xd01adfb7l,
		0xb8e1afedl, 0x6a267e96l, 0xba7c9045l, 0xf12c7f99l,
		0x24a19947l, 0xb3916cf7l, 0x0801f2e2l, 0x858efc16l,
		0x636920d8l, 0x71574e69l, 0xa458fea3l, 0xf4933d7el,
		0x0d95748fl, 0x728eb658l, 0x718bcd58l, 0x82154aeel,
		0x7b54a41dl, 0xc25a59b5l, 0x9c30d539l, 0x2af26013l,
		0xc5d1b023l, 0x286085f0l, 0xca417918l, 0xb8db38efl,
		0x8e79dcb0l, 0x603a180el, 0x6c9e0e8bl, 0xb01e8a3el,
		0xd71577c1l, 0xbd314b27l, 0x78af2fdal, 0x55605c60l,
		0xe65525f3l, 0xaa55ab94l, 0x57489862l, 0x63e81440l,
		0x55ca396al, 0x2aab10b6l, 0xb4cc5c34l, 0x1141e8cel,
		0xa15486afl, 0x7c72e993l, 0xb3ee1411l, 0x636fbc2al,
		0x2ba9c55dl, 0x741831f6l, 0xce5c3e16l, 0x9b87931el,
		0xafd6ba33l, 0x6c24cf5cl, 0x7a325381l, 0x28958677l,
		0x3b8f4898l, 0x6b4bb9afl, 0xc4bfe81bl, 0x66282193l,
		0x61d809ccl, 0xfb21a991l, 0x487cac60l, 0x5dec8032l,
		0xef845d5dl, 0xe98575b1l, 0xdc262302l, 0xeb651b88l,
		0x23893e81l, 0xd396acc5l, 0x0f6d6ff3l, 0x83f44239l,
		0x2e0b4482l, 0xa4842004l, 0x69c8f04al, 0x9e1f9b5el,
		0x21c66842l, 0xf6e96c9al, 0x670c9c61l, 0xabd388f0l,
		0x6a51a0d2l, 0xd8542f68l, 0x960fa728l, 0xab5133a3l,
		0x6eef0b6cl, 0x137a3be4l, 0xba3bf050l, 0x7efb2a98l,
		0xa1f1651dl, 0x39af0176l, 0x66ca593el, 0x82430e88l,
		0x8cee8619l, 0x456f9fb4l, 0x7d84a5c3l, 0x3b8b5ebel,
		0xe06f75d8l, 0x85c12073l, 0x401a449fl, 0x56c16aa6l,
		0x4ed3aa62l, 0x363f7706l, 0x1bfedf72l, 0x429b023dl,
		0x37d0d724l, 0xd00a1248l, 0xdb0fead3l, 0x49f1c09bl,
		0x075372c9l, 0x80991b7bl, 0x25d479d8l, 0xf6e8def7l,
		0xe3fe501al, 0xb6794c3bl, 0x976ce0bdl, 0x04c006bal,
		0xc1a94fb6l, 0x409f60c4l, 0x5e5c9ec2l, 0x196a2463l,
		0x68fb6fafl, 0x3e6c53b5l, 0x1339b2ebl, 0x3b52ec6fl,
		0x6dfc511fl, 0x9b30952cl, 0xcc814544l, 0xaf5ebd09l,
		0xbee3d004l, 0xde334afdl, 0x660f2807l, 0x192e4bb3l,
		0xc0cba857l, 0x45c8740fl, 0xd20b5f39l, 0xb9d3fbdbl,
		0x5579c0bdl, 0x1a60320al, 0xd6a100c6l, 0x402c7279l,
		0x679f25fel, 0xfb1fa3ccl, 0x8ea5e9f8l, 0xdb3222f8l,
		0x3c7516dfl, 0xfd616b15l, 0x2f501ec8l, 0xad0552abl,
		0x323db5fal, 0xfd238760l, 0x53317b48l, 0x3e00df82l,
		0x9e5c57bbl, 0xca6f8ca0l, 0x1a87562el, 0xdf1769dbl,
		0xd542a8f6l, 0x287effc3l, 0xac6732c6l, 0x8c4f5573l,
		0x695b27b0l, 0xbbca58c8l, 0xe1ffa35dl, 0xb8f011a0l,
		0x10fa3d98l, 0xfd2183b8l, 0x4afcb56cl, 0x2dd1d35bl,
		0x9a53e479l, 0xb6f84565l, 0xd28e49bcl, 0x4bfb9790l,
		0xe1ddf2dal, 0xa4cb7e33l, 0x62fb1341l, 0xcee4c6e8l,
		0xef20cadal, 0x36774c01l, 0xd07e9efel, 0x2bf11fb4l,
		0x95dbda4dl, 0xae909198l, 0xeaad8e71l, 0x6b93d5a0l,
		0xd08ed1d0l, 0xafc725e0l, 0x8e3c5b2fl, 0x8e7594b7l,
		0x8ff6e2fbl, 0xf2122b64l, 0x8888b812l, 0x900df01cl,
		0x4fad5ea0l, 0x688fc31cl, 0xd1cff191l, 0xb3a8c1adl,
		0x2f2f2218l, 0xbe0e1777l, 0xea752dfel, 0x8b021fa1l,
		0xe5a0cc0fl, 0xb56f74e8l, 0x18acf3d6l, 0xce89e299l,
		0xb4a84fe0l, 0xfd13e0b7l, 0x7cc43b81l, 0xd2ada8d9l,
		0x165fa266l, 0x80957705l, 0x93cc7314l, 0x211a1477l,
		0xe6ad2065l, 0x77b5fa86l, 0xc75442f5l, 0xfb9d35cfl,
		0xebcdaf0cl, 0x7b3e89a0l, 0xd6411bd3l, 0xae1e7e49l,
		0x00250e2dl, 0x2071b35el, 0x226800bbl, 0x57b8e0afl,
		0x2464369bl, 0xf009b91el, 0x5563911dl, 0x59dfa6aal,
		0x78c14389l, 0xd95a537fl, 0x207d5ba2l, 0x02e5b9c5l,
		0x83260376l, 0x6295cfa9l, 0x11c81968l, 0x4e734a41l,
		0xb3472dcal, 0x7b14a94al, 0x1b510052l, 0x9a532915l,
		0xd60f573fl, 0xbc9bc6e4l, 0x2b60a476l, 0x81e67400l,
		0x08ba6fb5l, 0x571be91fl, 0xf296ec6bl, 0x2a0dd915l,
		0xb6636521l, 0xe7b9f9b6l, 0xff34052el, 0xc5855664l,
		0x53b02d5dl, 0xa99f8fa1l, 0x08ba4799l, 0x6e85076al
	},
	{
		0x4b7a70e9l, 0xb5b32944l, 0xdb75092el, 0xc4192623l,
		0xad6ea6b0l, 0x49a7df7dl, 0x9cee60b8l, 0x8fedb266l,
		0xecaa8c71l, 0x699a17ffl, 0x5664526cl, 0xc2b19ee1l,
		0x193602a5l, 0x75094c29l, 0xa0591340l, 0xe4183a3el,
		0x3f54989al, 0x5b429d65l, 0x6b8fe4d6l, 0x99f73fd6l,
		0xa1d29c07l, 0xefe830f5l, 0x4d2d38e6l, 0xf0255dc1l,
		0x4cdd2086l, 0x8470eb26l, 0x6382e9c6l, 0x021ecc5el,
		0x09686b3fl, 0x3ebaefc9l, 0x3c971814l, 0x6b6a70a1l,
		0x687f3584l, 0x52a0e286l, 0xb79c5305l, 0xaa500737l,
		0x3e07841cl, 0x7fdeae5cl, 0x8e7d44ecl, 0x5716f2b8l,
		0xb03ada37l, 0xf0500c0dl, 0xf01c1f04l, 0x0200b3ffl,
		0xae0cf51al, 0x3cb574b2l, 0x25837a58l, 0xdc0921bdl,
		0xd19113f9l, 0x7ca92ff6l, 0x94324773l, 0x22f54701l,
		0x3ae5e581l, 0x37c2dadcl, 0xc8b57634l, 0x9af3dda7l,
		0xa9446146l, 0x0fd0030el, 0xecc8c73el, 0xa4751e41l,
		0xe238cd99l, 0x3bea0e2fl, 0x3280bba1l, 0x183eb331l,
		0x4e548b38l, 0x4f6db908l, 0x6f420d03l, 0xf60a04bfl,
		0x2cb81290l, 0x24977c79l, 0x5679b072l, 0xbcaf89afl,
		0xde9a771fl, 0xd9930810l, 0xb38bae12l, 0xdccf3f2el,
		0x5512721fl, 0x2e6b7124l, 0x501adde6l, 0x9f84cd87l,
		0x7a584718l, 0x7408da17l, 0xbc9f9abcl, 0xe94b7d8cl,
		0xec7aec3al, 0xdb851dfal, 0x63094366l, 0xc464c3d2l,
		0xef1c1847l, 0x3215d908l, 0xdd433b37l, 0x24c2ba16l,
		0x12a14d43l, 0x2a65c451l, 0x50940002l, 0x133ae4ddl,
		0x71dff89el, 0x10314e55l, 0x81ac77d6l, 0x5f11199bl,
		0x043556f1l, 0xd7a3c76bl, 0x3c11183bl, 0x5924a509l,
		0xf28fe6edl, 0x97f1fbfal, 0x9ebabf2cl, 0x1e153c6el,
		0x86e34570l, 0xeae96fb1l, 0x860e5e0al, 0x5a3e2ab3l,
		0x771fe71cl, 0x4e3d06fal, 0x2965dcb9l, 0x99e71d0fl,
		0x803e89d6l, 0x5266c825l, 0x2e4cc978l, 0x9c10b36al,
		0xc6150ebal, 0x94e2ea78l, 0xa5fc3c53l, 0x1e0a2df4l,
		0xf2f74ea7l, 0x361d2b3dl, 0x1939260fl, 0x19c27960l,
		0x5223a708l, 0xf71312b6l, 0xebadfe6el, 0xeac31f66l,
		0xe3bc4595l, 0xa67bc883l, 0xb17f37d1l, 0x018cff28l,
		0xc332ddefl, 0xbe6c5aa5l, 0x65582185l, 0x68ab9802l,
		0xeecea50fl, 0xdb2f953bl, 0x2aef7dadl, 0x5b6e2f84l,
		0x1521b628l, 0x29076170l, 0xecdd4775l, 0x619f1510l,
		0x13cca830l, 0xeb61bd96l, 0x0334fe1el, 0xaa0363cfl,
		0xb5735c90l, 0x4c70a239l, 0xd59e9e0bl, 0xcbaade14l,
		0xeecc86bcl, 0x60622ca7l, 0x9cab5cabl, 0xb2f3846el,
		0x648b1eafl, 0x19bdf0cal, 0xa02369b9l, 0x655abb50l,
		0x40685a32l, 0x3c2ab4b3l, 0x319ee9d5l, 0xc021b8f7l,
		0x9b540b19l, 0x875fa099l, 0x95f7997el, 0x623d7da8l,
		0xf837889al, 0x97e32d77l, 0x11ed935fl, 0x16681281l,
		0x0e358829l, 0xc7e61fd6l, 0x96dedfa1l, 0x7858ba99l,
		0x57f584a5l, 0x1b227263l, 0x9b83c3ffl, 0x1ac24696l,
		0xcdb30aebl, 0x532e3054l, 0x8fd948e4l, 0x6dbc3128l,
		0x58ebf2efl, 0x34c6ffeal, 0xfe28ed61l, 0xee7c3c73l,
		0x5d4a14d9l, 0xe864b7e3l, 0x42105d14l, 0x203e13e0l,
		0x45eee2b6l, 0xa3aaabeal, 0xdb6c4f15l, 0xfacb4fd0l,
		0xc742f442l, 0xef6abbb5l, 0x654f3b1dl, 0x41cd2105l,
		0xd81e799el, 0x86854dc7l, 0xe44b476al, 0x3d816250l,
		0xcf62a1f2l, 0x5b8d2646l, 0xfc8883a0l, 0xc1c7b6a3l,
		0x7f1524c3l, 0x69cb7492l, 0x47848a0bl, 0x5692b285l,
		0x095bbf00l, 0xad19489dl, 0x1462b174l, 0x23820e00l,
		0x58428d2al, 0x0c55f5eal, 0x1dadf43el, 0x233f7061l,
		0x3372f092l, 0x8d937e41l, 0xd65fecf1l, 0x6c223bdbl,
		0x7cde3759l, 0xcbee7460l, 0x4085f2a7l, 0xce77326el,
		0xa6078084l, 0x19f8509el, 0xe8efd855l, 0x61d99735l,
		0xa969a7aal, 0xc50c06c2l, 0x5a04abfcl, 0x800bcadcl,
		0x9e447a2el, 0xc3453484l, 0xfdd56705l, 0x0e1e9ec9l,
		0xdb73dbd3l, 0x105588cdl, 0x675fda79l, 0xe3674340l,
		0xc5c43465l, 0x713e38d8l, 0x3d28f89el, 0xf16dff20l,
		0x153e21e7l, 0x8fb03d4al, 0xe6e39f2bl, 0xdb83adf7l
	},
	{
		0xe93d5a68l, 0x948140f7l, 0xf64c261cl, 0x94692934l,
		0x411520f7l, 0x7602d4f7l, 0xbcf46b2el, 0xd4a20068l,
		0xd4082471l, 0x3320f46al, 0x43b7d4b7l, 0x500061afl,
		0x1e39f62el, 0x97244546l, 0x14214f74l, 0xbf8b8840l,
		0x4d95fc1dl, 0x96b591afl, 0x70f4ddd3l, 0x66a02f45l,
		0xbfbc09ecl, 0x03bd9785l, 0x7fac6dd0l, 0x31cb8504l,
		0x96eb27b3l, 0x55fd3941l, 0xda2547e6l, 0xabca0a9al,
		0x28507825l, 0x530429f4l, 0x0a2c86dal, 0xe9b66dfbl,
		0x68dc1462l, 0xd7486900l, 0x680ec0a4l, 0x27a18deel,
		0x4f3ffea2l, 0xe887ad8cl, 0xb58ce006l, 0x7af4d6b6l,
		0xaace1e7cl, 0xd3375fecl, 0xce78a399l, 0x406b2a42l,
		0x20fe9e35l, 0xd9f385b9l, 0xee39d7abl, 0x3b124e8bl,
		0x1dc9faf7l, 0x4b6d1856l, 0x26a36631l, 0xeae397b2l,
		0x3a6efa74l, 0xdd5b4332l, 0x6841e7f7l, 0xca7820fbl,
		0xfb0af54el, 0xd8feb397l, 0x454056acl, 0xba489527l,
		0x55533a3al, 0x20838d87l, 0xfe6ba9b7l, 0xd096954bl,
		0x55a867bcl, 0xa1159a58l, 0xcca92963l, 0x99e1db33l,
		0xa62a4a56l, 0x3f3125f9l, 0x5ef47e1cl, 0x9029317cl,
		0xfdf8e802l, 0x04272f70l, 0x80bb155cl, 0x05282ce3l,
		0x95c11548l, 0xe4c66d22l, 0x48c1133fl, 0xc70f86dcl,
		0x07f9c9eel, 0x41041f0fl, 0x404779a4l, 0x5d886e17l,
		0x325f51ebl, 0xd59bc0d1l, 0xf2bcc18fl, 0x41113564l,
		0x257b7834l, 0x602a9c60l, 0xdff8e8a3l, 0x1f636c1bl,
		0x0e12b4c2l, 0x02e1329el, 0xaf664fd1l, 0xcad18115l,
		0x6b2395e0l, 0x333e92e1l, 0x3b240b62l, 0xeebeb922l,
		0x85b2a20el, 0xe6ba0d99l, 0xde720c8cl, 0x2da2f728l,
		0xd0127845l, 0x95b794fdl, 0x647d0862l, 0xe7ccf5f0l,
		0x5449a36fl, 0x877d48fal, 0xc39dfd27l, 0xf33e8d1el,
		0x0a476341l, 0x992eff74l, 0x3a6f6eabl, 0xf4f8fd37l,
		0xa812dc60l, 0xa1ebddf8l, 0x991be14cl, 0xdb6e6b0dl,
		0xc67b5510l, 0x6d672c37l, 0x2765d43bl, 0xdcd0e804l,
		0xf1290dc7l, 0xcc00ffa3l, 0xb5390f92l, 0x690fed0bl,
		0x667b9ffbl, 0xcedb7d9cl, 0xa091cf0bl, 0xd9155ea3l,
		0xbb132f88l, 0x515bad24l, 0x7b9479bfl, 0x763bd6ebl,
		0x37392eb3l, 0xcc115979l, 0x8026e297l, 0xf42e312dl,
		0x6842ada7l, 0xc66a2b3bl, 0x12754cccl, 0x782ef11cl,
		0x6a124237l, 0xb79251e7l, 0x06a1bbe6l, 0x4bfb6350l,
		0x1a6b1018l, 0x11caedfal, 0x3d25bdd8l, 0xe2e1c3c9l,
		0x44421659l, 0x0a121386l, 0xd90cec6el, 0xd5abea2al,
		0x64af674el, 0xda86a85fl, 0xbebfe988l, 0x64e4c3fel,
		0x9dbc8057l, 0xf0f7c086l, 0x60787bf8l, 0x6003604dl,
		0xd1fd8346l, 0xf6381fb0l, 0x7745ae04l, 0xd736fcccl,
		0x83426b33l, 0xf01eab71l, 0xb0804187l, 0x3c005e5fl,
		0x77a057bel, 0xbde8ae24l, 0x55464299l, 0xbf582e61l,
		0x4e58f48fl, 0xf2ddfda2l, 0xf474ef38l, 0x8789bdc2l,
		0x5366f9c3l, 0xc8b38e74l, 0xb475f255l, 0x46fcd9b9l,
		0x7aeb2661l, 0x8b1ddf84l, 0x846a0e79l, 0x915f95e2l,
		0x466e598el, 0x20b45770l, 0x8cd55591l, 0xc902de4cl,
		0xb90bace1l, 0xbb8205d0l, 0x11a86248l, 0x7574a99el,
		0xb77f19b6l, 0xe0a9dc09l, 0x662d09a1l, 0xc4324633l,
		0xe85a1f02l, 0x09f0be8cl, 0x4a99a025l, 0x1d6efe10l,
		0x1ab93d1dl, 0x0ba5a4dfl, 0xa186f20fl, 0x2868f169l,
		0xdcb7da83l, 0x573906fel, 0xa1e2ce9bl, 0x4fcd7f52l,
		0x50115e01l, 0xa70683fal, 0xa002b5c4l, 0x0de6d027l,
		0x9af88c27l, 0x773f8641l, 0xc3604c06l, 0x61a806b5l,
		0xf0177a28l, 0xc0f586e0l, 0x006058aal, 0x30dc7d62l,
		0x11e69ed7l, 0x2338ea63l, 0x53c2dd94l, 0xc2c21634l,
		0xbbcbee56l, 0x90bcb6del, 0xebfc7da1l, 0xce591d76l,
		0x6f05e409l, 0x4b7c0188l, 0x39720a3dl, 0x7c927c24l,
		0x86e3725fl, 0x724d9db9l, 0x1ac15bb4l, 0xd39eb8fcl,
		0xed545578l, 0x08fca5b5l, 0xd83d7cd3l, 0x4dad0fc4l,
		0x1e50ef5el, 0xb161e6f8l, 0xa28514d9l, 0x6c51133cl,
		0x6fd5c7e7l, 0x56e14ec4l, 0x362abfcel, 0xddc6c837l,
		0xd79a3234l, 0x92638212l, 0x670efa8el, 0x406000e0l
	},
	{
		0x3a39ce37l, 0xd3faf5cfl, 0xabc27737l, 0x5ac52d1bl,
		0x5cb0679el, 0x4fa33742l, 0xd3822740l, 0x99bc9bbel,
		0xd5118e9dl, 0xbf0f7315l, 0xd62d1c7el, 0xc700c47bl,
		0xb78c1b6bl, 0x21a19045l, 0xb26eb1bel, 0x6a366eb4l,
		0x5748ab2fl, 0xbc946e79l, 0xc6a376d2l, 0x6549c2c8l,
		0x530ff8eel, 0x468dde7dl, 0xd5730a1dl, 0x4cd04dc6l,
		0x2939bbdbl, 0xa9ba4650l, 0xac9526e8l, 0xbe5ee304l,
		0xa1fad5f0l, 0x6a2d519al, 0x63ef8ce2l, 0x9a86ee22l,
		0xc089c2b8l, 0x43242ef6l, 0xa51e03aal, 0x9cf2d0a4l,
		0x83c061bal, 0x9be96a4dl, 0x8fe51550l, 0xba645bd6l,
		0x2826a2f9l, 0xa73a3ae1l, 0x4ba99586l, 0xef5562e9l,
		0xc72fefd3l, 0xf752f7dal, 0x3f046f69l, 0x77fa0a59l,
		0x80e4a915l, 0x87b08601l, 0x9b09e6adl, 0x3b3ee593l,
		0xe990fd5al, 0x9e34d797l, 0x2cf0b7d9l, 0x022b8b51l,
		0x96d5ac3al, 0x017da67dl, 0xd1cf3ed6l, 0x7c7d2d28l,
		0x1f9f25cfl, 0xadf2b89bl, 0x5ad6b472l, 0x5a88f54cl,
		0xe029ac71l, 0xe019a5e6l, 0x47b0acfdl, 0xed93fa9bl,
		0xe8d3c48dl, 0x283b57ccl, 0xf8d56629l, 0x79132e28l,
		0x785f0191l, 0xed756055l, 0xf7960e44l, 0xe3d35e8cl,
		0x15056dd4l, 0x88f46dbal, 0x03a16125l, 0x0564f0bdl,
		0xc3eb9e15l, 0x3c9057a2l, 0x97271aecl, 0xa93a072al,
		0x1b3f6d9bl, 0x1e6321f5l, 0xf59c66fbl, 0x26dcf319l,
		0x7533d928l, 0xb155fdf5l, 0x03563482l, 0x8aba3cbbl,
		0x28517711l, 0xc20ad9f8l, 0xabcc5167l, 0xccad925fl,
		0x4de81751l, 0x3830dc8el, 0x379d5862l, 0x9320f991l,
		0xea7a90c2l, 0xfb3e7bcel, 0x5121ce64l, 0x774fbe32l,
		0xa8b6e37el, 0xc3293d46l, 0x48de5369l, 0x6413e680l,
		0xa2ae0810l, 0xdd6db224l, 0x69852dfdl, 0x09072166l,
		0xb39a460al, 0x6445c0ddl, 0x586cdecfl, 0x1c20c8ael,
		0x5bbef7ddl, 0x1b588d40l, 0xccd2017fl, 0x6bb4e3bbl,
		0xdda26a7el, 0x3a59ff45l, 0x3e350a44l, 0xbcb4cdd5l,
		0x72eacea8l, 0xfa6484bbl, 0x8d6612ael, 0xbf3c6f47l,
		0xd29be463l, 0x542f5d9el, 0xaec2771bl, 0xf64e6370l,
		0x740e0d8dl, 0xe75b1357l, 0xf8721671l, 0xaf537d5dl,
		0x4040cb08l, 0x4eb4e2ccl, 0x34d2466al, 0x0115af84l,
		0xe1b00428l, 0x95983a1dl, 0x06b89fb4l, 0xce6ea048l,
		0x6f3f3b82l, 0x3520ab82l, 0x011a1d4bl, 0x277227f8l,
		0x611560b1l, 0xe7933fdcl, 0xbb3a792bl, 0x344525bdl,
		0xa08839e1l, 0x51ce794bl, 0x2f32c9b7l, 0xa01fbac9l,
		0xe01cc87el, 0xbcc7d1f6l, 0xcf0111c3l, 0xa1e8aac7l,
		0x1a908749l, 0xd44fbd9al, 0xd0dadecbl, 0xd50ada38l,
		0x0339c32al, 0xc6913667l, 0x8df9317cl, 0xe0b12b4fl,
		0xf79e59b7l, 0x43f5bb3al, 0xf2d519ffl, 0x27d9459cl,
		0xbf97222cl, 0x15e6fc2al, 0x0f91fc71l, 0x9b941525l,
		0xfae59361l, 0xceb69cebl, 0xc2a86459l, 0x12baa8d1l,
		0xb6c1075el, 0xe3056a0cl, 0x10d25065l, 0xcb03a442l,
		0xe0ec6e0el, 0x1698db3bl, 0x4c98a0bel, 0x3278e964l,
		0x9f1f9532l, 0xe0d392dfl, 0xd3a0342bl, 0x8971f21el,
		0x1b0a7441l, 0x4ba3348cl, 0xc5be7120l, 0xc37632d8l,
		0xdf359f8dl, 0x9b992f2el, 0xe60b6f47l, 0x0fe3f11dl,
		0xe54cda54l, 0x1edad891l, 0xce6279cfl, 0xcd3e7e6fl,
		0x1618b166l, 0xfd2c1d05l, 0x848fd2c5l, 0xf6fb2299l,
		0xf523f357l, 0xa6327623l, 0x93a83531l, 0x56cccd02l,
		0xacf08162l, 0x5a75ebb5l, 0x6e163697l, 0x88d273ccl,
		0xde966292l, 0x81b949d0l, 0x4c50901bl, 0x71c65614l,
		0xe6c6c7bdl, 0x327a140al, 0x45e1d006l, 0xc3f27b9al,
		0xc9aa53fdl, 0x62a80f00l, 0xbb25bfe2l, 0x35bdd2f6l,
		0x71126905l, 0xb2040222l, 0xb6cbcf7cl, 0xcd769c2bl,
		0x53113ec0l, 0x1640e3d3l, 0x38abbd60l, 0x2547adf0l,
		0xba38209cl, 0xf746ce76l, 0x77afa1c5l, 0x20756060l,
		0x85cbfe4el, 0x8ae88dd8l, 0x7aaaf9b0l, 0x4cf9aa7el,
		0x1948c25cl, 0x02fb8a8cl, 0x01c36ae4l, 0xd6ebe1f9l,
		0x90d4f869l, 0xa65cdea0l, 0x3f09252dl, 0xc208e69fl,
		0xb74e6132l, 0xce77e25bl, 0x578fdfe3l, 0x3ac372e6l
	}
};

/** @internal Original P-Array (hexdigits of pi) */ 

static const BLOWFISH_ULONG _BLOWFISH_PArray [ BLOWFISH_SUBKEYS ] = 
{
	0x243f6a88l, 0x85a308d3l, 0x13198a2el,
	0x03707344l, 0xa4093822l, 0x299f31d0l,
	0x082efa98l, 0xec4e6c89l, 0x452821e6l,
	0x38d01377l, 0xbe5466cfl, 0x34e90c6cl,
	0xc0ac29b7l, 0xc97c50ddl, 0x3f84d5b5l,
	0xb5470917l, 0x9216d5d9l, 0x8979fb1bl
};

/**

	@internal

	Set the mode and original initialisation vector in a context record.

	@param Context	Pointer to a context record to set the mode and initialisation vector.

	@param Mode		Mode to use when enciphering/decipering blocks. For supported modes see #BLOWFISH_MODE.

	@param IvHigh32	High 32-bits of the initialisation vector. Required if the Mode parameter is not #BLOWFISH_MODE_ECB.

	@param IvLow32	Low 32-bits of the initialisation vector. Required if the Mode parameter is not #BLOWFISH_MODE_ECB.

	@remarks It is an unchecked runtime error to supply a null pointer to this function.

	@return #BLOWFISH_RC_SUCCESS		The mode and original initialisation vector were set successfully.

	@return #BLOWFISH_RC_INVALID_MODE	The mode supplied was invalid.

  */ 

static BLOWFISH_RC _BLOWFISH_SetMode ( BLOWFISH_PCONTEXT Context, BLOWFISH_MODE Mode, BLOWFISH_ULONG IvHigh32, BLOWFISH_ULONG IvLow32 )
{
	/* Validate the block cipher mode, and set pointers to the encipher/decipher stream callbacks */ 

	switch ( Mode )
	{
		case BLOWFISH_MODE_ECB:
		{
			Context->EncipherStream = &_BLOWFISH_EncipherStream_ECB;
			Context->DecipherStream = &_BLOWFISH_DecipherStream_ECB;

			break;
		}
		case BLOWFISH_MODE_CBC:
		{
			Context->EncipherStream = &_BLOWFISH_EncipherStream_CBC;
			Context->DecipherStream = &_BLOWFISH_DecipherStream_CBC;

			break;
		}
		case BLOWFISH_MODE_CFB:
		{
			Context->EncipherStream = &_BLOWFISH_EncipherStream_CFB;
			Context->DecipherStream = &_BLOWFISH_DecipherStream_CFB;

			break;
		}
		case BLOWFISH_MODE_OFB:
		{
			Context->EncipherStream = &_BLOWFISH_EncipherDecipherStream_OFB;
			Context->DecipherStream = &_BLOWFISH_EncipherDecipherStream_OFB;

			break;
		}
		case BLOWFISH_MODE_CTR:
		{
			Context->EncipherStream = &_BLOWFISH_EncipherDecipherStream_CTR;
			Context->DecipherStream = &_BLOWFISH_EncipherDecipherStream_CTR;

			break;
		}
		default:
		{
			return BLOWFISH_RC_INVALID_MODE;
		}
	}

	/* Save the initialisation vector */ 

	Context->OriginalIvHigh32 = IvHigh32;
	Context->OriginalIvLow32 = IvLow32;

	return BLOWFISH_RC_SUCCESS;
}

/**

	@internal

	Initialise the P-Array and S-Boxes in a context record based on the key.

	@param Context		Pointer to a context record to initialise.

	@param Key			Pointer to the key.

	@param KeyLength	Length of the Key buffer.

	@remarks It is an unchecked runtime error to supply a null pointer to this function.

	@return #BLOWFISH_RC_SUCCESS		Successfully initialised the context record.

	@return #BLOWFISH_RC_INVALID_KEY	The length of the key is invalid.

	@return #BLOWFISH_RC_WEAK_KEY		The key has been deemed to be weak.

  */ 

static BLOWFISH_RC _BLOWFISH_SetKey ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR Key, BLOWFISH_SIZE_T KeyLength )
{
	BLOWFISH_SIZE_T	i;
	BLOWFISH_SIZE_T	j;
	BLOWFISH_SIZE_T	k;
	BLOWFISH_ULONG	Data = 0;
	BLOWFISH_ULONG	XLeft = 0;
	BLOWFISH_ULONG	XRight = 0;

	/* Ensure the key length is valid, ( between 4 and 56 bytes ) */ 

	if ( KeyLength < BLOWFISH_MIN_KEY_LENGTH || KeyLength > BLOWFISH_MAX_KEY_LENGTH )
	{
		return BLOWFISH_RC_INVALID_KEY;
	}

	/* Copy the original S-Boxes to the context */ 

	for ( i = 0; i < BLOWFISH_SBOXES; i++ )
	{
		for ( j = 0; j < BLOWFISH_SBOX_ENTRIES; j++ )
		{
			Context->SBox [ i ] [ j ] = _BLOWFISH_SBox [ i ] [ j ];
		}
	}

	/* XOR the original P-Array and key into the context P-Array */ 

	for ( i = 0, j = 0; i < BLOWFISH_SUBKEYS; i++ )
	{
		for ( k = 0; k < 4; k++ )
		{
			Data = ( Data << 8 ) | Key [ j ];

			/* Have we reached the end of the key? */ 

			j++;

			if ( j >= KeyLength )
			{
				/* Resume from the begining of the key */ 

				j = 0;
			}
		}

		Context->PArray [ i ] = _BLOWFISH_PArray [ i ] ^ Data;
	}

	/* Update all entries in the context P-Array with output from the continuously changing blowfish algorithm */ 

	for ( i = 0; i < BLOWFISH_SUBKEYS; i += 2 )
	{
		 BLOWFISH_Encipher ( Context, &XLeft, &XRight );

		 Context->PArray [ i ] = XLeft;
		 Context->PArray [ i + 1 ] = XRight;
	}

	/* Update all entries in the context S-Boxes with output from the continuously changing blowfish algorithm */ 

	for ( i = 0; i < BLOWFISH_SBOXES; i++ )
	{
		for ( j = 0; j < BLOWFISH_SBOX_ENTRIES; j += 2 )
		{
			BLOWFISH_Encipher ( Context, &XLeft, &XRight );

			/* Test the strength of the key */ 

			if ( XLeft == XRight )
			{
				return BLOWFISH_RC_WEAK_KEY;
			}

			Context->SBox [ i ] [ j ] = XLeft;
			Context->SBox [ i ] [ j + 1 ] = XRight;
		}
	}

	return BLOWFISH_RC_SUCCESS;
}

BLOWFISH_RC BLOWFISH_Init ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR Key, BLOWFISH_SIZE_T KeyLength, BLOWFISH_MODE Mode, BLOWFISH_ULONG IvHigh32, BLOWFISH_ULONG IvLow32 )
{
	BLOWFISH_RC	ReturnCode;

	/* Ensure pointers are valid */ 

	if ( Context == 0 || Key == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Set the mode and initialisation vector */ 

	ReturnCode = _BLOWFISH_SetMode ( Context, Mode, IvHigh32, IvLow32 );

	if ( ReturnCode == BLOWFISH_RC_SUCCESS )
	{
		/* Initialise the P-Array and S-Boxes based on the key */ 

		ReturnCode = _BLOWFISH_SetKey ( Context, Key, KeyLength );
	}

	return ReturnCode;
}

BLOWFISH_RC BLOWFISH_Reset ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR Key, BLOWFISH_SIZE_T KeyLength, BLOWFISH_MODE Mode, BLOWFISH_ULONG IvHigh32, BLOWFISH_ULONG IvLow32 )
{
	BLOWFISH_RC	ReturnCode = BLOWFISH_RC_SUCCESS;

	/* Ensure the context pointer is valid */ 

	if ( Context == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Has a new mode been specified */ 

	if ( Mode != BLOWFISH_MODE_CURRENT )
	{
		/* Reinitialise the mode and initialisation vector */ 

		ReturnCode = _BLOWFISH_SetMode ( Context, Mode, IvHigh32, IvLow32 );

		if ( ReturnCode != BLOWFISH_RC_SUCCESS )
		{
			return ReturnCode;
		}
	}

	/* Has a new key been specified? */ 

	if ( Key != 0 )
	{
		/* Reinitialise the P-Array and S-Boxes based on the new key */ 

		ReturnCode = _BLOWFISH_SetKey ( Context, Key, KeyLength );
	}

	return ReturnCode;
}

BLOWFISH_RC BLOWFISH_CloneContext ( BLOWFISH_PCONTEXT InContext, BLOWFISH_PCONTEXT OutContext )
{
	if ( InContext == 0 || OutContext == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Copy the context record */ 

	*OutContext = *InContext;

	return BLOWFISH_RC_SUCCESS;
}

BLOWFISH_RC BLOWFISH_Exit ( BLOWFISH_PCONTEXT Context )
{
	BLOWFISH_PUCHAR	MemoryToWipe = (BLOWFISH_PUCHAR)Context;
	BLOWFISH_SIZE_T	i;

	/* Ensure the context pointer is valid */ 

	if ( Context == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Overwrite the context record with null bytes (do not use memset!) */ 

	for ( i = 0; i < (BLOWFISH_SIZE_T)sizeof ( *Context ); i++ )
	{
		MemoryToWipe [ i ] = 0x00;
	}

	return BLOWFISH_RC_SUCCESS;
}

/**

	@internal

	Restore the original initialisation vector in a context record.

	@param Context	Pointer to an initialised context record.

*/ 

#define _BLOWFISH_BEGINSTREAM( Context )			\
{													\
	Context->IvHigh32 = Context->OriginalIvHigh32;	\
	Context->IvLow32 = Context->OriginalIvLow32;	\
}

BLOWFISH_RC BLOWFISH_BeginStream ( BLOWFISH_PCONTEXT Context )
{
	/* Ensure the context pointer is valid */ 

	if ( Context == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	_BLOWFISH_BEGINSTREAM ( Context );

	return BLOWFISH_RC_SUCCESS;
}

/**

	@internal

	Overwrite the final initialisation vector in a context record.

	@param Context	Pointer to an initialised context record.

*/ 

#define _BLOWFISH_ENDSTREAM( Context )	\
{										\
	Context->IvHigh32 = 0;				\
	Context->IvLow32 = 0;				\
}

BLOWFISH_RC BLOWFISH_EndStream ( BLOWFISH_PCONTEXT Context )
{
	/* Ensure the context pointer is valid */ 

	if ( Context == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	_BLOWFISH_ENDSTREAM ( Context );

	return BLOWFISH_RC_SUCCESS;
}

/**

	@internal

	Perform a single round of the cipher.

	xL = xL XOR Pn

	xR = F(xL) XOR xR

	Divide xL into four eight-bit quarters: a, b, c, and d.

	Then, F(xL) = ((S0,a + S1,b mod 232) XOR S2,c) + S3,d mod 232. 

	See @link glossary @endlink for more information.

	@remarks After each round the caller must swap xL and xR.

	@param XLeft			High 32-bits of the message to encipher.

	@param XRight			Low 32-bits of the message to encipher.

	@param P				Pointer to the P-Array.

	@param S0, S1, S2, S3	Pointers to each element of the S-Box array.

	@param Round			Current round to perform (0-15 to encipher, 17-2 to decipher).

  */ 

#define _BLOWFISH_CIPHER( XLeft, XRight, P, S0, S1, S2, S3, Round )	\
{																	\
	XLeft ^= P [ Round ];											\
	XRight ^= ( ( ( S0 [ XLeft >> 24 ] +							\
		S1 [ ( XLeft >> 16 ) & 0xff ] ) ^							\
		S2 [ ( XLeft >> 8 ) & 0xff ] ) +							\
		S3 [ XLeft & 0xff ] );										\
}

/**

	@internal

	Perform 16-round encipher, finalise round and unswap xL and xR:

	xR = xR XOR P18

	xL = xL XOR P17

	See @link glossary @endlink for more information.

	@param BufferHigh		Pointer to the high 32-bits of the output buffer.

	@param BufferLow		Pointer to the low 32-bits of the output buffer.

	@param XLeft			High 32-bits of the message to encipher.

	@param XRight			Low 32-bits of the message to encipher.

	@param P				Pointer to the P-Array.

	@param S0, S1, S2, S3	Pointers to each element of the S-Box array.

	@remarks If BufferHigh and BufferLow are the same variables as XLeft and XRight then the result will not be swapped!

  */ 

#define _BLOWFISH_ENCIPHER( BufferHigh, BufferLow, XLeft, XRight, P, S0, S1, S2, S3 )	\
{																						\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 0 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 1 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 2 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 3 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 4 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 5 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 6 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 7 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 8 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 9 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 10 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 11 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 12 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 13 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 14 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 15 );							\
	BufferLow = XLeft ^ P [ 16 ];														\
	BufferHigh = XRight ^ P [ 17 ];														\
}

void BLOWFISH_Encipher ( BLOWFISH_PCONTEXT Context, BLOWFISH_PULONG High32, BLOWFISH_PULONG Low32 )
{
	BLOWFISH_ULONG	XLeft = *High32;
	BLOWFISH_ULONG	XRight = *Low32;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];

	/* Encipher 8-byte plaintext block */ 

	_BLOWFISH_ENCIPHER ( *High32, *Low32, XLeft, XRight, P, S0, S1, S2, S3 );

	return;
}

/**

	@internal

	Encipher a stream of data in electronic codebook mode.

	Cn = Ek ( Pn )

	See @link glossary @endlink for more information.

	@param Context			Pointer to an initialised context record.

	@param PlainTextStream	Buffer of plaintext to encipher.

	@param CipherTextStream	Buffer to receive the ciphertext.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

	@remarks This function can be parallelised using OpenMP.

  */ 

static void _BLOWFISH_EncipherStream_ECB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG PlainTextStream, BLOWFISH_PULONG CipherTextStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft;
	BLOWFISH_ULONG	XRight;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	/* Encipher plaintext in 8-byte blocks */ 

#ifdef _OPENMP

	#pragma omp parallel for default ( none ) private ( i, XLeft, XRight ) shared ( PlainTextStream, CipherTextStream, P, S0, S1, S2, S3, StreamLength ) schedule ( static )

#endif

	for ( i = 0; i < StreamLength; i += 2 )
	{
		XLeft = PlainTextStream [ i ];
		XRight = PlainTextStream [ i + 1 ];

		_BLOWFISH_ENCIPHER ( CipherTextStream [ i ], CipherTextStream [ i + 1 ], XLeft, XRight, P, S0, S1, S2, S3 );
	}

	return;
}

/**

	@internal

	Encipher a stream of data in cipher block chaining mode.

	Round 1:

	C0 = Ek ( P0 XOR Iv )

	Round n:

	Cn = Ek ( Pn XOR ( Cn - 1 ) )

	See @link glossary @endlink for more information.

	@param Context			Pointer to an initialised context record.

	@param PlainTextStream	Buffer of plaintext to encipher.

	@param CipherTextStream	Buffer to receive the ciphertext.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

  */ 

static void _BLOWFISH_EncipherStream_CBC ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG PlainTextStream, BLOWFISH_PULONG CipherTextStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft;
	BLOWFISH_ULONG	XRight;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	/* XOR the first block of plaintext with the initialisation vector */ 

	XLeft = PlainTextStream [ 0 ] ^ Context->IvHigh32;
	XRight = PlainTextStream [ 1 ] ^ Context->IvLow32;

	/* Encipher the first block of plaintext */ 

	_BLOWFISH_ENCIPHER ( CipherTextStream [ 0 ], CipherTextStream [ 1 ], XLeft, XRight, P, S0, S1, S2, S3 );

	/* Encrypt any remaining blocks */ 

	for ( i = 2; i < StreamLength; i += 2 )
	{
		/* XOR the block of plaintext with the previous block of ciphertext */ 

		XLeft = PlainTextStream [ i ] ^ CipherTextStream [ i - 2 ];
		XRight = PlainTextStream [ i + 1 ] ^ CipherTextStream [ i - 1 ];

		/* Encipher the block of plaintext  */ 

		_BLOWFISH_ENCIPHER ( CipherTextStream [ i ], CipherTextStream [ i + 1 ], XLeft, XRight, P, S0, S1, S2, S3 );
	}

	/* Preserve the previous block of ciphertext as the new initialisation vector for stream based operations */ 

	Context->IvHigh32 = CipherTextStream [ i - 2 ];
	Context->IvLow32 = CipherTextStream [ i - 1 ];

	return;
}

/**

	@internal

	Encipher a stream of data in cipher feedback mode.

	Round 1:

	C0 = P0 XOR Ek ( Iv )

	Round n:

	Cn = Pn XOR Ek ( ( Cn - 1 ) )

	See @link glossary @endlink for more information.

	@param Context			Pointer to an initialised context record.

	@param PlainTextStream	Buffer of plaintext to encipher.

	@param CipherTextStream	Buffer to receive the ciphertext.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

  */ 

static void _BLOWFISH_EncipherStream_CFB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG PlainTextStream, BLOWFISH_PULONG CipherTextStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft = Context->IvHigh32;
	BLOWFISH_ULONG	XRight = Context->IvLow32;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	/* Encipher the initialisation vector */ 

	_BLOWFISH_ENCIPHER ( XRight, XLeft, XLeft, XRight, P, S0, S1, S2, S3 );

	/* XOR the enciphered initialisation vector with the plaintext to yeild the ciphertext */ 

	XRight ^= PlainTextStream [ 0 ];
	XLeft ^= PlainTextStream [ 1 ];

	CipherTextStream [ 0 ] = XRight;
	CipherTextStream [ 1 ] = XLeft;

	for ( i = 2; i < StreamLength; i += 2 )
	{
		/* Encipher the previous block of ciphertext */ 

		XLeft = CipherTextStream [ i - 2 ];
		XRight = CipherTextStream [ i - 1 ];

		_BLOWFISH_ENCIPHER ( XRight, XLeft, XLeft, XRight, P, S0, S1, S2, S3 );

		/* XOR the enciphered previous block of ciphertext with the plaintext to yeild the current block of ciphertext */ 

		XRight ^= PlainTextStream [ i ];
		XLeft ^= PlainTextStream [ i + 1 ];

		CipherTextStream [ i ] = XRight;
		CipherTextStream [ i + 1 ] = XLeft;
	}

	/* Preserve the previous block of ciphertext as the new initialisation vector for stream based operations */ 

	Context->IvHigh32 = XRight;
	Context->IvLow32 = XLeft;

	return;
}

/**

	@internal

	Encipher/Decipher a stream of data in output feedback mode.

	Iv = Ek ( Iv )

	Cn = Pn XOR Iv

	To decipher simply swap C and P.

	See @link glossary @endlink for more information.

	@param Context		Pointer to an initialised context record.

	@param InStream		Pointer to either a buffer of plaintext to encipher, or a buffer of ciphertext to decipher.

	@param OutStream	Pointer to a buffer to receive either the ciphertext or plaintext output.

	@param StreamLength	Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

  */ 

static void _BLOWFISH_EncipherDecipherStream_OFB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG InStream, BLOWFISH_PULONG OutStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft = Context->IvHigh32;
	BLOWFISH_ULONG	XRight = Context->IvLow32;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	for ( i = 0; i < StreamLength; i += 2 )
	{
		/* Encipher the initialisation vector */ 

		_BLOWFISH_ENCIPHER ( XRight, XLeft, XLeft, XRight, P, S0, S1, S2, S3 );

		/* Store and swap the enciphered initialisation vector */ 

		OutStream [ i ] = XRight;
		OutStream [ i + 1 ] = XLeft;

		XLeft = OutStream [ i ];
		XRight = OutStream [ i + 1 ];

		/* XOR the enciphered initialisation vector with the ciphertext or plaintext */ 

		OutStream [ i ] ^= InStream [ i ];
		OutStream [ i + 1 ] ^= InStream [ i + 1 ];
	}

	/* Preserve the enciphered initialisation vector as the new initialisation vector for stream based operations */ 

	Context->IvHigh32 = XLeft;
	Context->IvLow32 = XRight;

	return;
}

/**

	@internal

	Encipher/Decipher a stream of data in counter (segmented integer counter) mode.

	O = Ek ( Iv ADD ( n ) )

	Cn = Pn XOR O

	To decipher simply swap C and P.

	See @link glossary @endlink for more information.

	@param Context		Pointer to an initialised context record.

	@param InStream		Pointer to either a buffer of plaintext to encipher, or a buffer of ciphertext to decipher.

	@param OutStream	Pointer to a buffer to receive either the ciphertext or plaintext output.

	@param StreamLength	Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

	@remarks This function can be parallelised using OpenMP.

  */ 

static void _BLOWFISH_EncipherDecipherStream_CTR ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG InStream, BLOWFISH_PULONG OutStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft;
	BLOWFISH_ULONG	XRight;
	BLOWFISH_ULONG	IvHigh32 = Context->IvHigh32;
	BLOWFISH_ULONG	IvLow32 = Context->IvLow32;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

#ifdef _OPENMP

	#pragma omp parallel for default ( none ) private ( i, XLeft, XRight ) shared ( InStream, OutStream, IvHigh32, IvLow32, P, S0, S1, S2, S3, StreamLength ) schedule ( static )

#endif

	for ( i = 0; i < StreamLength; i += 2 )
	{
		/* Encipher the initialisation vector added with the counter */ 

		XLeft = IvHigh32 + (BLOWFISH_ULONG)i;
		XRight = IvLow32 + (BLOWFISH_ULONG)( i + 1 );

		_BLOWFISH_ENCIPHER ( XRight, XLeft, XLeft, XRight, P, S0, S1, S2, S3 );

		/* XOR the enciphered initialisation vector with the plaintext or ciphertext */ 

		OutStream [ i ] = InStream [ i ] ^ XRight;
		OutStream [ i + 1 ] = InStream [ i + 1 ] ^ XLeft;
	}

	/* Preserve the initialisation vector added with the counter as the new initialisation vector for stream based operations */ 

	Context->IvHigh32 += (BLOWFISH_ULONG)StreamLength;
	Context->IvLow32 += (BLOWFISH_ULONG)( StreamLength + 1 );

	return;
}

BLOWFISH_RC BLOWFISH_EncipherStream ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR PlainTextStream, BLOWFISH_PUCHAR CipherTextStream, BLOWFISH_SIZE_T StreamLength )
{
	/* Ensure the context and stream buffer pointers are non null */ 

	if ( Context == 0 || PlainTextStream == 0 || CipherTextStream == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Ensure the stream length is a multiple of 8 */ 

	if ( ( StreamLength & ~0x07 ) == 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	} 

#ifdef _OPENMP

	/* Ensure the stream length is not negative */ 

	if ( StreamLength < 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	}

#endif

	/* Encipher stream based on block cipher mode */ 

	Context->EncipherStream ( Context, (BLOWFISH_PCULONG)PlainTextStream, (BLOWFISH_PULONG)CipherTextStream, StreamLength >> 2 );

	return BLOWFISH_RC_SUCCESS;
}

BLOWFISH_RC BLOWFISH_EncipherBuffer ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR PlainTextBuffer, BLOWFISH_PUCHAR CipherTextBuffer, BLOWFISH_SIZE_T BufferLength )
{
	/* Ensure the context and buffer pointers are non null */ 

	if ( Context == 0 || CipherTextBuffer == 0 || PlainTextBuffer == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Ensure the buffer length is a multiple of 8 */ 

	if ( ( BufferLength & ~0x07 ) == 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	} 

#ifdef _OPENMP

	/* Ensure the buffer length is not negative */ 

	if ( BufferLength < 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	}

#endif

	/* Encipher buffer as a stream based on the block cipher mode */ 

	_BLOWFISH_BEGINSTREAM ( Context );

	Context->EncipherStream ( Context, (BLOWFISH_PCULONG)PlainTextBuffer, (BLOWFISH_PULONG)CipherTextBuffer, BufferLength >> 2 );

	_BLOWFISH_ENDSTREAM ( Context );

	return BLOWFISH_RC_SUCCESS;
}

/**

	@internal

	Perform 16-round decipher, finalise round and unswap xL and xR:

	xR = xR XOR P0

	xL = xL XOR P1

	See @link glossary @endlink for more information.

	@param BufferHigh		Pointer to the high 32-bits of the output buffer.

	@param BufferLow		Pointer to the low 32-bits of the output buffer.

	@param XLeft			High 32-bits of the message to decipher.

	@param XRight			Low 32-bits of the message to decipher.

	@param P				Pointer to the P-Array.

	@param S0, S1, S2, S3	Pointers to each element of the S-Box array.

	@remarks If BufferHigh and BufferLow are the same variables as XLeft and XRight then the result will not be swapped!

  */ 

#define _BLOWFISH_DECIPHER( BufferHigh, BufferLow, XLeft, XRight, P, S0, S1, S2, S3 )	\
{																						\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 17 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 16 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 15 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 14 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 13 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 12 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 11 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 10 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 9 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 8 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 7 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 6 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 5 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 4 );							\
	_BLOWFISH_CIPHER ( XLeft, XRight, P, S0, S1, S2, S3, 3 );							\
	_BLOWFISH_CIPHER ( XRight, XLeft, P, S0, S1, S2, S3, 2 );							\
	BufferHigh = XRight ^ P [ 0 ];														\
	BufferLow = XLeft ^ P [ 1 ];														\
}

void BLOWFISH_Decipher ( BLOWFISH_PCONTEXT Context, BLOWFISH_PULONG High32, BLOWFISH_PULONG Low32 )
{
	BLOWFISH_ULONG	XLeft = *High32;
	BLOWFISH_ULONG	XRight = *Low32;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];

	/* Decipher 8-byte plaintext block */ 

	_BLOWFISH_DECIPHER ( *High32, *Low32, XLeft, XRight, P, S0, S1, S2, S3 );

	return;
}

/**

	@internal

	Decipher a stream of data in electronic codebook mode.

	Pn = Ek ( Cn )

	See @link glossary @endlink for more information.

	@param Context			Pointer to an initialised context record.

	@param CipherTextStream	Buffer of ciphertext to decipher.

	@param CipherTextStream	Buffer to receive the plaintext.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

	@remarks This function can be parallelised using OpenMP.

  */ 

static void _BLOWFISH_DecipherStream_ECB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG CipherTextStream, BLOWFISH_PULONG PlainTextStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft;
	BLOWFISH_ULONG	XRight;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	/* Decipher ciphertext in 8-byte blocks */ 

#ifdef _OPENMP

	#pragma omp parallel for default ( none ) private ( i, XLeft, XRight ) shared ( PlainTextStream, CipherTextStream, P, S0, S1, S2, S3, StreamLength ) schedule ( static )

#endif

	for ( i = 0; i < StreamLength; i += 2 )
	{
		XLeft = CipherTextStream [ i ];
		XRight = CipherTextStream [ i + 1 ];

		_BLOWFISH_DECIPHER ( PlainTextStream [ i ], PlainTextStream [ i + 1 ], XLeft, XRight, P, S0, S1, S2, S3 );
	}

	return;
}

/**

	@internal

	Decipher a stream of data in cipher block chaining mode.

	Round 1:

	P0 = Dk ( C0 ) XOR ( Iv )

	Round n:

	Pn = Dk ( Cn ) XOR ( Cn - 1 )

	See @link glossary @endlink for more information.

	@param Context			Pointer to an initialised context record.

	@param CipherTextStream	Buffer of ciphertext to decipher.

	@param CipherTextStream	Buffer to receive the plaintext.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

	@remarks This function can be parallelised using OpenMP.

  */ 

static void _BLOWFISH_DecipherStream_CBC ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG CipherTextStream, BLOWFISH_PULONG PlainTextStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft;
	BLOWFISH_ULONG	XRight;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	/* Decipher the first block of ciphertext */ 

	XLeft = CipherTextStream [ 0 ];
	XRight = CipherTextStream [ 1 ];

	_BLOWFISH_DECIPHER ( PlainTextStream [ 0 ], PlainTextStream [ 1 ], XLeft, XRight, P, S0, S1, S2, S3 );

	/* XOR the deciphered first block with the initialisation vector to yeild the plaintext */ 

	PlainTextStream [ 0 ] ^= Context->IvHigh32;
	PlainTextStream [ 1 ] ^= Context->IvLow32;

	/* Decrypt any remaining blocks */ 

#ifdef _OPENMP

	#pragma omp parallel for default ( none ) private ( i, XLeft, XRight ) shared ( PlainTextStream, CipherTextStream, P, S0, S1, S2, S3, StreamLength ) schedule ( static )

#endif

	for ( i = 2; i < StreamLength; i += 2 )
	{
		/* Decipher block of ciphertext */ 

		XLeft = CipherTextStream [ i ];
		XRight = CipherTextStream [ i + 1 ];

		_BLOWFISH_DECIPHER ( PlainTextStream [ i ], PlainTextStream [ i + 1 ], XLeft, XRight, P, S0, S1, S2, S3 );

		/* XOR the deciphered block with the previous block of ciphertext to yeild the plaintext */ 

		PlainTextStream [ i ] ^= CipherTextStream [ i - 2 ];
		PlainTextStream [ i + 1 ] ^= CipherTextStream [ i - 1 ];
	}

	/* Preserve the previous block of ciphertext as the new initialisation vector for stream based operations */ 

	Context->IvHigh32 = CipherTextStream [ StreamLength - 2 ];
	Context->IvLow32 = CipherTextStream [ StreamLength - 1 ];

	return;
}

/**

	@internal

	Decipher a stream of data in cipher feedback mode.

	Round 1:

	P0 = C0 XOR Ek ( Iv )

	Round n:

	Pn = Cn XOR Ek ( ( Cn - 1 ) )

	See @link glossary @endlink for more information.

	@param Context			Pointer to an initialised context record.

	@param CipherTextStream	Buffer of ciphertext to decipher.

	@param CipherTextStream	Buffer to receive the plaintext.

	@param StreamLength		Length of the plaintext and ciphertext stream buffers in 4-byte blocks.

	@remarks It is an unchecked runtime error to supply either a null pointer, or a stream buffer length that is not a multiple of 4 to this function.

	@remarks This function can be parallelised using OpenMP.

  */ 

static void _BLOWFISH_DecipherStream_CFB ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCULONG CipherTextStream, BLOWFISH_PULONG PlainTextStream, BLOWFISH_SIZE_T StreamLength )
{
	BLOWFISH_ULONG	XLeft;
	BLOWFISH_ULONG	XRight;
	BLOWFISH_PULONG	P = Context->PArray;
	BLOWFISH_PULONG	S0 = Context->SBox [ 0 ];
	BLOWFISH_PULONG	S1 = Context->SBox [ 1 ];
	BLOWFISH_PULONG	S2 = Context->SBox [ 2 ];
	BLOWFISH_PULONG	S3 = Context->SBox [ 3 ];
	BLOWFISH_SIZE_T	i;

	/* Encipher the initialisation vector */ 

	XLeft = Context->IvHigh32;
	XRight = Context->IvLow32;

	_BLOWFISH_ENCIPHER ( XRight, XLeft, XLeft, XRight, P, S0, S1, S2, S3 );

	/* XOR enciphered initialisation vector with the ciphertext to yeild the plaintext */ 

	PlainTextStream [ 0 ] = XRight ^ CipherTextStream [ 0 ];
	PlainTextStream [ 1 ] = XLeft ^ CipherTextStream [ 1 ];

	/* Decrypt any remaining blocks */ 

#ifdef _OPENMP

	#pragma omp parallel for default ( none ) private ( i, XLeft, XRight ) shared ( PlainTextStream, CipherTextStream, P, S0, S1, S2, S3, StreamLength ) schedule ( static )

#endif

	for ( i = 2; i < StreamLength; i += 2 )
	{
		/* Encipher the previous block of ciphertext */ 

		XLeft = CipherTextStream [ i - 2 ];
		XRight = CipherTextStream [ i - 1 ];

		_BLOWFISH_ENCIPHER ( XRight, XLeft, XLeft, XRight, P, S0, S1, S2, S3 );

		/* XOR the enciphered previous block of ciphertext with the current block ciphertext to yeild the plaintext */ 

		PlainTextStream [ i ] = XRight ^ CipherTextStream [ i ];
		PlainTextStream [ i + 1 ] = XLeft ^ CipherTextStream [ i + 1 ];
	}

	/* Preserve the previous block of ciphertext as the new initialisation vector for stream based operations */ 

	Context->IvHigh32 = CipherTextStream [ StreamLength - 2 ];
	Context->IvLow32 = CipherTextStream [ StreamLength - 1 ];

	return;
}

BLOWFISH_RC BLOWFISH_DecipherStream ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR CipherTextStream, BLOWFISH_PUCHAR PlainTextStream, BLOWFISH_SIZE_T StreamLength )
{
	/* Ensure the context and stream buffer pointers are non null */ 

	if ( Context == 0 || CipherTextStream == 0 || PlainTextStream == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Ensure the stream length is a multiple of 8 */ 

	if ( ( StreamLength & ~0x07 ) == 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	}

#ifdef _OPENMP

	/* Ensure the stream length is not negative */ 

	if ( StreamLength < 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	}

#endif

	/* Decipher stream buffer based on block cipher mode */ 

	Context->DecipherStream ( Context, (BLOWFISH_PCULONG)CipherTextStream, (BLOWFISH_PULONG)PlainTextStream, StreamLength >> 2 );

	return BLOWFISH_RC_SUCCESS;
}

BLOWFISH_RC BLOWFISH_DecipherBuffer ( BLOWFISH_PCONTEXT Context, BLOWFISH_PCUCHAR CipherTextBuffer, BLOWFISH_PUCHAR PlainTextBuffer, BLOWFISH_SIZE_T BufferLength )
{
	/* Ensure the context and buffer pointers are non null */ 

	if ( Context == 0 || CipherTextBuffer == 0 || PlainTextBuffer == 0 )
	{
		return BLOWFISH_RC_INVALID_PARAMETER;
	}

	/* Ensure the buffer length is a multiple of 8 */ 

	if ( ( BufferLength & ~0x07 ) == 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	}

#ifdef _OPENMP

	/* Ensure the buffer length is not negative */ 

	if ( BufferLength < 0 )
	{
		return BLOWFISH_RC_BAD_BUFFER_LENGTH;
	}

#endif

	/* Decipher buffer as a stream based on the block cipher mode */ 

	_BLOWFISH_BEGINSTREAM ( Context );

	Context->DecipherStream ( Context, (BLOWFISH_PCULONG)CipherTextBuffer, (BLOWFISH_PULONG)PlainTextBuffer, BufferLength >> 2 );

	_BLOWFISH_ENDSTREAM ( Context );

	return BLOWFISH_RC_SUCCESS;
}

/** @} */ 
