thmj3g-tools
============
Tools to unpack and repack data files for [Touhou Unreal Mahjong 3rd Generation](http://www.dna-softwares.com/thmj3g/ "(Japanese)"), produced by [D.N.A.Softwares](http://www.dna-softwares.com/ "(Japanese)"). The intent behind creating these tools is to create an English translation of the game.

This game uses the [AIMS 2D game engine](http://aims.dna-softwares.com/?page_id=14 "(Japanese)"), which in turn makes heavy use of the (now defunct) D3D library [Luna](http://web.archive.org/web/20060425214438/http://luna.sumomo.ne.jp/ "(Japanese)"). A few of the utilities included in both the AIMS SDK as well as the `bin/` directory of this repository come from the Luna library, specifically `LLZSS.exe` and `LPACK.exe`.

The `.lua` files contained within the packfiles of `thmj3g.p` (and likely those of certain other games) are precompiled, so a disassembler (and an understanding of LASM) will be necessary to modify them. [Lua Assembly Tools](https://github.com/mlnlover11/LuaAssemblyTools) is recommended for disassembling and recompiling these files.

To use `blowpack` or `lunpack -b`, you will need to provide a 448-bit key file named `thmj3g.key`. The file should be 56 bytes long and contain a binary representation of the key.

blowpack
--------
Encrypts a file using a non-chaining Blowfish implementation and adds a bogus LZSS header. The bogus header is used by thmj3g's loader to determine the length of the original unpadded file. ...yes, really. It's not compressed at all.

### Usage
`blowpack filename`

The file is overwritten, so be careful!

### TODO
- Check for existing header, don't encrypt again if the header exists (decode/strip header instead)
- Add a decrypt/header-stripping mode
- Allow keyfile to be specified as an argument


lunpack
-------
Unpacker utility for games created using the [AIMS 2D game engine](http://aims.dna-softwares.com/?page_id=14 "(Japanese)") by D.N.A.Softwares.

### Usage
`lunpack packfile.p [-b/-l]`

- `-b` will decrypt files using non-chaining Blowfish. (used by Touhou Unreal Mahjong 3rd Generation)
- `-l` will attempt to decompress files in the packfile using `LLZSS.exe`. (used in other games

The two switches cannot be combined. Choose one or the other.

Outputs files into `packfile/` (or `packfile-music/` if processing a `.mus` file).

### TODO
- Allow keyfile to be specified as an argument


Notes and Credit
----------------
`LLZSS.exe` and `LPACK.exe` from the AIMS 1.8.0 toolkit (and subsequently, the Luna library) are included for convenience.

The Blowfish implementation used for these tools is Paul Kocher's version, written in 1997.

The copies of `blowpack.exe` and `lunpack.exe` in this repository were compiled on Win7 x64 using MinGW.