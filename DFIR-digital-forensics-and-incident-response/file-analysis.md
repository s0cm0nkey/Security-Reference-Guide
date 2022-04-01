---
description: What is this? I didn't put this file here...
---

# File/Binary Analysis

## **File Analysis Methodology**

* [https://zeltser.com/analyzing-malicious-documents/](https://zeltser.com/analyzing-malicious-documents/)
* [SANS Malicious File Analysis Cheatsheet](https://sansorg.egnyte.com/dl/IQ3GhaH868/?)
* [https://hunter.jorgetesta.tech/malware/tips/analisis-estatico](https://hunter.jorgetesta.tech/malware/tips/analisis-estatico)

### Static Analysis Tasklist

* Anatomy
  * Time Date Stamp
  * Discrepancy between Raw and Virtual Size
* Hashes&#x20;
  * Check Hashes against [https://s0cm0nkey.github.io/EasyThreatFile.html](https://s0cm0nkey.github.io/EasyThreatFile.html)
* Strings
  * Too many meaningless strings (Possible obfuscation)
  * Internal/external messages
  * Referenced (invoked) functions
  * Sections used by the PE
  * IPs and/or Domains
  * Error messages or exceptions
  * Names or keywords
* Libraries
  * Low number of libraries?
  * Cryptography Libraries - Why does this need a crypto library?
* Imports/VirtualAlloc

### Dynamic Analysis Task List

* Run file through available/allowed Sandboxing utilties

{% content-ref url="sandboxing.md" %}
[sandboxing.md](sandboxing.md)
{% endcontent-ref %}

* Process Hacker
  * Observe active processes and pay attention to their colors
  * Extract strings and data in memory of the active suspicious process
  * Investigate Handles, including Mutex name
* Process Monitor
  * Record local system interactions
* ProcDOT
  * Organize and clean Process Monitor data
* Wireshark
  * Record network activity
  * Give the malware what it wants and redirect its request to a local web server in your lab. You can use IPTABLES on linux (your lab's gateway) to intercept and redirect all internal traffic and reinfect your victim machine
    * Use FAKEDNS in REMnux
    * What happens if you let malware connect to your web server?

## **File Analysis Tools**

### Exif/Metadata viewers&#x20;

Often the metadata surrounding a file can yield a trove of useful information. The below tools can be used to pull handy exif data from images or metadata from other files.

* [http://www.exifdataviewer.com/](http://www.exifdataviewer.com)
* [https://www.extractmetadata.com/](https://www.extractmetadata.com)
* [https://exifinfo.org/](https://exifinfo.org)
* [http://exif.regex.info/exif.cgi](http://exif.regex.info/exif.cgi)
* [https://www.metadata2go.com/](https://www.metadata2go.com)
* CLI Tools&#x20;
  * [exiftool](https://github.com/exiftool/exiftool) -  ExifTool meta information reader/writer&#x20;
  * [FOCA](https://github.com/ElevenPaths/FOCA) -  Tool to find metadata and hidden information in the documents.&#x20;
  * [Foremost](https://github.com/korczis/foremost): Foremost is a console program to recover files based on their headers, footers, and internal data structures.
  * [exifprobe](https://www.kali.org/tools/exifprobe/) - xifprobe reads image files produced by digital cameras (including several so-called “raw” file formats) and reports the structure of the files and the auxiliary data and metadata contained within them.
  * [exiv2](https://www.kali.org/tools/exiv2/) - Exiv2 is a C++ library and a command line utility to manage image metadata. It provides fast and easy read and write access to the Exif, IPTC and XMP metadata of images in various formats
  * [metacam](https://www.kali.org/tools/metacam/) - Extract EXIF information from digital camera files

### [Python-Ole tools](https://github.com/decalage2/oletools)&#x20;

A package of python tools to analyze [Microsoft OLE2 files](http://en.wikipedia.org/wiki/Compound\_File\_Binary\_Format) (also called Structured Storage, Compound File Binary Format or Compound Document File Format), such as Microsoft Office documents or Outlook messages, mainly for malware analysis, forensics and debugging.

* Tools for analyzing objects within an OLE file:
  * Pre-2oleid - analyses OLE files to detect specific characteristics usually found in malicious files.
  * olevba - extracts and analyses VBA Macro source code from MS Office documents (OLE and OpenXML).
  * mraptor - detects malicious VBA Macros.
  * msodde - detects and extracts DDE/DDEAUTO links from MS Office documents, RTF and CSV.
  * pyxswf - detects, extracts and analyses Flash objects (SWF) that may be embedded in files such as MS Office documents (e.g. Word, Excel) and RTF, which is especially useful for malware analysis.
  * oleobj - extracts embedded objects from OLE files.
  * rtfobj - extracts embedded objects from RTF files.
* Tools to analyse the structure of OLE files:
  * olebrowse - is a simple GUI to browse OLE files (e.g., MS Word, Excel, PowerPoint documents), view and extract individual data streams.
  * olemeta - extracts all standard properties (metadata) from OLE files.
  * oletimes - extracts creation and modification timestamps of all streams and storages.
  * oledir - displays all the directory entries of an OLE file, including free and orphaned entries.
  * olemap - displays a map of all the sectors in an OLE file.

### Binary Analysis Tools

* [binwalk](https://www.kali.org/tools/binwalk/) - Binwalk is a tool for searching a given binary image for embedded files and executable code.
* [de4dot](https://www.kali.org/tools/de4dot/) - de4dot is a .NET deobfuscator and unpacker.
* [pev](https://www.kali.org/tools/pev/) - pev is a tool to get information of PE32/PE32+ executables (EXE, DLL, OCX etc) like headers, sections, resources and more.
* [ropper](https://www.kali.org/tools/ropper/) - This package contains scripts that display info about files in different formats and find gadgets to build ROPs chains for different architectures (x86/x86\_64, ARM/ARM64, MIPS, PowerPC). For disassembly ropper uses the Capstone Framework.

### Doc Analysis Tools

* [Peepdf ](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool)- A Python tool to explore PDF files in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that a security researcher could need in a PDF analysis without using 3 or 4 tools to make all the tasks.
* [pdf-parser](https://www.kali.org/tools/pdf-parser/) - This tool will parse a PDF document to identify the fundamental elements used in the analyzed file. It will not render a PDF document.
* [pdfid](https://www.kali.org/tools/pdfid/) - Scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain (for example) JavaScript or execute an action when opened. PDFiD will also handle name obfuscation.
*   [ViperMonkey](https://github.com/decalage2/ViperMonkey) - A VBA Emulation engine written in Python, designed to analyze and de-obfuscate malicious VBA Macros contained in Microsoft Office files.

    * **Parse and interpret VBA macros**

    ```
    vmonkey phishing.docm
    ```

    * **Faster output**

    ```
    pypy vmonkey.py -s phishing.docm
    ```

    * **Less verbose output**

    ```
    vmonkey -l warning phishing.docm
    ```

## File Unpacker

* [cabextract](https://www.kali.org/tools/cabextract/) - A program which unpacks cabinet (.cab) files, which are a form of archive Microsoft uses to distribute their software and things like Windows Font Packs.

## **File Encrypt/Decrypt/Crack**

* [Pem File Cracking](https://github.com/robertdavidgraham/pemcrack) - Cracks SSL PEM files that hold encrypted private keys. Brute forces or dictionary cracks.
*   [PKZip File Cracking](https://www.unix-ag.uni-kl.de/\~conrad/krypto/pkcrack.html) - Breaking Pkzip encryption.  This package implements an algorithm that was developed by Eli Biham and Paul Kocher and that is described in [this paper (Postscript, 80k)](ftp://utopia.hacktic.nl/pub/crypto/cracking/pkzip.ps.gz).

    &#x20;The attack is a _known plaintext attack_, which means you have to know part of the encrypted data in order to break the cipher.
* [bruteforce-salted-openssl](https://www.kali.org/tools/bruteforce-salted-openssl/) - Try to find the passphrase or password of a file that was encrypted with the openssl command.
* [ccrypt](https://www.kali.org/tools/ccrypt/) - ccrypt is a utility for encrypting and decrypting files and streams.
* [fcrackzip](https://www.kali.org/tools/fcrackzip/) - fcrackzip is a fast password cracker partly written in assembler. It is able to crack password protected zip files with brute force or dictionary based attacks, optionally testing with unzip its results. It can also crack cpmask’ed images.
* [nasty  - ](https://www.kali.org/tools/nasty/)Nasty is a program that helps you to recover the passphrase of your PGP or GPG-key in case you forget or lost it.
* [pdfcrack](https://www.kali.org/tools/pdfcrack/) - PDFCrack is a simple tool for recovering passwords from pdf-documents.
* [rarcrack](https://www.kali.org/tools/rarcrack/)  This program uses a brute force algorithm to guess your encrypted compressed file’s password. This program can crack zip,7z and rar file passwords.

## File Conversion Tools

* [exe2hexbat](https://www.kali.org/tools/exe2hexbat/) - A Python script to convert a Windows PE executable file to a batch file and vice versa.

## File Artifact Reference

* [https://filesec.io/](https://filesec.io) - Resource for seeing which file extensions are used in different types of malware
* [Strontic xCyclopedia](https://strontic.github.io/xcyclopedia/) - Huge encyclopedia of executables, dll files, scripts, even the file paths they are supposed to be under. Contains tons of metadata, file hashes, reputation scores, handles, and so much more!
* [Winbindex](https://winbindex.m417z.com) - Index of windows binaries with file hash, size, what update it was created with, and many more. Perfect for understanding more on a file.

### [Forensics Artifact Project](https://www.kali.org/tools/forensic-artifacts/)

[https://github.com/ForensicArtifacts/artifacts/](https://github.com/ForensicArtifacts/artifacts/tree/main/data) - A free, community-sourced, machine-readable knowledge base of digital forensic artifacts that the world can use both as an information source and within other tools.

#### Get an object of forensic artifacts <a href="#get-an-object-of-forensic-artifacts" id="get-an-object-of-forensic-artifacts"></a>

```
$WindowsArtifacts=$(curl https://raw.githubusercontent.com/ForensicArtifacts/artifacts/master/data/windows.yaml)
$obj = ConvertFrom-Yaml $WindowsArtifacts.Content -AllDocuments
```

Now that it is stored within a format we can use the below will give us information at a glance.

```
$count=0;
foreach ($Artifact in $obj){
$Artifacts = [pscustomobject][ordered]@{
	Name = $obj.name[$count]
	Description = $obj.doc[$count]
	References = $obj.urls[$count]
	Attributes = $obj.sources.attributes[$count]
}
$count++;
$Artifacts | FL;
}
```

#### Query object for relevant registry keys: <a href="#query-object-for-relevant-registry-keys" id="query-object-for-relevant-registry-keys"></a>

```
$obj.sources.attributes.keys|Select-String "HKEY"
$obj.sources.attributes.key_value_pairs
```

#### Query object for relevant file paths: <a href="#query-object-for-relevant-file-paths" id="query-object-for-relevant-file-paths"></a>

```
$obj.sources.attributes.paths
```

### File Signatures

* [https://en.wikipedia.org/wiki/List\_of\_file\_signatures](https://en.wikipedia.org/wiki/List\_of\_file\_signatures)
* [https://www.garykessler.net/library/file\_sigs.html](https://www.garykessler.net/library/file\_sigs.html)
* [https://filesignatures.net/index.php?page=all](https://filesignatures.net/index.php?page=all)

****
