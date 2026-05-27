---
description: I'm the data, playing the data, disguised as another data...
---

# Steganography

**Steganography** is the practice of concealing a message, file, image, or video within another file, message, image, or video. Unlike cryptography, which scrambles data to make it unreadable, steganography hides the existence of the message.

## Relevance to Defense

For blue teamers and security analysts, steganography matters because:

* **Malware communication:** Attackers may hide C2 traffic or configuration data inside images or legitimate-looking traffic.
* **Data exfiltration:** Insiders or malware may smuggle sensitive data out of a network inside benign-looking files.
* **Forensics:** Analysts may need to detect and extract hidden artifacts during investigations, malware analysis, or CTF-style training.

## Common Techniques

* **Least Significant Bit (LSB):** Modifies the last bit of image bytes to store hidden data while minimally changing the visible image.
* **End of File (EOF) / Injection:** Appends data after a file's normal end marker.
* **Metadata Manipulation:** Hides data in headers or metadata such as EXIF or ID3 tags.
* **Network Steganography:** Hides information in protocol headers, sequence numbers, or timing channels.

## General Analysis Utilities

* [CyberChef](https://gchq.github.io/CyberChef/) - Web app for encoding, decoding, compression, and data analysis. Useful for LSB extraction, XOR, and magic header detection.
* [Binwalk](https://github.com/ReFirmLabs/binwalk) - Detects and extracts embedded files and appended data.
* [ExifTool](https://exiftool.org/) - Reads, writes, and manipulates image, audio, video, and PDF metadata.
* [Strings](https://linux.die.net/man/1/strings) - Prints readable strings from files. Often a first check for unencrypted hidden text.

These tools also overlap with DFIR file analysis workflows.

{% content-ref url="../dfir-digital-forensics-and-incident-response/file-analysis.md" %}
[file-analysis.md](../dfir-digital-forensics-and-incident-response/file-analysis.md)
{% endcontent-ref %}

## General Purpose and Command-Line Tools

* [Steghide](https://steghide.sourceforge.net/) - Classic program for hiding data in image and audio files. Still widely used in CTFs, but older.
* [StegSeek](https://github.com/RickdeJager/stegseek) - Fast replacement for StegCracker that can crack Steghide passwords.
* [OutGuess](https://www.kali.org/tools/outguess/) - Tool for inserting hidden information into redundant bits of data sources.
* [OpenStego](https://www.openstego.com/) - Open-source Java tool for data hiding and digital watermarking.

## Image Analysis

* [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier) - Online forensic image analysis toolkit.
* [Aperi'Solve](https://aperisolve.fr/) - Online steganography analysis platform that combines common image-analysis tools.
* [StegSolve](https://github.com/Giotino/StegSolve) - Classic Java tool for analyzing image layers, planes, and filters.
* [StegoOnline](https://stegonline.georgeom.net/upload) - Web-based enhanced port of StegSolve for image plane and data analysis.
* [StegoToolKit](https://github.com/DominicBreuker/stego-toolkit) - Docker image with tools for steganography challenges.
* [zsteg](https://github.com/zed-0xff/zsteg) - Detects hidden data in PNG and BMP files.
* [Base64 to Image Converter](https://codebeautify.org/base64-to-image-converter) - Useful when Base64 strings may represent images.

## Audio Steganography

Hidden messages within audio files often require spectral analysis or specialized software.

* [Audacity](https://www.audacityteam.org/) - Free audio editor useful for spectrogram and waveform analysis.
* [Sonic Visualiser](https://www.sonicvisualiser.org/) - Application for viewing and analyzing audio file contents.

## Miscellaneous and Decoders

* [WebQR](https://webqr.com/index.html) - Online QR code scanner.
* [Online Barcode Reader](https://online-barcode-reader.inliteresearch.com/) - Reads various barcode formats.

## Guides and Collections

* [0xRick's Stego Tool Collection](https://0xrick.github.io/lists/stego/) - Comprehensive list of steganography tools.
* [The Exo Guide to Data Cloaking](https://exo.substack.com/p/the-exo-guide-to-data-cloaking) - Guide on data hiding techniques.
* [Caesum's Stego Guide](http://www.caesum.com/) - Legacy CTF-oriented steganography resource.

## Legacy / Older Utilities

* [StegCracker](https://www.kali.org/tools/stegcracker/) - Deprecated brute-force utility for Steghide. Use StegSeek instead.
* [Snowdrop](https://www.kali.org/tools/snowdrop/) - Steganographic watermarking for text documents and C source code.
* [Stegsnow](https://www.kali.org/tools/stegsnow/) - Conceals messages in ASCII text by appending whitespace to the end of lines.

Training rooms and CTF practice links are preserved in the Training section.

{% content-ref url="../training/" %}
[training](../training/)
{% endcontent-ref %}
