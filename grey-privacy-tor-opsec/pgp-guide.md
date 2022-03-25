# PGP Guide

{% embed url="https://youtu.be/CEADq-B8KtI" %}

## General PGP Opsec&#x20;

* Sometimes when you inport a public PGP key, it will reach out to PGP servers to validate the key, if setup to do so.&#x20;
* Be wary of this if using you own host machine. Catch with Snitch program.&#x20;
* Again, do not use your host device to manage the PGP keys.
* The start of pgp messages will detail the OS that created it
* PGP key scrubbing
  * &#x20;\#gpg --encrypt --armor --no-comments --no-emit-version -r KEY&#x20;
* Ensure you put the date in the message and the reason for the signed pgp message to ensure you dont get impersonated on other forums&#x20;
* Verify signed pgp message&#x20;
  * gpg --verify
  * paste the whole signed PGP mesage&#x20;
  * CTRL+D&#x20;

• _**Back up your pgp key ring\***_

### Importing public PGP keys&#x20;

* When you have recieved a new public key, you should import it on to your keyring
  * \#gpg --import&#x20;
  * paste whole key&#x20;
  * CTRL+D&#x20;
  * Should display "key XXXXXXXXXXX: ‘username’ imported&#x20;
* To use the imported key ◇ gpg --encrypt --armor -r XXXXXXXXXX&#x20;
  * Type out your message and hit CTRL+D when done to produce the encrypted pgp message

### Encrypting messages&#x20;

\#gpg --encrypt --armor -r KEY

### Decrypting messages&#x20;

* \#gpg -d \<paste message>&#x20;
* enter passphrase

## Key Generation

Generating a Keypair Before we can encrypt a message, we are going to need to generate a keypair. To do this, enter the following command:

gpg --gen-key The following text will then be prompted:gpg (GnuPG) 2.0.26; Copyright (C) 2013 Free Software Foundation, Inc. This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want: (1) RSA and RSA (default) (2) DSA and Elgamal (3) DSA (sign only) (4) RSA (sign only) Your selection? 1 The main difference between RSA & DSA and Elgamal is the underlying mathematical principles, for this guide we'll be using RSA. Enter 1 and hit enter. Next prompt:RSA keys may be between 1024 and 4096 bits long. What keysize do you want? (2048) 4096 Use of 4096 for the added security. Next prompt:Please specify how long the key should be valid. 0 = key does not expire  = key expires in n days w = key expires in n weeks m = key expires in n months y = key expires in n years Key is valid for? (0) 1y In the world of privacy, permanent anything is usually looked down upon, so I would recommend setting some length of time. For this tutorial my key will last for 1 year. To do this I enter 1y. Next prompt:Key expires at 12/12/15 Is this correct? (y/N) y I entered y, as it was the correct amount of time. The next prompt will ask for each of the following one at a time. The only field you actually need to fill out is real name. In that category put whatever you want. The Email address and comment are optional.GnuPG needs to construct a user ID to identify your key.

Real name: WhatEverNameYouWant Email address: Comment: You selected this USER-ID: "WhatEverNameYouWant"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O Modification options are given, but I'm satisfied with my entry, so I entered O to progress further.You will then be presented with a prompt to enter a passphrase. Pick a good one and move on. You will then be presented with the following message:We need to generate a lot of random bytes. It is a good idea to perform some other action (type on the keyboard, move the mouse, utilize the disks) during the prime generation; this gives the random number generator a better chance to gain enough entropy. We need to generate a lot of random bytes. It is a good idea to perform some other action (type on the keyboard, move the mouse, utilize the disks) during the prime generation; this gives the random number generator a better chance to gain enough entropy. gpg: key CA637B79 marked as ultimately trusted public and secret key created and signed.

Basically hit a bunch of keys on your keyboard, and click around a bit until it finishes generating random information. Once done, you should receive some form of confirmation, and return to the console. At this point you will have successfully generated a keypair that can be used to encrypt and decrypt messages.

## Editing Keys

If you want to edit any key attributes, run the following command:

gpg --edit-key WhatEverNameYouWant&#x20;

The following will then appear: gpg (GnuPG) 2.0.26; Copyright (C) 2013 Free Software Foundation, Inc. This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

Secret key is available.

pub 4096R/(Expunged) created: 2014-12-25 expires: 2015-12-25 usage: SC trust: ultimate validity: ultimate sub 4096R/(Expunged) created: 2014-12-25 expires: 2015-12-25 usage: E \[ultimate] (1). WhatEverNameYouWant

gpg> You can obtain a list of editing options by running the command "help"gpg> help&#x20;

* quit - quit this menu&#x20;
* save -save and quit&#x20;
* help - show this help&#x20;
* fpr - show key fingerprint&#x20;
* list -list key and user IDs&#x20;
* uid - select user ID N&#x20;
* key - select subkey N&#x20;
* check - check signatures&#x20;
* sign - sign selected user IDs \[\* see below for related commands]&#x20;
* lsign - sign selected user IDs locally&#x20;
* tsign - sign selected user IDs with a trust signature&#x20;
* nrsign - sign selected user IDs with a non-revocable signature&#x20;
* adduid - add a user ID&#x20;
* addphoto - add a photo ID&#x20;
* deluid - delete selected user IDs&#x20;
* addkey - add a subkey&#x20;
* addcardkey - add a key to a smartcard&#x20;
* keytocard - move a key to a smartcard&#x20;
* bkuptocard - move a backup key to a smartcard&#x20;
* delkey - delete selected subkeys&#x20;
* addrevoker - add a revocation key&#x20;
* delsig - delete signatures from the selected user IDs&#x20;
* expire - change the expiration date for the key or selected subkeys&#x20;
* primary - flag the selected user ID as primary&#x20;
* toggle - toggle between the secret and public key listings&#x20;
* pref - list preferences (expert)&#x20;
* showpref - list preferences (verbose)&#x20;
* setpref - set preference list for the selected user IDs&#x20;
* keyserver - set the preferred keyserver URL for the selected user IDs&#x20;
* notation - set a notation for the selected user IDs&#x20;
* passwd - change the passphrase trust change the ownertrust&#x20;
* revsig - revoke signatures on the selected user IDs&#x20;
* revuid - revoke selected user IDs&#x20;
* revkey - revoke key or selected subkeys&#x20;
* enable - enable key&#x20;
* disable - disable key&#x20;
* showphoto - show selected photo IDs&#x20;
* clean - compact unusable user IDs and remove unusable signatures from key&#x20;
* minimize - compact unusable user IDs and remove all signatures from key
*   The `sign' command may be prefixed with an`l' for local signatures (lsign),

    a `t' for trust signatures (tsign), an`nr' for non-revocable signatures

    (nrsign), or any combination thereof (ltsign, tnrsign, etc.).

gpg> As an example, I'll show you how to edit the trust of a key. Start by running the "trust" command:gpg> trust Here is the output:pub 4096R/(Expunged) created: 2014-12-25 expires: 2015-12-25 usage: SC trust: marginally validity: marginally sub 4096R/(Expunged) created: 2014-12-25 expires: 2015-12-25 usage: E \[ultimate] (1). WhatEverNameYouWant

Please decide how far you trust this user to correctly verify other users' keys (by looking at passports, checking fingerprints from different sources, etc.)

1 = I don't know or won't say 2 = I do NOT trust 3 = I trust marginally 4 = I trust fully 5 = I trust ultimately m = back to the main menu

Your decision? 5 I created the key, so there's no reason other than to trust it to its fullest extent, therefore I selected 5.Do you really want to set this key to ultimate trust? (y/N) y

pub 4096R/(Expunged) created: 2014-12-12 expires: 2015-12-12 usage: SC trust: ultimate validity: ultimate sub 4096R/(Expunged) created: 2014-12-12 expires: 2015-12-12 usage: E \[ultimate] (1). WhatEverNameYouWant

## Import/Export

Exporting and Importing Keys At this stage you now have your own keypair; the next step is to retrieve your public key so you can distribute it for others to use when messaging you. In this tutorial, we created a user under the ID of WhatEverNameYouWant. This is the ID which I shall use. To print the key, enter the following command:

gpg --armor --export WhatEverNameYouWant where WhatEverNameYouWant is the ID or Email picked when creating the keypair. This will print the public key to the console screen:&#x20;

\-----BEGIN PGP PUBLIC KEY BLOCK----- Version: GnuPG v2

KEY GOES HERE

\-----END PGP PUBLIC KEY BLOCK-----&#x20;

If you want it instead to save it to a file the following command can instead be entered:gpg --armor --output myPubKey.asc --export WhatEverNameYouWant Where myPubKey.asc is the name and directory path of the file to save it to. This can be opened with a text editor, and the public key can be copied.Alternatively, you can use a single bracket redirect character to funnel the output of a command into a file:gpg --armor -export WhatEverNameYouWant > myPubKey.asc The result is the same._LINUX TIP_ The ">" character redirects stdout (standard out-- what would normally be printed on the screen), and overwrites the file placed to the right of the character. If no such file exists, it is created. If the file does exist, it will be overwritten, and the previous information that it contained will be lost. To export your private key, you will enter the following command:gpg --armor --export-secret-keys WhatEverNameYouWant This will print an output to the console resembling this:

\-----BEGIN PGP PRIVATE KEY BLOCK----- <

\> -----END PGP PRIVATE KEY BLOCK-----&#x20;

To export to a file, use either the "--output" or the ">" character methods outlined above.As a reminder, do not EVER share your private key with anyone. The only time you should be exporting your private key is when creating a back up.Importing a KeyTo encrypt a message for someone, you're going to need to import their public key. For this tutorial I will be importing the public key provided on Agora's help and info page. You are more than welcome to import the public key displayed earlier. To import a key from a file:gpg --import path/to/pubkey.asc where pubkey.asc is the file where you saved the public key you want to import. Here's the output you should receive:gpg: key (Expunged): public key "Agora One" imported gpg: Total number processed: 1 gpg: imported: 1 (RSA: 1) And that's it, you can now write messages using the key imported.The Fileless MethodTo import a key directly, without the use of a file, you can use either the "cat" command, or "echo" along with a pipe character "|".Using "cat":cat < You can now paste the public key block from your clipboard. Hit enter to move to the next blank line if you are not already there, and type "END."cat <\<END | gpg --import

> \-----BEGIN PGP PUBLIC KEY BLOCK----- _keyblock removed to reduce page length_ -----END PGP PUBLIC KEY BLOCK----- END Hit "Enter" once more and the command is completed. The output:gpg: key 0B701872: public key "Mun Mun Mun [munmunmun@mun.mun](mailto:munmunmun@mun.mun)" imported gpg: Total number processed: 1 gpg: imported: 1 (RSA: 1) To accomplish the same task using the "echo" command, the syntax is as follows:echo "" | gpg --import Note the use of the quotation marks. If you attempt to run the echo command without quotation or tick marks, bash will attempt to interpret each line of the key you paste as a command the second you paste it in. When using this method, I always use double quotes, as I have run into some random cases where single quotes (or ticks) caused unexpected behaviour.echo "-----BEGIN PGP PUBLIC KEY BLOCK----- _keyblock removed to reduce page length_ -----END PGP PUBLIC KEY BLOCK----- " | gpg --import The output is the same as the other methods:gpg: key 0B701872: public key "Mun Mun Mun [munmunmun@mun.mun](mailto:munmunmun@mun.mun)" imported gpg: Total number processed: 1 gpg: imported: 1 (RSA: 1)

_LINUX TIP_ The "echo" command allows the user to input a string, which is then sent to stdout. Just like in the cat example, the pipe character turns the output from the "ech"o command on the left into and input for the "gpg" command on the right.

## Encrypting a Message&#x20;

Once you have imported someone else's public key, you can encrypt a message. For this tutorial, I will use the text Hello World! and place it into file myMessage.txt . Now that we have a file with a message in it, enter the following command:

gpg --armor --output encMessage.asc --encrypt myMessage.txt where myMessage.txt is the name of the file you are encrypting. Throughout this tutorial, there has been use of other parameters before encrypting the message. Let's take a minute and examine the parameters set forth. Notice that we use --encrypt and then the file name to specify the file to encrypt, but there are a few other parameters not fully described.--armor tells the program to use ASCII armor, this makes GnuPG encrypt the data in the file so it can be copied and pasted via text characters.--output enables the user to specify a name and location of the output file, where encMessage.asc is the desired name of the output file.So once that command is input, the user will be prompted to enter a recipient. As seen earlier, the user ID for Agora was Agora One. So that is what I entered. Alternatively, the user's email can also be entered. After that, I simply hit enter to confirm no other recipients.This is what the console looked like:You did not specify a user ID. (you may use "-r")

Current recipients:

Enter the user ID. End with an empty line: Agora One gpg: (Expunged): There is no assurance this key belongs to the named user

pub (Expunged)/(Expunged) Agora One Primary key fingerprint: (Expunged) Subkey fingerprint: (Expunged)

It is NOT certain that the key belongs to the person named in the user ID. If you _really_ know what you are doing, you may answer the next question with yes.

Use this key anyway? (y/N) y

Current recipients: (Expunged)/(Expunged) "Agora One"

Enter the user ID. End with an empty line: I just added this key from agora, so I am well aware that it is the actual user ID, therefore I can trust it, and input y and preceded on. Needing no other recipients, I simply hit enter and let the program compile an encrypted message.Upon completion, the file encMessage.asc was generated. When opened with a text editor, the PGP message was shown. This is the message which I would send to the recipient, in this case it would be the Agora staff.The same task can be achieved without writing the output to a file by using the "cat" or "echo" command methods outlined above.Using cat:cat <\<END | gpg -ear Mun

> Hello World! END gpg: 32E3AC7F: There is no assurance this key belongs to the named user

pub 4096R/32E3AC7F 2018-09-07 Mun Mun Mun [munmunmun@mun.mun](mailto:munmunmun@mun.mun) Primary key fingerprint: 4EAD DF75 A81F 1903 303F C7B2 9479 D2AC 0B70 1872 Subkey fingerprint: 4378 37D6 13E4 3AED 0F25 CFA0 20BB 05A5 32E3 AC7F

It is NOT certain that the key belongs to the person named in the user ID. If you _really_ know what you are doing, you may answer the next question with yes.

Use this key anyway? (y/N) y -----BEGIN PGP MESSAGE-----

hQIMAyC7BaUy46x/ARAAmEmI28SlznRZG3e76AUWGHyeW+SwqQWfXGOljYBjHTLv 6nvV8+brrEIiIRGOT++s7jpTwYrowcP4h9EHNpId9vJ5bfGJUFPXcX3UPBkEG8Dt e8FVdJa4T11yk0pot96jbmVnHKVMbsFVoescIsrUD8+N3y+Gax/RrOEY16SlqG5p RBWChGLKwb04+KZWIwVRbrYwWU7Xiu/8A1T6tP/7CB7c9kegLrgusWWZ3evPLYcp gYgJpuZfK5jvfasHOU3KrF80fR71xkeSocrl3IRuGRwl+s1kqsOkX6II2vPsm8Ut 0xG7ySF1d6QLz1CJ3A4EV/n56rJVs1qAHx0B3OyMvwmMPoPHFiaiErfYqb7UnP73 EcvZNpD19mLgKdM7qrYtdUIvYBn6dTlt5yPiES87Fk5yTLWW+HeBBkLL+ZuI3mnF 0KUYVeuFBmGs96QhyZmKmnH/F0HDjECW0KnB+rZkFEXMzh3yHhoE5Du34UUHnUI0 GTDp854FWSMm8DTtCYtywx2YMS+FuglhytCjNfEmdoszg+SoH3K3xqR9O9FoZjFa q/TwhUPvTSM8sWkAEf37QhR6b52giaGItVK8RG50e813hW9ncINQDwF9a4kqZ5PS BMrK5bv3suPzcpOl+ZpsRDSofnjnWQK9HLHWBEyf5vGaHNLeG7iTIVjHa/igP4zS SAF9hMhPFa5rq+NsBuSlTF2oi0fazG1ctGR2HhL6WBRckroVwsZ4v3CKmuBuk69J AhSsJnbOT1hPmLPPU7FK6szH2dBumuOQuA== =DP51 -----END PGP MESSAGE-----&#x20;

_LINUX TIP_ Note that all of the longhand flags preceded by a double dash "--" (--encrypt, --armor, --recipient) can be shortened to single character flags preceded by a single dash "-" (-e, -a, -r). These single character flags can then be combined into one flag representing a combination of single character flags, -ear. Most commands have both short and longhand flags, which can be found using "\[command] --help" or by pulling up the command manual with "man \[command]" Be aware though, some programs have strict enforcement over the order of flags delivered. Check the help or manual pages for whatever program you are using for more information.Using echo:echo "Hello world" | gpg -ear Mun gpg: 32E3AC7F: There is no assurance this key belongs to the named user

pub 4096R/32E3AC7F 2018-09-07 Mun Mun Mun [munmunmun@mun.mun](mailto:munmunmun@mun.mun) Primary key fingerprint: 4EAD DF75 A81F 1903 303F C7B2 9479 D2AC 0B70 1872 Subkey fingerprint: 4378 37D6 13E4 3AED 0F25 CFA0 20BB 05A5 32E3 AC7F

It is NOT certain that the key belongs to the person named in the user ID. If you _really_ know what you are doing, you may answer the next question with yes.

Use this key anyway? (y/N) y -----BEGIN PGP MESSAGE-----

hQIMAyC7BaUy46x/AQ//W2FukPjZr51RWhtdVSkQWj7hGijey7dwwoVQvXP4wpBx H6rRiCTulwvBAA5IEG/fxQoDXw/k2KDI6IDaTwA277/tewZs0zXI7bUmY54Nh0mU RZMGfSjpU1CDjEAc85d9tdP6jKkunxFnIarjbJkLVjL71AUzRJqNbWZJDLObDmRj R2UfKuLGvtpRbrgsWUiLxXDRbcMb961y+x337So8FP38J6fUOldBj4JfljEt62r7 6cI+WJDDo5wr45uejNP8mqsEyDJz24rRgqoylhKLkyZbKOziryAlMy/Svk+KkwWN GHMI5h/2A619v1Ylj8zQakgdQ7Rq/LiK67ztO5VknAqWUTN1Fvky4TC/+MvkiWqw /PkzTgfXW7v8nAQs5ZFWNqUh/mvVtvKKllsTCxGOhnBwxRDO+RWq86pE693uQTzD WzjzfAOEkMtntnDMWUKtHX8jo/XWAESl6TDgyi3AGZYerA/mfNHmF+txRWlW4Hd0 pnDYjah+aKlA6Y4Mi/G4cn6C9nAf8K62JpnQx+6ze9L4/liVQFiyuBAdXWcVv66o EMQZMm8n+2T/Y62B5sNsJofK/yyIc9KhGjFcvNX89YHigfpCBVtR6qOR0YudrFNE 9Azoz/kfX+dYxPdNKr34R1125QRCJuwYhEPDiuYAr3E+IFAtRK0SZ08+pTQMQePS RwFtqXRS1vzv3rYpS7PF/7jHet8yCxNWfsSIce+nv6IcsHVYdry3ZkJh3rw5RoXy 1/t1ESI6kKZ6EFFAszF6hgnAQHNRMW2T =feuT -----END PGP MESSAGE-----&#x20;

Note that when using echo, you can use "SHIFT+ENTER" to jump to a new line. You might opt to type your messages in a more user-friendly text editor, and then paste them into the console if formatting is a concern.===Decrypting a message===So at this stage you can now generate your own keys, and send messages to others using their keys. The only thing left is to decrypt a message when a user messages you. This is the text Hello World! when encrypted using the WhatEverNameYouWant public key:-----BEGIN PGP MESSAGE----- Version: GnuPG v2

hQIMA0O56MNiiHV5AQ//WLFKdMBF0a5vuW9EoNbWvS656cPBvKHiEBT7ygtvHLfM DS7hDzp+F7gqImm3Ql3be5o+7QNHDIRWdEiZ2SR3NopHyRYHEA9k3G+d33qV/Ykz su8qqxUm7Y3UKtf2nKpY3jRPml5Stm8QtwaznARH6tPqzHCh69f7Uz40pwpbl53v kpTOKcjYAwI5rC/k4GNgGj3luhEgzha13j7VXDl9zaXK78NaBQCBqUUJbtPG3jmv vZRLvvgMPxbSuyyYPNbXoNkvImNfP4UdD4KSBRHq2LiSDkkyJqXZJ2ZrP7j3gE/4 rJ2hiUeJLQpDE51CEpGY0lfJIFz7JbIv+V3CNqkJOR/2TtqZhjkp4gLFgVPNpolf mVoTG0eOZjieP9d56cPVEW3uEpc4CvtqDHIRQeEBMgPVQeKTL+iTk8Zq02Bg6C0l 8ITh/ekhiweD5jBbC0to7PCHFMH4TJklnRrmzl2ykNzcB6RR1QJgk9EceE/vxYEB Y2FFqTUcbzZRi4hpCbfqgDZDgG9SbUgkDmWLV0OuQ/iGZJiu7wyI4KiXl9BSoY7q NrMjhvOBUNFIn7FoquxH9c+ETUFnchm9y9Cu3+RzA8eqqJF+sCrCXokLE/J6aRrW zq0FlK4lzpFMHSYWpt7CDJh5uIe6zxyzPDN2vUAbGAzW8mLaA5IEKLH2yHJehcrS VAHd/9l3vKzweZdugQVAloTBMdX06YZBlhuBQl19br1SGiFTk+TeiyykQCqrWHYt bDoXB1S9BX8ux8RRSi53Y9xVN0/EA5pYJpzx8geJ0NikFeAFSQ== =gL3V -----END PGP MESSAGE-----&#x20;

## Decrypting Messages

Decrypting this is a relatively painless and simple process. First I saved the message to a text file titled myEncMessage.asc. Once there I entered the following command:gpg --decrypt myEncMessage.asc where myEncMessage.asc is the name of the file with the message in it. This command will have it output the message into the console, if you want it to be placed into a file instead, use the following command:gpg --output myDecMessage.txt --decrypt myEncMessage.asc Where myDecMessage.txt is the name of the file to export the message to.Alternatively, you can direct the output by using a ">" character:gpg --decrypt myEncMessage.asc > myDecMessage.txt The decryption process requires accessing the private key; for this reason, you must provide the password you created when generating the keypair. During the process a prompt will appear, fill in the password and it will decrypt. Here is the output of the command with no output file specified:You need a passphrase to unlock the secret key for user: "WhatEverNameYouWant" 4096-bit RSA key, ID , created 2014-12-12 (main key ID)

gpg: encrypted with 4096-bit RSA key, ID , created 2014-12-12 "WhatEverNameYouWant" Hello World! Notice how a recipient is never specified, this is because the ciphertext can be linked to a key automatically. If the user has a message and the appropriate key to decipher it, GnuPG will find it on it's own.To decrypt a message without saving the ciphertext to a file, use the "cat" or "echo" methods outlined above:cat <\<END | gpg -d

> PASTE CIPHERTEXT HERE END ORecho "PASTE CIHPER TEXT HERE" | gpg -d

You may notice that I used the shorthand "-d" in place of --decrypt.

## PGP Signatures

Signatures and Verification When sending a message to someone, you know that only the person in control of that key will be able to read it, because they should be the only one with with the private key associated with the public key you encrypted to, and therefore are the only one able to decrypt the message. So how do we verify that a specific party wrote, sent, or posted a message? This is where signatures come in.

Signing messages is way for the originator of a message to prove that the message was created by them, assuming that they are in control of their key. They generate a signature hash around a message that can be verified by anyone with their public key.

There are three common scenarios for the use of clearsigning: 1). Establishing PGP key lineage. When your current key is set to expire, you might sign a message containing your new key with your old key. 2). Important announcements from administrators, developers, or vendors. 3). Proving account ownership.

### Clearsigning

Here are a few examples from opie\_ on clearsigning messages, keys, and verifying keys using the "cat" command. The same can be done using the "echo" method, or by saving text to files and reading or writing from the file.

cat <\<END | gpg --clearsign

> Hey! Ho! What's goodie? Swiggity Swootie, I'm coming for that booty! END Output:-----BEGIN PGP SIGNED MESSAGE----- Hash: SHA512

Hey! Ho! What's goodie? Swiggity Swootie, I'm coming for that booty! -----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEBHRN9HAfZ1F/IBCZMBbTaXgXIagFAlwFh7gACgkQMBbTaXgX IahW3g/+LIda/IPTcXqgG5sMbUjUe1Et3IHzc4GwxQUcnTa2HtPFNfQWZEe+AiPt uiZdz6E7+3npndK8ZEnwZCbt4k1+e++EozHKWObCyQUdfi3aY/79tsbCCJc76Bao S1dEiD6cRUTalsg61AbnrYucvA6a9xiLqyzjlWJolBRPOxj4LJi+iJtWcc83Jp8B Doec+Lfgo/IGO7u+CZj2IJ2kK1FGQIcWk4IqRiWTXIbYKo48QxpUqjOadnBfiJ7s CfF1EAo5qcffu3J+o/453FjChVOWTeKdSdchlksqcm/THS0KF4ZuKuI3J4lUHPRr KrB+InJyGq/7AF5x/AwqPnYUPmX9P12d+PYCEFMXif2X2yVRL5S2VROfSHU4TZRQ juAV+z4xJXNRskYl2ZbFOhTlu8OkpQfHcaliUfzZTCjDU4ZtLdzKq6bMOZ7A1NhL T19kOhJb/G61RPkiy13/S7Cp2cpD+0W25ce1E3GOXaRcUDJAGqToIXR2WbCgFgmW KvEzg8M55xOu4ssUkfDHEz9KTjGb375tNMTTkRs6BIFjKsfNvdG7ufgvRnMNWNHA xY/7qLB9ijrXqQ3CilgwxfnKLscFjoTuvrcXgsondIJnmyx77/57dgeNWx4MN6Zt Nzima96VFmGTuooE3QZb1eL84bSArilvrB8uCGCkDI35pQeevvg= =1VrI -----END PGP SIGNATURE-----&#x20;

You can also nest piped commands to clearsign and then encrypt a message or vise versa (just switch the placement of the two gpg commands to first encrypt and then sign):cat <\<END | gpg --clearsign | gpg -a -r opie\_ -e

This message will be clearsigned and then encrypted. Second line just because.&#x20;

END Output:-----BEGIN PGP MESSAGE-----

KEY DATA

&#x20;\-----END PGP MESSAGE-----&#x20;

Similarly one could also export and sign their public key with one fell swoop:gpg -a --export opie\_ | gpg --clearsign Output:-----BEGIN PGP SIGNED MESSAGE----- Hash: SHA512

\-----BEGIN PGP PUBLIC KEY BLOCK-----

KEY DATA

\-----END PGP PUBLIC KEY BLOCK-----

\-----BEGIN PGP SIGNATURE-----

SIGNATURE DATA

&#x20;\-----END PGP SIGNATURE-----&#x20;

### Verifying Signatures

What good are signatures if we can't verify them?cat <\<END | gpg --verify

> \-----BEGIN PGP SIGNED MESSAGE----- Hash: SHA512
>
> Hey! Ho! What's goodie? Swiggity Swootie, I'm coming for that booty! -----BEGIN PGP SIGNATURE-----
>
> iQIzBAEBCgAdFiEEBHRN9HAfZ1F/IBCZMBbTaXgXIagFAlwFizIACgkQMBbTaXgX IaiWCBAAmq4vnbHex+6JTuFHYyuhZeoyOQNamBUP1IJqiu1tDYrjAsWPrQdjoZdw kDNE4asN//Y4lnxlbOwKeBFLM+NdIQui2/3ppbWENp9igGXTk8H7ZCOzH/OHgLTi rjZgtVdSVMrWQJKjqeiU7Kr/RvmBk3Gbdy7kUysW9LkfQ1Tu+Bg2NODvMbQoZ2cN SCHs+6rskRNbbKzq/TE2EQCYOubuAwj7tgssVH9ZNlIlDr4z8bxAy1iYF+lzJXG3 UFQldoDZ4d8fqagEVh5PEfHbEy3Wn4ldXgmDcTTDLu1MEnkO7Jy/sxRklMff+lFZ SvKyNnYf/9kyo9KR56KxwmESQPru4cxrXl9KDLly/OyrWFQ27fZRyNg8dZMNuZi2 46pmDFqoCJ/sAp2K97aJKU1PctLy2pnbc4CIIrN0eDhWkV5zOtuLBOtIdgG/ug57 IOG/yTKpUvedOil7J954RI4QEGBgVRufsCLabV3H1S8R1X9UfEWjEnpBZ3tlbY15 KGUptCZ5wjtv8IJPcX25REYBq6xCI7XNiup7YOXDhNpmlKCJMTXDP9A9zn/Q2Vjh Meztnx5P9K51tkhCrj0f43CMyeGV561GuaHBKuXNC9DxO5XPBURcHhIxWE3fJyCP B8rC+4gqItY0bvgqcyYRYDy2+qMirEiUl+mlxgJWFQsPRWLgsvM= =eSMz -----END PGP SIGNATURE----- END Output:gpg:&#x20;
>
> Signature made Mon 03 Dec 2018 02:59:46 PM EST gpg: using RSA key 04744DF4701F67517F2010993016D369781721A8 gpg: Good signature from "opie\_ [opie@tt3j2x4k5ycaa5zt.onion](mailto:opie@tt3j2x4k5ycaa5zt.onion)" \[ultimate]
>
> &#x20;Note that if any of the text in the message is changed after the signature is made, it will NOT verify as a "good" signature.cat&#x20;
>
> <\<END | gpg --verify -----BEGIN PGP SIGNED MESSAGE----- Hash: SHA512
>
> Hey! Ho! What's goodie? Swiggity Swootie, I'm coming for that booty!
>
> Make sure to send your bitcoins to:&#x20;
>
> \-----BEGIN PGP SIGNATURE-----
>
> iQIzBAEBCgAdFiEEBHRN9HAfZ1F/IBCZMBbTaXgXIagFAlwFizIACgkQMBbTaXgX IaiWCBAAmq4vnbHex+6JTuFHYyuhZeoyOQNamBUP1IJqiu1tDYrjAsWPrQdjoZdw kDNE4asN//Y4lnxlbOwKeBFLM+NdIQui2/3ppbWENp9igGXTk8H7ZCOzH/OHgLTi rjZgtVdSVMrWQJKjqeiU7Kr/RvmBk3Gbdy7kUysW9LkfQ1Tu+Bg2NODvMbQoZ2cN SCHs+6rskRNbbKzq/TE2EQCYOubuAwj7tgssVH9ZNlIlDr4z8bxAy1iYF+lzJXG3 UFQldoDZ4d8fqagEVh5PEfHbEy3Wn4ldXgmDcTTDLu1MEnkO7Jy/sxRklMff+lFZ SvKyNnYf/9kyo9KR56KxwmESQPru4cxrXl9KDLly/OyrWFQ27fZRyNg8dZMNuZi2 46pmDFqoCJ/sAp2K97aJKU1PctLy2pnbc4CIIrN0eDhWkV5zOtuLBOtIdgG/ug57 IOG/yTKpUvedOil7J954RI4QEGBgVRufsCLabV3H1S8R1X9UfEWjEnpBZ3tlbY15 KGUptCZ5wjtv8IJPcX25REYBq6xCI7XNiup7YOXDhNpmlKCJMTXDP9A9zn/Q2Vjh Meztnx5P9K51tkhCrj0f43CMyeGV561GuaHBKuXNC9DxO5XPBURcHhIxWE3fJyCP B8rC+4gqItY0bvgqcyYRYDy2+qMirEiUl+mlxgJWFQsPRWLgsvM= =eSMz -----END PGP SIGNATURE----- END Outputgpg: Signature made Mon 03 Dec 2018 02:59:46 PM EST gpg: using RSA key 04744DF4701F67517F2010993016D369781721A8 gpg: BAD signature from "opie\_ [opie@tt3j2x4k5ycaa5zt.onion](mailto:opie@tt3j2x4k5ycaa5zt.onion)" \[ultimate]

## Tails with PGP

Let's learn how to use PGP within Tails. First thing you are going to want to do is create your own personal key, which consists of your public key that you can give out to people or post in your profiles online. As mentioned before, this is the key people use to encrypt messages to send to you. Your personal key also consists of your private key which you can use to decrypt messages that are encrypted using your PGP public key. If you look up to the top right area, you will see a list of icons, and one o them looks like a clipboard. You need to click on that clipboard and click Manage Keys Next click File ­> New Select PGP Key and click Continue Fill out your full name (I suggest you use your online name, not your real name) Optionally fill out an email and a comment as well. Next, click Advanced Key Options. Make sure Encryption type is set to RSA and set key strength to 4096. Once you have done this, click Create and it will generate your key. Once you have done this, you can view your personal key by clicking the tab My Personal Keys. You have now created your personal key! To find your PGP public key, you Right click on your personal key and click Copy and it will copy your PGP public key to your clipboard, in which you can paste anywhere you wish. Next, you are going to want to save the private key on a secondary USB drive or SD card. If you are running Tails from a USB drive, then you must use a separate drive to store your key on. If you are running Virtual Box, you want to right click on the icon in the bottom right corner that looks like a USB drive, and select your separate drive that you will be using to store your keys on. Again, never store your private keys on your hard drive, keep them OFF your computer. To save your private key, you are going to right click on your personal key and click Properties. I know you probably saw where it says Export, but this is not what you want to do. Clicking export will ONLY export your public key and will not save your private key. If you lose your private key, you can never recover it even if you create another personal key using the exact same password. Each private key is unique to the time it was created and if lost, is lost forever. So once you have clicked Properties, go over to the tab Details and click Export Complete Key. Once you have done this, you have saved your personal key for future use once you restart Tails. Remembering that Tails is not installed on your hard drive, so every time you restart Tails you lose all your keys. By saving your keys onto a USB drive or SD card, you can import your keys for use every time you restart it. Next you are going to want to learn how to encrypt and decrypt messages using your key. Well, luckily for me, Tails has already made a tutorial on how to do this, so I will refer you to their webpage. But before I do that, I need to mention that you need to find somebody else's PGP public key, or you can practice by using your own. Needless to say, the way you import other people's keys into what's called your key ring is by loading them into a text file. You do this with the program called gedit Text Editor. Click Applications ­> Accessories ­> gedit Text Editor and enter in someone's public key and hit save. Next you can return to your key program from the clipboard icon and click File ­> Import and select that file. It will import that person's public key into your key ring. To add future public keys to your key ring, I suggest reopening the same file and just adding the next key below the previous key and each time you open that file it will load all keys within that file. This way you can keep all the PGP public keys together in one file and save it on your SD card or USB drive for future use. Finally you can use the following 2 pages to learn how to encrypt and decrypt messages using PGP.&#x20;

hxxps://tails.boum.org/doc/encryption\_and\_privacy/gpgapplet/public­key\_cryptography/index.en.html&#x20;

hxxps://tails.boum.org/doc/encryption\_and\_privacy/gpgapplet/decrypt\_verify/index.en.html
