# Regex

## Regex Tools and Reference

Regular expressions allow us to search for patterns in datasets and are processed by regular expression engines – pieces of software which match strings to a given pattern.For example, a search pattern with a sequence **`a1\d`** would find any sequence of characters, or string, in which the letter `a` is followed by a `1` and then any digit. Here, the **`\d`** is a metacharacter that tells the regex engine to search for any digit.

* Regex Testers
  * [RegExr](https://regexr.com/) - Learn, Build, & Test RegEx&#x20;
  * [RegEx Testing](https://www.regextester.com/) - online regex testing tool.
  * [RegEx Pal](https://www.regexpal.com/) - online regex testing tool + other tools.
  * [Pyrexp](https://pythonium.net/regex) - online visual regex testing tool.
* Regex Training Material
  * [RegexOne](https://regexone.com/) - Learn Regular Expressions - Lesson 1: An Introduction, and the ABCs&#x20;
  * [Regex101](https://regex101.com/) - Online regex tester and debugger: PHP, PCRE, Python, Golang and JavaScript&#x20;
  * [RexEgg](http://www.rexegg.com)
  * [https://regexcrossword.com/](https://regexcrossword.com/) - Fun regex training with a crossword.
  * [The 30 Minute Regex Tutorial](http://www.codeproject.com/Articles/9099/The-Minute-Regex-Tutorial) - Jim Hollenhorst
  * [https://tryhackme.com/room/catregex](https://tryhackme.com/room/catregex)
* Books, Articles, and Cheatsheets
  * [Regular Expression Cheat Sheet](https://github.com/niklongstone/regular-expression-cheat-sheet)
  * [i Hate Regex - The Regex Cheat Sheet](https://ihateregex.io/)
  * [JavaScript RegExp](https://learnbyexample.github.io/learn\_js\_regexp/) - Sundeep Agarwal
  * [Python re(gex)?](https://learnbyexample.github.io/py\_regular\_expressions/) - Sundeep Agarwal
  * [Regular Expressions for Regular Folk](https://refrf.shreyasminocha.me) - Shreyas Minocha
  * [Ruby Regexp](https://learnbyexample.github.io/Ruby\_Regexp/) - Sundeep Agarwal
  * [The Bastards Book of Regular Expressions: Finding Patterns in Everyday Text](https://leanpub.com/bastards-regexes) - Dan Nguyen _(Leanpub account or valid email r_equested)

## Basics

### Metacharacters

◇ **`\s`** – this represents any whitespace character, such as a tab, space, or carriage return.\
◇ **`\w`** – this tells the regex engine to search for any alphanumeric character.\
◇  – this represents a carriage return.

### Grep and Regex

◇ `grep -P "`**`regex`**`" input_file`

### Special character sequences

These normally consist of a backslash, **`\`**, followed by a letter and represent either non-printable characters or entire categories of ASCII characters.\
Here are some examples:\
• **`\d`** – this represents any digit\
• **`\w`** – this represents any alphanumeric character\
• **`\s`** – this represents any whitespace character\
• **–** this represents a tab\
The first three examples can capture the reverse group through capitalisation, such that **`\D`**, **`\W`**, and **`\S`** represent any non-digit, non-alphanumeric, or non-whitespace character respectively.

### Groupings

Groupings are made using the square brackets, **`[`** and **`]`**. They are used to represent specified sets of characters and can therefore be more precise than special character sequences. Within a grouping, individual characters or a range of characters can be specified. Ranges are specified using a hyphen, **`-`**.

The regex pattern **`[ce]`** would match any instances of the letters `c` or `e`, whereas the pattern **`[c-e]`** would match instances of `c`, `d`, or `e`.

Multiple individual characters or ranges of characters can be specified within the same grouping, and their order does not matter. For example, the pattern **`[dt-v9]`** would match instances of `d`, `t`, `u`, `v`, or `9`.&#x20;

### Escapes

You can see above that the backslash or square brackets are not used as their literal characters in regex; nor are any of the other metacharacters. But what if you want to search for square brackets, or periods in a string? Well, this is where escape characters are required.

Usually, a metacharacter can be escaped using a backslash, **`\`**. In some cases, when escaping certain metacharacters, it is necessary to change the syntax of the command within which the regex is used. This is because the backslash escape character is not exclusive to regex and can affect, for example, the quotes that encapsulate command arguments. An example of this can be seen in the video below, with the grep command.

### Tips

Pipe the output of your search to the word count command, `wc -l`, to quickly count the number of results returned.\
Print a line until a specific character (-)\
`$ sed 's/-[^-]*$//' file`

## Using regex in Linux

While grep can use regex to search files for patterns, it is not the only command capable of utilising this powerful searching tool.

The awk command can utilise regex to search files for a specified pattern and then perform a specified action on the search results. The basic usage of regex in awk is as follows:\
`awk ‘/regex-pattern/{print $0}’ input-file > output-file`

You can use the sed command with regex to perform more comprehensive searching. It is capable of searching for files and manipulating them within a single command. The basic syntax to use regex with the sed command is as follows: `sed -rn ‘/regex-pattern/p’`

### Repetitions

Repetitions, denoted by **`*`**, **`+`**, or **`{}`**, can be used when the number of characters of a certain type in a desired search string is unknown. The appropriate repetition metacharacter is placed immediately after the character or grouping which is repeated.\
◇ **`*`**     – Zero or more repetitions of the previous character or grouping.\
◇ **`+`**     – One or more repetitions.\
◇ **`{m}`**  – ‘m’ repetitions.\
◇ **`{m,n}`** – Between ‘m’ and ‘n’ (inclusive) repetitions.\
Repetitions can provide a level of optionality to your search pattern. For example, in the search pattern **`.*abc`**, the user does not care which characters, if any, appear before the string `abc`.

### Logical operators

Logical operators enable the AND, OR, and NOT logic functions within a search pattern.

* NOT
  * The caret **`^`** can denote a NOT logic function within a set or POSIX character class. Not to be confused with the use of the caret as an anchor, it is used as follows:
    * **`[^abc]`** or **`[^[:alnum:]]`**
  * These would match any character except `a`, `b`, or `c`, or any character which is non-alphanumeric respectively.
* OR
  * The pipe **`|`** denotes an OR logic function and is used within parentheses. Parentheses containing an OR pipe still define a capture group.
    * **`(abc|def)`** matches and captures `abc` or `def`.
  * The **`?`** question mark denotes optionality of the previous token.\
    **`files?`** matches `file` or `files`.
* AND
  * While the AND logic function is inherent in regex for sequential characters in a search pattern, there are cases where you may want to match a string which contains both one pattern and another.
  * This can be easily done by chaining multiple commands in sed, awk, or grep. However, many regex engines, including the Perl regex engine used by grep, introduce the **`(?=)`** positive lookahead so that you can perform the same task in a single command.
  * The positive lookahead matches the regex pattern before the opening parentheses if the pattern before is followed by the characters within the parentheses. For example, **`He(?=llo)`** would match the `He` in `Hello` but not in `Hey`.
  * By placing the lookahead at the start of your search pattern and using the **`.*`** wildcard within the lookahead, you tell the regex engine to match any line which contains zero or more repetitions of any characters followed by the remaining characters within the lookahead.
  * You can see for yourself that the following two commands produce the same result.\
    ▪ `grep -P "[pP]" Countries.txt | grep -P “[cC]”`\
    ▪ `grep -P "(?=.*[pP])(?=.*[cC])" Countries.txt`

### Captures

Parentheses can be used in regular expressions to capture part of a matched pattern. This can then be used for a range of purposes, including 'Find and Replace' functions. While true regex captures require more complicated syntax within the grep and awk commands, they can be written in sed using the following format:\
`sed -rn ‘s/.*(capture).*/\1/p' file_name.txt`\
This command replaces the entirety of the matched string with the string inside the capturing parentheses.\
In grep, an additional `-o` flag can be passed to only output the exactly matched text so that a carefully constructed regex can be used to create an equivalent output to a regex capture. When doing this, it is often necessary to use anchors or specifically exclude the characters which surround the desired region.

### Anchors

Anchors are used in a search pattern to match positions.

The caret `^` anchor matches the start of a line and the dollar sign **`$`** anchor matches the end a line.

The boundary **`\b`** special character sequence is an anchor used to match word boundaries, often to perform searches for whole words only. It matches the position between a 'word character' and a ‘non-word character’. In most flavours of regex, a word character is simply any alphanumeric. For example, the search pattern **`^abc\b.*123$`** will match any line that starts with `abc` and a non-alphanumeric character, has any characters in the middle, and ends in `123`.

## Regex in Java

* [https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html](https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html)

## Regex in JavaScript

\
In JavaScript, regexes can be created either by calling the constructor function of the RegExp object, or by using a regex literal, as follows:

* Constructor function
  * `var my_regex_variable = new RegExp(/my_regex_pattern/flags);`
* Regex literal
  * `var my_regex_variable = /my_regex_pattern/flags;`
* Flags can be passed to the regex for additional functionality, affecting how and what the regex matches in a string. Below are some examples:
  * g – Global search, so the method using the regex will act on all matches within the string, not just the first match.
  * i – Case-insensitive search.
  * m – Multi-line search; by default regexes separate strings by line breaks.
  * s – The dot **`.`** wildcard matches newline characters; it does not match these by default.
* For example, `var my_regex = /`**`abc`**`/gi;` will look for all instances of the string ‘abc’ and be case-insensitive, so will also match ‘aBc’.
* To use a regex in JavaScript, it must be paired with a method which supports regular expressions. The `match()`, `replace()`, or `search()` methods can be called on a String object. Alternatively, the `test()` or `exec()` methods can be called on a RegExp object.

| Method    | Action                                                                                                                                                                   |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| match()   | Returns either an array of the first match, the captured substring, the index and the input, or, if it is told to match globally, an array of all matches in the string. |
| replace() | Searches for a match and replaces the matched substring with a replacement substring. You can use $n to refer to the nth capture group in the regex.                     |
| search()  | Returns the index of the first match found or determines that no match exists.                                                                                           |
| test()    | Returns true or false for if a match exists.                                                                                                                             |
| exec()    | Returns an array including the first match, the captured substring, the index of the match and the input.                                                                |

For example, the JavaScript code in the panel below will assign the index of the matched substring, ‘2’, to the `my_index` variable.

View and execute the 'regex\_methods.js' script to see how these methods function.

`var my_index = “abracadabra”.search(/Ra/gi);`

## Regex in Python

\
◇ Python has a built-in module called 're' which must be imported in the script and can be used to work with Perl-based regex.\
◇ Unlike in JavaScript, regexes in Python are not created as objects but given as an argument to functions of the 're' module.&#x20;

| Function  | Action                                                               |
| --------- | -------------------------------------------------------------------- |
| findall() | Returns a list containing all matches.                               |
| search()  | Returns a ‘Match’ object if there is a match anywhere in the string. |
| split()   | Returns a list where the string has been split at each match.        |
| sub()     | Replaces one or many matches within a string.                        |

◇ A regex pattern can be specified as an argument to the functions using the syntax `r'`**`pattern`**`'`, or alternatively, a simple string can be used.\
◇ For example, the Python code in the panel below will assign the list of split substrings, `['one: ‘, ’two: ‘, ’three: ‘, ’']`, to the `my_list` variable.\
◇ View and execute the 're\_functions.py' script to see how these functions work.\
▪ `my_list = re.split(r'\d', “one: 1 two: 2 three: 3”)`

### Lookarounds

Lookarounds are regex assertions which match characters in a string based on the surrounding characters. There are four kinds:\
**`(?=regex)`** Positive lookahead\
**`(?!regex)`** Negative lookahead\
**`(?<=regex)`** Positive lookbehind\
**`(?<!regex)`** Negative lookbehind\
\
◇ Positive and negative lookaheads match the regex characters before the parentheses if they are, or are not, respectively followed by the characters within the lookahead. Positive and negative lookbehinds match the regex characters after the parentheses if they are, or are not, respectively preceded by the characters within the lookbehind. \
◇ For example, **`(?<![0-2])a`** will match any occurrence of the letter ‘a’ which is not preceded by the numbers ‘0’, ‘1’, or ‘2’.
