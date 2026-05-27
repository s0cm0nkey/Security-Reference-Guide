# Regex

Regular expressions search for text patterns. They are useful for log analysis, scripting, validation, parsing, and detection engineering, but each tool or language may use a slightly different regex engine.

## Regex Tools and Reference

### Testers

* [Regex101](https://regex101.com/) - Regex tester and debugger for PCRE, PHP, Python, Go, JavaScript, and more.
* [RegExr](https://regexr.com/) - Interactive regex builder and tester.
* [RegEx Testing](https://www.regextester.com/) - Online regex testing tool.
* [RegEx Pal](https://www.regexpal.com/) - Online regex testing tool.
* [CyberChef](https://gchq.github.io/CyberChef/) - Includes regex operations alongside encoding, decoding, and data transformation tools.

### Training

* [RegexOne](https://regexone.com/) - Introductory regular expression lessons.
* [RexEgg](https://www.rexegg.com/) - Detailed regex reference and tutorial site.
* [Regex Crossword](https://regexcrossword.com/) - Regex practice through puzzles.
* [The 30 Minute Regex Tutorial](https://www.codeproject.com/Articles/9099/The-30-Minute-Regex-Tutorial) - Jim Hollenhorst.
* [TryHackMe: Cat Regex](https://tryhackme.com/room/catregex)

### Cheatsheets and Books

* [Regular Expression Cheat Sheet](https://github.com/niklongstone/regular-expression-cheat-sheet)
* [i Hate Regex](https://ihateregex.io/)
* [JavaScript RegExp](https://learnbyexample.github.io/learn_js_regexp/) - Sundeep Agarwal.
* [Python re(gex)?](https://learnbyexample.github.io/py_regular_expressions/) - Sundeep Agarwal.
* [Regular Expressions for Regular Folk](https://refrf.shreyasminocha.me/)
* [Ruby Regexp](https://learnbyexample.github.io/Ruby_Regexp/) - Sundeep Agarwal.
* [The Bastards Book of Regular Expressions](https://leanpub.com/bastards-regexes) - Dan Nguyen.

## Basics

### Common Character Classes

| Pattern | Meaning |
| --- | --- |
| `\d` | Any digit |
| `\D` | Any non-digit |
| `\w` | Any word character, usually letters, digits, and underscore |
| `\W` | Any non-word character |
| `\s` | Any whitespace character |
| `\S` | Any non-whitespace character |
| `\t` | Tab |
| `\r` | Carriage return |
| `\n` | Newline |

### Character Groups

Square brackets define a set or range of characters.

* `[ce]` matches `c` or `e`.
* `[c-e]` matches `c`, `d`, or `e`.
* `[^abc]` matches any character except `a`, `b`, or `c`.

### Escapes

Regex metacharacters such as `.`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `|`, `^`, `$`, and `\` need escaping when you want to match them literally.

```text
\.example\.com
```

### Repetition

| Pattern | Meaning |
| --- | --- |
| `*` | Zero or more of the previous token |
| `+` | One or more of the previous token |
| `?` | Zero or one of the previous token |
| `{m}` | Exactly `m` repetitions |
| `{m,n}` | Between `m` and `n` repetitions |

By default, quantifiers are greedy. Adding `?` makes many quantifiers lazy.

* `.*` - Greedy match.
* `.*?` - Lazy match.

### Anchors

| Pattern | Meaning |
| --- | --- |
| `^` | Start of line or string |
| `$` | End of line or string |
| `\b` | Word boundary |

Example:

```text
^abc\b.*123$
```

This matches a line that starts with `abc` as a whole word and ends with `123`.

### Captures

Parentheses capture part of a matched pattern. Captures are useful for extraction and replacement.

```bash
sed -rn 's/.*(capture).*/\1/p' file_name.txt
```

In `grep`, `-o` prints only the matched portion:

```bash
grep -Po 'user=\K[^ ]+' auth.log
```

### Lookarounds

Lookarounds are zero-width assertions. They match based on surrounding text without consuming that text.

| Pattern | Meaning |
| --- | --- |
| `(?=regex)` | Positive lookahead |
| `(?!regex)` | Negative lookahead |
| `(?<=regex)` | Positive lookbehind |
| `(?<!regex)` | Negative lookbehind |

Example:

```text
(?<![0-2])a
```

This matches `a` when it is not preceded by `0`, `1`, or `2`.

## Regex in Linux Tools

### grep

```bash
grep -P "regex" input_file
```

### awk

```bash
awk '/regex-pattern/{print $0}' input-file > output-file
```

### sed

```bash
sed -rn '/regex-pattern/p' input-file
```

### rg

```bash
rg "regex-pattern"
```

* [ripgrep](https://github.com/BurntSushi/ripgrep) is a fast line-oriented search tool that recursively searches directories.

## Regex in Java

* [Java Pattern Class](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/regex/Pattern.html)

## Regex in JavaScript

JavaScript regexes can be created with a literal or the `RegExp` constructor.

```javascript
const literal = /my_regex_pattern/gi;
const constructed = new RegExp("my_regex_pattern", "gi");
```

Common flags:

| Flag | Meaning |
| --- | --- |
| `g` | Global search |
| `i` | Case-insensitive search |
| `m` | Multi-line search |
| `s` | Dot matches newline |

Common methods:

| Method | Action |
| --- | --- |
| `match()` | Returns matches from a string |
| `replace()` | Replaces matching text |
| `search()` | Returns the index of the first match |
| `test()` | Returns true or false for whether a match exists |
| `exec()` | Returns match details from a regex object |

Example:

```javascript
const myIndex = "abracadabra".search(/ra/gi);
```

## Regex in Python

Python's built-in `re` module supports regular expressions.

```python
import re

my_list = re.split(r"\d", "one: 1 two: 2 three: 3")
```

Common functions:

| Function | Action |
| --- | --- |
| `findall()` | Returns all matches |
| `search()` | Returns a match object if the pattern matches anywhere |
| `split()` | Splits a string at each match |
| `sub()` | Replaces matches |
