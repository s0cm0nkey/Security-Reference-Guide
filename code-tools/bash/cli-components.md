# CLI Components

Use this page as a quick reference for shell operators, streams, and redirection.

## Common Operators

* `&&` - Run the second command only if the first command succeeds.
  * Example: `mkdir reports && cd reports`
* `||` - Run the second command only if the first command fails.
  * Example: `grep "needle" file.txt || echo "not found"`
* `;` - Run the next command regardless of whether the previous command succeeds.
  * Example: `whoami; hostname`
* `|` - Pipe standard output from one command into the next command.
  * Example: `ps -ef | grep ssh`
* `&` - Run the command in the background.
  * Example: `sleep 60 &`
* `>` - Redirect standard output to a file, overwriting the file.
  * Example: `date > run.log`
* `>>` - Append standard output to a file.
  * Example: `date >> run.log`
* `<` - Read command input from a file.
  * Example: `sort < names.txt`

## Streams

* `stdin` - Standard input, usually data going into the program.
* `stdout` - Standard output, usually normal command output.
* `stderr` - Standard error, usually errors and diagnostic messages.

## Stream Redirection

* `2>` - Redirect errors to a file.
  * Example: `grep needle missing.txt 2> errors.log`
* `2>&1` - Send errors to the same place as standard output.
  * Example: `command > output.log 2>&1`
* `/dev/null` - Discard output.
  * Example: `command > /dev/null 2>&1`
