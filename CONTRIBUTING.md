Contributing Guidelines
=======================

Table of Contents
-----------------

<!--lint disable list-item-spacing-->

- [Testing](#testing)
- [Coding Style](#coding-style)
  - [PHPDoc](#phpdoc)
- [Commit Message Guidelines](#commit-message-guidelines)
  - [Message Header](#message-header)
    - [Subject](#subject)
    - [Type](#type)
    - [Scope](#scope)
    - [Revert](#revert)
  - [Message Body](#message-body)
  - [Message Footer](#message-footer)
    - [Referencing Issues](#referencing-issues)
  - [Example Commit Messages](#example-commit-messages)
- [Development Tasks CLI Commands](#development-tasks-cli-commands)
- [Version Bump and Changelog](#version-bump-and-changelog)
- [Git Hooks](#git-hooks)
  - [Installing Hooks](#installing-hooks)

<!--lint enable list-item-spacing-->

Testing
-------

This project uses [PHPUnit](https://phpunit.de) for unit testing. The tests are
usually in a Behavior-Driven Development (BDD) style.

To run all tests, use the following command.
```shell
"vendor/bin/phpunit"
```

Coding Style
------------

This project follows the [PSR-2 Coding Style
Guide](https://www.php-fig.org/psr/psr-2/) for PHP code.
[PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer) is used to
make sure the PHP code adheres to PSR-2. Use the `php artisan lint` command to
find and report coding style errors and warnings in PHP files.

### PHPDoc

This project uses
[PHPDoc](https://docs.phpdoc.org/references/phpdoc/index.html). Below is an
example of a valid documentation block. Note that the `@param` attribute is
followed by two spaces, the argument type, two more spaces, and finally the
variable name:

```php
/**
 * Register a binding with the container.
 *
 * @param  string|array  $abstract
 * @param  \Closure|string|null  $concrete
 * @param  bool  $shared
 * @return void
 */
public function bind($abstract, $concrete = null, $shared = false)
{
    //
}
```

Commit Message Guidelines
-------------------------

The commit message guidelines are based on
[Karma's commit message guidelines](http://karma-runner.github.io/1.0/dev/git-commit-msg.html)
and [AngularJS commit message guidelines](https://github.com/angular/angular/blob/master/CONTRIBUTING.md).

Each commit message consists of a **header**, a **body** and a **footer**. The
header has a special format that includes a **type**, a **scope** and a
**subject**:

```text
<type>(<scope>): <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

### Message Header

The `<header>` is the first line of the message and is mandatory, and the
`<scope>` of the `<header>` is optional. The `<header>` cannot be longer than
**70** characters.

#### Subject
The `<subject>` contains succinct description of the change:

- Use the imperative, present tense: "change" not "changed" nor "changes"
- Don't capitalize the first letter
- No period (.) at the end

#### Type
The `<type>` must be one of the following:

<!--lint disable list-item-spacing-->

- **build**: Changes that affect the build system or external dependencies
  (example scopes: composer, gulp, broccoli, npm)
- **ci**: Changes to our CI configuration files and scripts (example scopes:
  Travis, Circle, BrowserStack, SauceLabs)
- **docs**: Documentation only changes
- **feat**: A new feature
- **fix**: A bug fix
- **perf**: A code change that improves performance
- **security**: A code change that improves security
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **style**: Changes that do not affect the meaning of the code (white-space,
  formatting, missing semi-colons, etc.)
- **test**: Adding missing tests or correcting existing tests
- **chore**: Updating configuration files etc.; no production code change

<!--lint enable list-item-spacing-->

#### Scope

The `<scope>` generally should refer to the component that was affected.
However, the `<scope>` can be empty (e.g. if the change is a global or difficult
to assign to a single component), in which case the parentheses are omitted.

#### Revert

If the commit reverts a previous commit, it should begin with `revert: `,
followed by the header of the reverted commit. In the body it should say:
`This reverts commit <hash>.`, where the hash is the SHA (at least the first 8
characters) of the commit being reverted.

### Message Body

- Must use the imperative, present tense: "change" not "changed" nor "changes"
- Should include motivation for the change and contrasts with previous behavior
- Should be wrapped at **80** characters

For more info about message body, see:
- <http://365git.tumblr.com/post/3308646748/writing-git-commit-messages>
- <http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html>

### Message Footer

Like the `<body>` the `<footer>` should be wrapped at **80** characters.

#### Referencing Issues

Closed issues should be listed on a separate line in the `<footer>` prefixed
with "Closes" keyword like this:

```text
Closes #234
```

or in the case of multiple issues:

```text
Closes #123, #245, #992
```

### Example Commit Messages

```text
fix(middleware): ensure Range headers adhere more closely to RFC 2616

Add one new dependency, use `range-parser` (Express dependency) to compute
range. It is more well-tested in the wild.

Fixes #2310
```

```text
docs(changelog): update change log to beta.5
```

```text
fix(release): need to depend on latest rxjs and zone.js

The version in our package.json gets copied to the one we publish, and users
need the latest of these.
```

Development Tasks CLI Commands
------------------------------

CLI commands for development and deployment tasks are handled by
[Robo](https://robo.li/). Use the following command to get a list of available
Robo commands and their descriptions.
```shell
"./vendor/bin/robo"
```

Version Bump and Changelog
--------------------------

The version is bumped automatically and the `CHANGELOG.md` file is generated
from the commit messages using [development task CLI commands](#development-tasks-cli-commands).
Installing the [Standard Version](https://github.com/conventional-changelog/standard-version),
Node/NPM package is required to bump the version and generate the `CHANGELOG.md`
file successfully.

Git Hooks
---------

The Git hook scripts are stored in the `bin/hooks` directory. Each of the hook
scripts execute their corresponding Artisan `git:hook-*` command. For example,
the `bin/hooks/pre-commit` hook script executes
`"./vendor/bin/robo" git:hook-pre-commit`. This allows the hook logic to be
written in PHP and handled by Robo, which is compatible with Windows, Mac OS,
and \*nix systems.

### Installing Hooks

To install the hooks run the following command:
```shell
git config core.hooksPath ./bin/hooks
```
