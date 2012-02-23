# Lithium Intrusion Detection System Library

Lithium library for Intrusion Detection [PHPIDS](http://phpids.org/).

PHPIDS Spec version: `0.7`

## Installation

Add a submodule to your li3 libraries:

	git submodule add git@github.com:bruensicke/li3_ids.git libraries/li3_ids

and activate it in you app (config/bootstrap/libraries.php), of course:

	Libraries::add('li3_ids');

Also, make sure, that you give write access to the ids tmp path. which is

	chmod -R 0777 li3_ids/libraries/phpids/lib/IDS/tmp

In upcoming releases we try to write directly to `app/resources/tmp`

## Usage

To have a look at what is going on, have a look into your `logs` folder

	tail -f resources/tmp/warning.log

## Credits

This plugin is kindly provided by weluse GmbH. Thanks for that.

more Features will follow soon.

Ideas:

- Database Logging
- MailService
- ImpactLevel mapping to Log-Levels
