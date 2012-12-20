## 0.0.6 (Dec 19, 2012)

Bugfixes:

- fixed test_helper require that was broken in ruby 1.9.2

Features:

- Created this changelog

- Added load_pubkey method to auth_keys class that restricts
the attributes that can be set by a pubkey.

- Reworked load_raw_line in auth_keys class to accept optional
array of attributes to be set, ignoring all other attributes
not listed.

## 0.0.5 (Nov 9, 2012)

Bugfixes:

- fixed bug that prevented documentation generation by rubygems

## 0.0.4 (Nov 8, 2012)

Features:

- Added additional unit tests and documentation

## 0.0.3 (Nov 1, 2012)

Features:

- Added additional unit tests and documentation

## 0.0.2 (Oct 30, 2012)

Features:

- Added unit tests
- Added error class for auth_keys validation errors

## 0.0.1 (Oct 24, 2012)

Features:

- Initial commit
