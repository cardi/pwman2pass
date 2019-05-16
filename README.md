# pwman2pass

**pwman2pass.py** converts your [pwman][pwman] database to files in the
[pass][pass] folder hierarchy (typically `~/.password-store`).

## dependencies

* python2.7
* gpg
* [pass][pass]

## usage

pwman2pass.py takes in an unencrypted pwman database via filename or
standard input (`STDIN`) and directly uses `pass' to import:

```bash
# convert an already decrypted pwman db
pwman2pass pwman.db.plaintext

# convert a db via STDIN
gpg -d pwman.db | pwman2pass
```

Your pwman database is imported into pass under a timestamped subfolder
(in order to prevent overwriting any existing pass entries).

[pass]: https://www.passwordstore.org/
[pwman]: https://sourceforge.net/projects/pwman/

## LICENSE

[CC0 1.0 Universal](./LICENSE)
