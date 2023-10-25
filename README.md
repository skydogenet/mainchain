Check skydogehash branche for latest release

Skydoge / Drivechain (BIPs 300+301)
------------------

Drivechain allows Bitcoin to create, delete, send BTC to, and receive BTC from “Layer-2”s called “sidechains”. Sidechains are Altcoins that lack a native “coin” – instead, BTC must first be sent over.

Learn more about Skydoge here:
https://skydoge.net

Start helping here:
https://github.com/skydogenet/mainchain/issues

For an example sidechain implementation, see: https://github.com/skydogenet/sidechains

BIP 300:
https://github.com/bitcoin/bips/blob/master/bip-0300.mediawiki

BIP 301:
https://github.com/bitcoin/bips/blob/master/bip-0301.mediawiki

What is Skydoge?
--------------------------
Skydoge.net is a decentralized messaging platform including it's own crypto currency built on layer 1 blockchain network also including sidechain enabled technologies. This project is a fork of Drivechain (Bitcoin Core 0.16.99 + BIPs 300 and 301) and could be implemented on Bitcoin.

Learn more about Drivechain here:
http://drivechain.info

For an example sidechain implementation, see: https://github.com/drivechain-project/sidechains

License
-------

Bitcoin Core, Drivechain and Skydoge are released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/skydogenet/mainchain/tags) are created
regularly to indicate new official, stable release versions of Skydoge Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

The developer [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/bitcoin-dev)
should be used to discuss complicated or controversial changes before working
on a patch set.

Developer IRC can be found on Freenode at #skydogenet.

Testing
-------

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and OS X, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.
=======
Bitcoin Core (and Drivechain) are released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.
