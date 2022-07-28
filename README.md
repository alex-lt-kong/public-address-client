# public-address-client

A RESTful-based public address client designed to run on embedded devices.

## Dependencies
* [Onion HTTP library](https://github.com/davidmoreno/onion)
    * Onion will be `make install`ed to `/usr/local/lib/`, add the directory to `$LD_LIBRARY_PATH`:
 `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/`
* Library search support: `apt install pkg-config`.
* SSL/TLS support: `apt install gnutls-dev libgcrypt-dev`
* MP3 support: `apt install libmpg123-dev libao-dev`.
* JSON support: `apt install libjson-c-dev`.