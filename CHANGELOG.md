# Changelog

## [1.1.0](https://github.com/stfsy/go-jwt-cookie/compare/v1.0.0...v1.1.0) (2025-10-27)


### Features

* return types jwt.MapClaims ([9774101](https://github.com/stfsy/go-jwt-cookie/commit/9774101f7bb19e3b57e56596388a7d48dbaae467))

## 1.0.0 (2025-10-27)


### Features

* add keyid to jwt header and use it to lookup validation key fast ([fcdda44](https://github.com/stfsy/go-jwt-cookie/commit/fcdda44a4987c39f77c242c77ae03e6eeeb0c532))
* add RSA and ECDSA algorithm support for JWT signing ([ee8401d](https://github.com/stfsy/go-jwt-cookie/commit/ee8401d14704f1ee162624db7a8f91f8f69051c4))
* add salt to computed hmac key id ([57abb70](https://github.com/stfsy/go-jwt-cookie/commit/57abb708a7a7ebabd3c42a429a944b1ce321ed85))
* add security improvements ([cf4502b](https://github.com/stfsy/go-jwt-cookie/commit/cf4502b8abfd9dcda9475c23acdb0d1c78505b20))
* add typesafe methods for each algorithm ([7143162](https://github.com/stfsy/go-jwt-cookie/commit/714316238d1dbe3e435fbcd7053d6e1e9f4f4db2))
* add withLeway option to counter clock skew ([ed5c57b](https://github.com/stfsy/go-jwt-cookie/commit/ed5c57b332b081c42753355e184b177ce298a82c))
* allow only alphanumeric (more or less) claims ([d1c9589](https://github.com/stfsy/go-jwt-cookie/commit/d1c9589c6dd0db608c5ea6df5d686337f6ca8e02))
* cache parser instance ([8f809c6](https://github.com/stfsy/go-jwt-cookie/commit/8f809c6c1976f35b096f45896ff833e7fc17a2df))
* **cookie:** add GetClaimsOfValid, key rotation, and fuzz tests ([f3ecfe4](https://github.com/stfsy/go-jwt-cookie/commit/f3ecfe450839b7882fb5fb6c33dbea2463f82754))
* improve config defaults and add additional validation ([afefb59](https://github.com/stfsy/go-jwt-cookie/commit/afefb59e4c5a3cff975e45c476bd6669b9dc81a7))
* increase kid length and add salt to hmac key ([635b5c8](https://github.com/stfsy/go-jwt-cookie/commit/635b5c82402409fb095578dd314512039d56d1ea))
* keep validation keys in separate variables to speed up validation ([86a5bd0](https://github.com/stfsy/go-jwt-cookie/commit/86a5bd042e3780de6d573d40346f5f8658f9357f))
* pre allocate claims map ([51450de](https://github.com/stfsy/go-jwt-cookie/commit/51450de594f563c0be2e23cbc9444fb2ee691999))
* require hmac salt for hmac algorithms ([df5fab3](https://github.com/stfsy/go-jwt-cookie/commit/df5fab3e83deafbffe09871e4595d32a5d70f8b1))
* return claims map directly, do not copy ([827cc64](https://github.com/stfsy/go-jwt-cookie/commit/827cc64982dae01881e47a78a6ad5b3edfac80ab))
* support cookie prefixes ([1934215](https://github.com/stfsy/go-jwt-cookie/commit/193421528ac9ae226fe6c7c8365a8a83e2fc0d6f))
