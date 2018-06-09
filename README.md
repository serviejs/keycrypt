# Keycrypt

[![NPM version](https://img.shields.io/npm/v/keycrypt.svg?style=flat)](https://npmjs.org/package/keycrypt)
[![NPM downloads](https://img.shields.io/npm/dm/keycrypt.svg?style=flat)](https://npmjs.org/package/keycrypt)
[![Build status](https://img.shields.io/travis/serviejs/keycrypt.svg?style=flat)](https://travis-ci.org/serviejs/keycrypt)
[![Test coverage](https://img.shields.io/coveralls/serviejs/keycrypt.svg?style=flat)](https://coveralls.io/r/serviejs/keycrypt?branch=master)

> Data encryption and decryption for rotating credentials and algorithms.

_(Inspired by [keygrip](https://github.com/crypto-utils/keygrip) and [this PR](https://github.com/crypto-utils/keygrip/pull/29))._

## Installation

```
npm install keycrypt --save
```

## Usage

```ts
import { Keycrypt } from 'keycrypt'

const secrets = [Buffer.from('secret', 'utf8')]
const keycrypt = new Keycrypt(secrets)

const raw = Buffer.from('some data', 'utf8')
const encrypted = keycrypt.encode(raw)
const decrypted = keycrypt.decode(encrypted)

assert.equal(decrypted, raw)
```

## TypeScript

This project is using [TypeScript](https://github.com/Microsoft/TypeScript) and publishes the definitions to NPM.

## License

Apache 2.0
