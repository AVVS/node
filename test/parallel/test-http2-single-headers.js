'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');
const assert = require('assert');
const http2 = require('http2');

const server = http2.createServer();

// Each of these headers must appear only once
const singles = [
  'content-type',
  'user-agent',
  'referer',
  'authorization',
  'proxy-authorization',
  'if-modified-since',
  'if-unmodified-since',
  'from',
  'location',
  'max-forwards',
];

server.on('stream', common.mustNotCall());

server.listen(0, common.mustCall(() => {
  for (const i of singles) {
    http2
      .connect(`http://localhost:${server.address().port}`)
      .request({ [i]: 'abc', [i.toUpperCase()]: 'xyz' })
      .on('error', common.expectsError({
        code: 'ERR_HTTP2_HEADER_SINGLE_VALUE',
        name: 'TypeError',
        message: `Header field "${i}" must only have a single value`
      }));

    http2
      .connect(`http://localhost:${server.address().port}`)
      .request({ [i]: ['abc', 'xyz'] })
      .on('error', common.expectsError({
        code: 'ERR_HTTP2_HEADER_SINGLE_VALUE',
        name: 'TypeError',
        message: `Header field "${i}" must only have a single value`
      }));
  }

  // server.close();
}));
