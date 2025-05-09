'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');
const { strictEqual } = require('assert');
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
  let expectedCalls = singles.length * 2;

  const callCompleted = () => {
    if (--expectedCalls === 0) {
      server.close();
      client.close();
    }
  }

  const client = http2
    .connect(`http://localhost:${server.address().port}`);

  for (const i of singles) {
    client
      .request({ [i]: 'abc', [i.toUpperCase()]: 'xyz' })
      .on('error', common.mustCall((e) => {
        strictEqual(e.code, 'ERR_HTTP2_HEADER_SINGLE_VALUE');
        strictEqual(e.name, 'TypeError');
        strictEqual(e.message, `Header field "${i}" must only have a single value`);
        callCompleted();
      }));

    client
      .request({ [i]: ['abc', 'xyz'] })
      .on('error', common.mustCall((e) => {
        strictEqual(e.code, 'ERR_HTTP2_HEADER_SINGLE_VALUE');
        strictEqual(e.name, 'TypeError');
        strictEqual(e.message, `Header field "${i}" must only have a single value`);
        callCompleted();
      }));
  }
}));
