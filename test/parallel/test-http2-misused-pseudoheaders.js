'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();

server.on('stream', common.mustCall((stream) => {
  [
    ':path',
    ':authority',
    ':method',
    ':scheme',
  ].forEach((i) => {
    assert.throws(() => stream.respond({ [i]: '/' }),
                  {
                    code: 'ERR_HTTP2_INVALID_PSEUDOHEADER'
                  });
  });

  stream.respond({}, { waitForTrailers: true });

  const onErr = common.expectsError({
    code: 'ERR_HTTP2_INVALID_PSEUDOHEADER'
  });

  stream.once('error', (err) => {
    console.error(err);
    onErr(err);
    stream.close();
  });

  stream.on('wantTrailers', () => {
    stream.sendTrailers({ ':status': 'bar' });
  });

  stream.end('hello world');
}));


server.listen(0, common.mustCall(() => {
  const client = h2.connect(`http://localhost:${server.address().port}`);
  const req = client.request();

  req.on('response', common.mustCall());
  req.resume();
  req.on('end', common.mustCall());
  req.on('close', common.mustCall(() => {
    server.close();
    client.close();
  }));
}));
