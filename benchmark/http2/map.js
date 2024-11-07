'use strict';

const common = require('../common.js');

const bench = common.createBenchmark(main, {
  n: [1e3],
  nheaders: [0, 10, 100, 1000],
}, { flags: ['--no-warnings', '--expose-internals'] });

function main({ n, nheaders }) {
  const { mapToHeaders } = require('internal/http2/util');

  const headersObject = {
    ':path': '/',
    ':scheme': 'http',
    'accept-encoding': 'gzip, deflate',
    'accept-language': 'en',
    'content-type': 'text/plain',
    'referer': 'https://example.org/',
    'user-agent': 'SuperBenchmarker 3000',
  };

  for (let i = 0; i < nheaders; i++) {
    headersObject[`foo${i}`] = `some header value ${i}`;
  }

  bench.start();
  for (let i = 0; i < n; i += 1) {
    // we can optimize this more, but it's irrelevant as we need something
    // better to be passed on to c++ side
    const remapped = mapToHeaders(headersObject)
  }
  bench.end(n);
}
