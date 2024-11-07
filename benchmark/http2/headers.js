'use strict';

const common = require('../common.js');

const bench = common.createBenchmark(main, {
  nheaders: [0, 10, 100],
  n: [50000, 100000],
  parallel: [10],
}, { flags: ['--no-warnings'] });

function main({ parallel, nheaders, n }) {

  const http2 = require('http2');
  const server = http2.createServer({
    maxHeaderListPairs: 20000,
  });

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

  server.on('stream', (stream) => {
    stream.respond();
    stream.end('Hi!');
  });
  server.listen(0, () => {
    // bench.http({
    //   path: '/',
    //   port: server.address().port,
    //   requests,
    //   maxConcurrentStreams: streams,
    //   clients,
    //   headers: headersObject,
    //   duration,
    //   threads: clients,
    // }, () => { server.close(); });

    const client = http2.connect(`http://localhost:${server.address().port}/`, {
      maxHeaderListPairs: 20000,
    });

    let inflight = 0;
    function doRequest(remaining) {
      inflight += 1;
      const req = client.request(headersObject);
      req.resume();
      req.on('end', () => {
        inflight -= 1;
        if (remaining > 0) {
          doRequest(remaining - 1);
        } else if (inflight === 0) {
          bench.end(n);
          server.close();
          client.destroy();
        }
      });
    }

    bench.start();

    // parallel requests
    let i = parallel;
    const total = n / i;
    while (i-- > 0) {
      doRequest(total);
    }
  });
}
