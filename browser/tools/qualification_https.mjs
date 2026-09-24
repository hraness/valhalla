// Synthetic HTTPS qualification only. Never changes an OS/browser trust store.
import {createHash, X509Certificate} from 'node:crypto';
import {request as httpsRequest} from 'node:https';

export function chromeHttpsArguments(certificate) {
  const leaf = new X509Certificate(certificate);
  if (leaf.checkHost('rooms.example.test') !== 'rooms.example.test') throw Error('qualification certificate name');
  const spki = createHash('sha256').update(leaf.publicKey.export({type:'spki',format:'der'})).digest('base64');
  return {spki, args:[
    '--host-resolver-rules=MAP rooms.example.test 127.0.0.1',
    '--proxy-bypass-list=rooms.example.test',
    '--ignore-certificate-errors-spki-list='+spki,
  ]};
}

// The probe validates the CA, DNS name, TLS version and real response. Node's
// request API never follows redirects. Cap all bytes and the entire deadline,
// including DNS/TLS; response errors must not leave a hanging qualification.
export function probeHttps({origin, ca, body, headers, signal}, request = httpsRequest) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.hostname !== 'rooms.example.test' || !url.port ||
      url.origin !== origin || !Buffer.isBuffer(body) || body.length > 300000 || !ca) throw Error('qualification probe scope');
  return new Promise((resolve,reject) => {
    let req, settled = false;
    const finish = (error,result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) { req?.destroy(); reject(error); } else resolve(result);
    };
    const timer = setTimeout(() => finish(Error('HTTPS qualification probe deadline')),5000);
    try {
      req = request({hostname:url.hostname, port:Number(url.port), servername:url.hostname,
        path:'/private-relay/v1', method:'POST', ca, rejectUnauthorized:true,
        minVersion:'TLSv1.3', ALPNProtocols:['http/1.1'], agent:false, signal,
        lookup:(_hostname, options, callback) => options.all
          ? callback(null,[{address:'127.0.0.1',family:4}]) : callback(null,'127.0.0.1',4),
        headers:{...headers,'content-length':body.length}}, response => {
          const chunks=[]; let bytes=0;
          const protocol=response.socket?.getProtocol(), alpn=response.socket?.alpnProtocol;
          response.on('error',()=>finish(Error('HTTPS qualification response failed')));
          response.on('aborted',()=>finish(Error('HTTPS qualification response aborted')));
          response.on('data',chunk=>{
            bytes+=chunk.length;
            if (bytes>65536) { finish(Error('HTTPS qualification response bound')); return; }
            chunks.push(chunk);
          });
          response.on('end',()=>{
            if (protocol !== 'TLSv1.3') { finish(Error('HTTPS qualification TLS version')); return; }
            if (alpn !== 'http/1.1') { finish(Error('HTTPS qualification ALPN')); return; }
            finish(null,{status:response.statusCode,body:Buffer.concat(chunks),protocol,alpn});
          });
        });
      req.on('error',()=>finish(Error('HTTPS qualification request failed')));
      req.end(body);
    } catch { finish(Error('HTTPS qualification request failed')); }
  });
}
