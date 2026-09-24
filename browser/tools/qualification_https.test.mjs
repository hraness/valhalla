import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {rootCertificates} from 'node:tls';
import {chromeHttpsArguments, probeHttps} from './qualification_https.mjs';

const options=()=>({origin:'https://rooms.example.test:8790',ca:Buffer.from('synthetic CA'),
  body:Buffer.from([0,0,0,1,2]),headers:{authorization:'Bearer SYNTHETIC','x-vhalla-namespace':'synthetic'}});
function fixture(deliver) {
  const observed={calls:0,destroyed:0};
  const request=(options,receive)=>{
    observed.calls++;observed.options=options;
    const req=new EventEmitter();
    req.destroy=()=>{observed.destroyed++;};
    req.end=body=>{
      observed.body=body;
      queueMicrotask(()=>{
        const response=new EventEmitter();
        response.statusCode=200;response.socket={getProtocol:()=> 'TLSv1.3',alpnProtocol:'http/1.1'};
        deliver({response,req,receive});
      });
    };
    return req;
  };
  return {observed,request};
}

test('HTTPS probes retain strict CA/name/version verification while resolving only synthetic loopback',async()=>{
  const {observed,request}=fixture(({response,receive})=>{receive(response);response.emit('data',Buffer.from('ok'));response.emit('end');});
  const result=await probeHttps(options(),request);
  assert.equal(result.protocol,'TLSv1.3');assert.equal(result.body.toString(),'ok');
  assert.equal(result.alpn,'http/1.1');
  assert.equal(observed.options.rejectUnauthorized,true);assert.equal(observed.options.servername,'rooms.example.test');
  assert.equal(observed.options.minVersion,'TLSv1.3');assert.deepEqual(observed.options.ALPNProtocols,['http/1.1']);
  assert.deepEqual(observed.options.ca,options().ca);assert.equal(observed.options.agent,false);
  for(const all of [true,false]){
    observed.options.lookup('rooms.example.test',{all},(error,address,family)=>{
      assert.equal(error,null);
      if(all)assert.deepEqual(address,[{address:'127.0.0.1',family:4}]);
      else{assert.equal(address,'127.0.0.1');assert.equal(family,4);}
    });
  }
});

test('redirect responses are returned as refusals to inspect, never followed with credentials',async()=>{
  const {observed,request}=fixture(({response,receive})=>{
    response.statusCode=307;response.headers={location:'https://attacker.example/'};
    receive(response);response.emit('end');
  });
  assert.equal((await probeHttps(options(),request)).status,307);
  assert.equal(observed.calls,1);assert.equal(observed.options.path,'/private-relay/v1');
});

test('an oversized response cannot resolve successfully even if end follows it',async()=>{
  const {observed,request}=fixture(({response,receive})=>{
    receive(response);response.emit('data',Buffer.alloc(65537));response.emit('end');
  });
  await assert.rejects(probeHttps(options(),request),/response bound/);assert.equal(observed.destroyed,1);
});

test('a partial response abort rejects and closes the owned request',async()=>{
  const {observed,request}=fixture(({response,receive})=>{
    receive(response);response.emit('data',Buffer.from('partial'));response.emit('aborted');response.emit('end');
  });
  await assert.rejects(probeHttps(options(),request),/response aborted/);assert.equal(observed.destroyed,1);
});

test('TLS failure diagnostics never echo request credentials or raw provider error',async()=>{
  const {observed,request}=fixture(({req})=>req.emit('error',Error('Bearer SYNTHETIC provider details')));
  await assert.rejects(probeHttps(options(),request),error=>error.message==='HTTPS qualification request failed');
  assert.equal(observed.destroyed,1);
});

test('a response from an unexpected TLS version cannot count as qualification',async()=>{
  const {request}=fixture(({response,receive})=>{
    response.socket.getProtocol=()=> 'TLSv1.2';receive(response);response.emit('end');
  });
  await assert.rejects(probeHttps(options(),request),/TLS version/);
});

test('successful HTTP bytes without negotiated HTTP/1.1 cannot count as qualification',async()=>{
  const {request}=fixture(({response,receive})=>{
    response.socket.alpnProtocol=false;receive(response);response.emit('end');
  });
  await assert.rejects(probeHttps(options(),request),/ALPN/);
});

test('probe scope refuses ambient network destinations and malformed origins before opening a request',()=>{
  for(const origin of ['https://example.com:8790','http://rooms.example.test:8790',
    'https://rooms.example.test','https://rooms.example.test:8790/',
    'https://user:pass@rooms.example.test:8790','https://127.0.0.1:8790']){
    assert.throws(()=>probeHttps({...options(),origin},()=>{throw Error('must not open');}),/probe scope/);
  }
});

test('certificate exception refuses malformed certificates and unrelated public CA names',()=>{
  assert.throws(()=>chromeHttpsArguments('not a certificate'));
  assert.throws(()=>chromeHttpsArguments(rootCertificates[0]),/certificate name/);
});
