// Layout verification keeps external hosts blocked. This fixture requests
// opt-in without contacting the regional service or enabling analytics.
export const consentRegionUrl = 'https://account.hraness.com/api/consent/region';

export function consentRegionResponse(request) {
  if (request.url !== consentRegionUrl || request.method !== 'GET') {
    throw Error('Unexpected request at the consent-region fixture');
  }
  return {
    responseCode: 200,
    responseHeaders: [
      {name: 'Content-Type', value: 'application/json'},
      {name: 'Access-Control-Allow-Origin', value: '*'},
      {name: 'Cache-Control', value: 'no-store'},
    ],
    body: Buffer.from(JSON.stringify({required: true})).toString('base64'),
  };
}
