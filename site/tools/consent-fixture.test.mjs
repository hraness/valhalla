import {expect, test} from 'bun:test';
import {consentRegionResponse, consentRegionUrl} from './consent-fixture.mjs';

test('the layout fixture requires opt-in and handles only the regional GET', () => {
  const response = consentRegionResponse({url: consentRegionUrl, method: 'GET'});
  expect(JSON.parse(Buffer.from(response.body, 'base64').toString())).toEqual({required: true});
  expect(response.responseCode).toBe(200);
  for (const request of [
    {url: consentRegionUrl, method: 'POST'},
    {url: consentRegionUrl + '?unexpected=1', method: 'GET'},
    {url: 'https://us.i.posthog.com/i/v0/e/', method: 'POST'},
  ]) expect(() => consentRegionResponse(request)).toThrow('Unexpected request');
});
