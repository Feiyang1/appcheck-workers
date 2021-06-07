import { 
  JWK,
  JWS
} from 'node-jose';

export async function handleRequest(request: Request): Promise<Response> {
  // fetch jwks from appcheck
  const jwks = await fetch('https://firebaseappcheck.googleapis.com/v1beta/jwks');
  const jwksJson = await jwks.json();
  
  
  const keystore = await JWK.asKeyStore(jwksJson);
  const verifier = JWS.createVerify(keystore, { algorithms: ['RS256'] });

  // get appcheck token from the request
  const appCheckToken = request.headers.get('X-Firebase-AppCheck');
  // const appCheckToken = 'eyJraWQiOiJmQjdFNnciLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxOjQ3MzMxNTQ5NzI2Nzp3ZWI6NDhiODY1MjJjNGQxMzVhNCIsImF1ZCI6WyJwcm9qZWN0c1wvNDczMzE1NDk3MjY3IiwicHJvamVjdHNcL2hhdmVmdW4tMWQxNzAiXSwiaXNzIjoiaHR0cHM6XC9cL2ZpcmViYXNlYXBwY2hlY2suZ29vZ2xlYXBpcy5jb21cLzQ3MzMxNTQ5NzI2NyIsImV4cCI6MTYyMzEwNDM5NiwiaWF0IjoxNjIzMTAwNzk2fQ.nWlQ8jbUaKoxWRh4iTRSAKGw9TBw6KHylOk_UztAzwVeXYfJYGnm1ODAoInKYm4230aWu6PwgGQaINNmVlLrER1uCMcMIuY_h8J3lohNKGp0JPeuhwnfm1-tMwlFacBCVnBOrMr0PIg5i0Xch-98TG8dmgYM_KKXlukppllzOsQm5VPogoNdQYWfdA8tObJj96qMBk1aDjS9193aqp7J8_MiYcTEYYJk_MgdN1mKIca4HV4bXS7il-liiBsnEO7ZwXLUoPlMo2b8VXmjk23avUK2ytMYcQtX_e8VtbZZ-iDRR7XmDROosC9i3KlK3By1I80T3CjtlwlaFA4cX6K0bcZbnbctOszpHGUkO6sK4vADaygx7cVAoX8VjOtjYdj5H-gT5OW13vOu6cQw6MwijSj6Dgh47y0Y63aCsN3WLjWbNhcRRndV01xuKpZ5jLKQn-e14DEiLsEjcRByPJHEfZhS0KAKk4d4HJSsdrhTKzrEBqLYnl8tNy62tU0SPOnt';
  if (!appCheckToken) {
    return new Response('no appcheck token', {
      status: 403
    });
  }
  let result;
  try {
    result = await verifier.verify(appCheckToken);
  } catch (e) {
    return new Response(`invalid appcheck token, ${JSON.stringify(e)}`, {
      status: 403
    });
  }

  const decoder = new TextDecoder();
  const payload = decoder.decode(result.payload.buffer);
  console.log('payload', payload);
  return new Response(payload, {
    headers: {
      'content-type': 'application/json;charset=UTF-8'
    }
  });
}
