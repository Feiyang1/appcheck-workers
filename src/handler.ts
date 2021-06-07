import { 
  JWK,
  JWS
} from 'node-jose';

export async function handleRequest(request: Request): Promise<Response> {

  // fetch jwks from appcheck
  const jwks = await fetch('https://firebaseappcheck.googleapis.com/v1beta/jwks');

  const keystore = await JWK.asKeyStore(await jwks.json());

  const verifier = JWS.createVerify(keystore);

  // get appcheck token from the request
  const appCheckToken = request.headers.get('X-Firebase-AppCheck');
  if (!appCheckToken) {
    return new Response('no appcheck token', {
      status: 403
    });
  }

  let result;
  try {
    result = await verifier.verify(appCheckToken);
  } catch (e) {
    return new Response('invalid appcheck token', {
      status: 403
    });
  }

  const payload = JSON.parse(result.payload.toString());
  console.log('payload', payload);
  return new Response(payload, {
    headers: {
      'content-type': 'application/json;charset=UTF-8'
    }
  });
}
