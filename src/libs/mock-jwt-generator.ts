import jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';

//creates RSA Key Pair (Used for RS256 & RS512 Signing)
//2048-bit key size to ensure security
const { privateKey: rsaPrivateKey, publicKey: rsaPublicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

//creates EC Key Pair (Used for ES256 Signing)
//using prime256v1 curve for elliptic curve cryptography, read more at: https://www.geeksforgeeks.org/blockchain-elliptic-curve-cryptography/
const { privateKey: ecPrivateKey, publicKey: ecPublicKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

//secret key for HS256 Signing (Symmetric Key)
//this should be kept secret and not shared with anyone, but for testing purposes, it is okay to expose it since it is a mock key.
const hsSecret = 'supersecretkey';

export const generateMockJWT = (algorithm, payload = {}, expiresIn = 3600, sub) => {
  const tokenOptions = { algorithm, expiresIn };
  
  switch (algorithm) {
    case 'RS512':
    case 'RS256':
      //signing with RSA private key
      return jwt.sign({ sub, iat: Math.floor(Date.now() / 1000), ...payload }, rsaPrivateKey, tokenOptions);
    case 'HS256':
      //signing with HMAC secret key
      return jwt.sign({ sub, iat: Math.floor(Date.now() / 1000), ...payload }, hsSecret, tokenOptions);
    case 'ES256':
      //signing with EC private key
      return jwt.sign({ sub, iat: Math.floor(Date.now() / 1000), ...payload }, ecPrivateKey, tokenOptions);
    default:
      throw new Error('Unsupported algorithm');
  }
};

//function that verifies and decodes token of different algorithms
export const verifyMockJWT = (token, algorithm) => {
  try {
    switch (algorithm) {
      case 'RS512':
      case 'RS256':
        //verifies token using RSA public key
        return jwt.verify(token, rsaPublicKey, { algorithms: [algorithm] });
      case 'HS256':
        //verifies token using HMAC secret key
        return jwt.verify(token, hsSecret, { algorithms: ['HS256'] });
      case 'ES256':
        //verifies token using EC public key
        return jwt.verify(token, ecPublicKey, { algorithms: ['ES256'] });
      default:
        throw new Error('Unsupported algorithm');
    }
  } catch (error) {
    //log verification failure, does't just fail silently
    return `Token verification failed: ${error.message}`;
  }
};