import jwt from 'jsonwebtoken';
import { generateKeyPairSync, createSign, createVerify } from 'crypto';

const { privateKey: rsaPrivateKey, publicKey: rsaPublicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const { privateKey: ecPrivateKey, publicKey: ecPublicKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const hsSecret = 'supersecretkey';

export const generateMockJWT = (algorithm, payload = {}, expiresIn = 3600, sub) => {
  const tokenOptions = { algorithm, expiresIn };
  
  switch (algorithm) {
    case 'RS512':
    case 'RS256':
      return jwt.sign({ sub, iat: Math.floor(Date.now() / 1000), ...payload }, rsaPrivateKey, tokenOptions);
    case 'HS256':
      return jwt.sign({ sub, iat: Math.floor(Date.now() / 1000), ...payload }, hsSecret, tokenOptions);
    case 'ES256':
      return jwt.sign({ sub, iat: Math.floor(Date.now() / 1000), ...payload }, ecPrivateKey, tokenOptions);
    default:
      throw new Error('Unsupported algorithm');
  }
};

export const verifyMockJWT = (token, algorithm) => {
  try {
    switch (algorithm) {
      case 'RS512':
      case 'RS256':
        return jwt.verify(token, rsaPublicKey, { algorithms: [algorithm] });
      case 'HS256':
        return jwt.verify(token, hsSecret, { algorithms: ['HS256'] });
      case 'ES256':
        return jwt.verify(token, ecPublicKey, { algorithms: ['ES256'] });
      default:
        throw new Error('Unsupported algorithm');
    }
  } catch (error) {
    return `Token verification failed: ${error.message}`;
  }
};

export { rsaPrivateKey, rsaPublicKey, ecPrivateKey, ecPublicKey, hsSecret };