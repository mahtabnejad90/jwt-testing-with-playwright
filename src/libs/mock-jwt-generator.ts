import jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';


const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

export const generateMockJWTWithRs512 = (payload: object = {}, expiresIn: number = 3600, sub: string): string => {
  const token = jwt.sign(
    {
      sub: sub,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresIn,
      ...payload,
    },
    privateKey,
    { algorithm: 'RS512' }
  );

  return token;
};

export const verifyRs512MockJWT = (token: string): object | string => {
  try {
    return jwt.verify(token, publicKey, { algorithms: ['RS512'] });
  } catch (error) {
    return `Token verification failed: ${error.message}`;
  }
};

export { privateKey, publicKey };
