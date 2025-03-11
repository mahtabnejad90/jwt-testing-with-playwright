import { test, expect } from '@playwright/test';
import { generateMockJWTWithRs512, verifyRs512MockJWT, publicKey } from '../libs/mock-jwt-generator';
import { faker } from '@faker-js/faker';


test('Verifies mocked jwt token when decoded', async () => {

  const customSub = faker.string.numeric(10)
  // generate a jwt token with custom payload
  const mockPayload = { role: 'admin', featureAccess: ['reports', 'dashboard'] };
  // the 600 value is the expiry time in seconds which amounts to 10 minutes
  const token = generateMockJWTWithRs512(mockPayload, 600, customSub);

  // uncomment to see the generated token
  // console.log(token);

  // decodes the token
  const decodedToken = verifyRs512MockJWT(token);

  // assertion to verify the decoded token is an object
  expect(typeof decodedToken).toBe('object');

  if (typeof decodedToken === 'object' && decodedToken !== null) {
    // this is a type assertion to tell ts that it is a valid jwt payload
    const jwtPayload = decodedToken as { sub: string; iat: number; exp: number; role: string; featureAccess: string[] };

    // playwright asseertions
    expect(jwtPayload).toHaveProperty('sub', customSub);
    expect(jwtPayload).toHaveProperty('iat');
    expect(jwtPayload).toHaveProperty('exp');
    expect(jwtPayload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(jwtPayload).toHaveProperty('role', 'admin');
    expect(jwtPayload).toHaveProperty('featureAccess');
    expect(Array.isArray(jwtPayload.featureAccess)).toBe(true);
    expect(jwtPayload.featureAccess).toContain('reports');
    expect(jwtPayload.featureAccess).toContain('dashboard');
  } else {
    // error handling incase jwt is not an object
    throw new Error('JWT verification failed. Decoded token is not an object.');
  }
  console.log(decodedToken);
});
