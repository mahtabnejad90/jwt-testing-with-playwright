import { test, expect } from '@playwright/test';
import { generateMockJWT, verifyMockJWT, rsaPublicKey, ecPublicKey, hsSecret } from '../libs/mock-jwt-generator';
import { faker } from '@faker-js/faker';

const algorithms = ['RS512', 'RS256', 'HS256', 'ES256'];

algorithms.forEach(algorithm => {
  test(`Verifies mocked JWT token with ${algorithm} when decoded`, async () => {
    const customSub = faker.string.numeric(10);
    const mockPayload = { role: 'admin', featureAccess: ['reports', 'dashboard'] };
    const token = generateMockJWT(algorithm, mockPayload, 600, customSub);

    // uncomment to see the generated token
    // console.log(token);

    const decodedToken = verifyMockJWT(token, algorithm);
    expect(typeof decodedToken).toBe('object');

    if (typeof decodedToken === 'object' && decodedToken !== null) {
      const jwtPayload = decodedToken as { sub: string; iat: number; exp: number; role: string; featureAccess: string[] };
      
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
      throw new Error(`JWT verification failed for ${algorithm}. Decoded token is not an object.`);
    }
    console.log(`${algorithm} Decoded Token:`, decodedToken);
  });
});
