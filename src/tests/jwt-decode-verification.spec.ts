import { test, expect } from '@playwright/test';
import { generateMockJWT, verifyMockJWT } from '../libs/mock-jwt-generator';
import { faker } from '@faker-js/faker';

test.describe('JWT Token Verification', () => {

  test('Validates JWT token with RS512', async () => {
    const customSub = faker.string.numeric(10);
    const mockPayload = { role: 'admin', featureAccess: ['reports', 'dashboard'] };
    const token = generateMockJWT('RS512', mockPayload, 600, customSub);
    //if you want to see the generated token, uncomment the line below
    //console.log(token)
    const decodedToken = verifyMockJWT(token, 'RS512');
    expect(typeof decodedToken).toBe('object');

    if (typeof decodedToken === 'object' && decodedToken !== null) {
      expect(decodedToken).toHaveProperty('sub', customSub);
      expect(decodedToken).toHaveProperty('role', 'admin');
      expect(Array.isArray(decodedToken.featureAccess)).toBe(true);
      expect(decodedToken.featureAccess).toContain('reports');
    } else {
      throw new Error('JWT verification failed for RS512.');
    }
  });

  test('Validates JWT token with RS256', async () => {
    const customSub = faker.string.numeric(10);
    const mockPayload = { role: 'editor', featureAccess: ['edit', 'publish'] };
    const token = generateMockJWT('RS256', mockPayload, 600, customSub);
    //if you want to see the generated token, uncomment the line below
    //console.log(token)

    const decodedToken = verifyMockJWT(token, 'RS256');
    expect(typeof decodedToken).toBe('object');

    if (typeof decodedToken === 'object' && decodedToken !== null) {
      expect(decodedToken).toHaveProperty('sub', customSub);
      expect(decodedToken).toHaveProperty('role', 'editor');
      expect(Array.isArray(decodedToken.featureAccess)).toBe(true);
      expect(decodedToken.featureAccess).toContain('edit');
    } else {
      throw new Error('JWT verification failed for RS256.');
    }
  });

  test('Validates JWT token with HS256', async () => {
    const customSub = faker.string.numeric(10);
    const mockPayload = { role: 'user', permissions: ['read'] };
    const token = generateMockJWT('HS256', mockPayload, 600, customSub);
    //if you want to see the generated token, uncomment the line below
    //console.log(token)

    const decodedToken = verifyMockJWT(token, 'HS256');
    expect(typeof decodedToken).toBe('object');

    if (typeof decodedToken === 'object' && decodedToken !== null) {
      expect(decodedToken).toHaveProperty('sub', customSub);
      expect(decodedToken).toHaveProperty('role', 'user');
      expect(Array.isArray(decodedToken.permissions)).toBe(true);
      expect(decodedToken.permissions).toContain('read');
    } else {
      throw new Error('JWT verification failed for HS256.');
    }
  });

  test('Validates JWT token with ES256', async () => {
    const customSub = faker.string.numeric(10);
    const mockPayload = { role: 'superadmin', featureAccess: ['all'] };
    const token = generateMockJWT('ES256', mockPayload, 600, customSub);
    //if you want to see the generated token, uncomment the line below
    //console.log(token)

    const decodedToken = verifyMockJWT(token, 'ES256');
    expect(typeof decodedToken).toBe('object');

    if (typeof decodedToken === 'object' && decodedToken !== null) {
      expect(decodedToken).toHaveProperty('sub', customSub);
      expect(decodedToken).toHaveProperty('role', 'superadmin');
      expect(Array.isArray(decodedToken.featureAccess)).toBe(true);
      expect(decodedToken.featureAccess).toContain('all');
    } else {
      throw new Error('JWT verification failed for ES256.');
    }
  });
});