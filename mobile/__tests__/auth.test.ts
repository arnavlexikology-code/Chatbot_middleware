/**
 * Unit tests for auth service
 */

import * as AuthService from '../app/services/auth';
import * as SecureStore from 'expo-secure-store';

// Mock expo-secure-store
jest.mock('expo-secure-store', () => ({
  getItemAsync: jest.fn(),
  setItemAsync: jest.fn(),
  deleteItemAsync: jest.fn(),
}));

describe('AuthService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getToken', () => {
    it('should return token from secure store', async () => {
      const mockToken = 'test-token-123';
      (SecureStore.getItemAsync as jest.Mock).mockResolvedValue(mockToken);

      const token = await AuthService.getToken();

      expect(token).toBe(mockToken);
      expect(SecureStore.getItemAsync).toHaveBeenCalledWith('auth_token');
    });

    it('should return null if token not found', async () => {
      (SecureStore.getItemAsync as jest.Mock).mockResolvedValue(null);

      const token = await AuthService.getToken();

      expect(token).toBeNull();
    });

    it('should return null on error', async () => {
      (SecureStore.getItemAsync as jest.Mock).mockRejectedValue(new Error('Storage error'));

      const token = await AuthService.getToken();

      expect(token).toBeNull();
    });
  });

  describe('setToken', () => {
    it('should store token in secure store', async () => {
      const mockToken = 'test-token-123';
      (SecureStore.setItemAsync as jest.Mock).mockResolvedValue(undefined);

      await AuthService.setToken(mockToken);

      expect(SecureStore.setItemAsync).toHaveBeenCalledWith('auth_token', mockToken);
    });

    it('should throw error on storage failure', async () => {
      const mockToken = 'test-token-123';
      (SecureStore.setItemAsync as jest.Mock).mockRejectedValue(new Error('Storage error'));

      await expect(AuthService.setToken(mockToken)).rejects.toThrow();
    });
  });

  describe('clearToken', () => {
    it('should delete token from secure store', async () => {
      (SecureStore.deleteItemAsync as jest.Mock).mockResolvedValue(undefined);

      await AuthService.clearToken();

      expect(SecureStore.deleteItemAsync).toHaveBeenCalledWith('auth_token');
    });

    it('should not throw on error', async () => {
      (SecureStore.deleteItemAsync as jest.Mock).mockRejectedValue(new Error('Storage error'));

      await expect(AuthService.clearToken()).resolves.not.toThrow();
    });
  });

  describe('isTokenExpired', () => {
    it('should return true for expired token', () => {
      // Create a token that expired 1 hour ago
      const exp = Math.floor(Date.now() / 1000) - 3600;
      const payload = { exp };
      const token = `header.${Buffer.from(JSON.stringify(payload)).toString('base64')}.signature`;

      expect(AuthService.isTokenExpired(token)).toBe(true);
    });

    it('should return false for valid token', () => {
      // Create a token that expires in 1 hour
      const exp = Math.floor(Date.now() / 1000) + 3600;
      const payload = { exp };
      const token = `header.${Buffer.from(JSON.stringify(payload)).toString('base64')}.signature`;

      expect(AuthService.isTokenExpired(token)).toBe(false);
    });

    it('should return true for invalid token format', () => {
      expect(AuthService.isTokenExpired('invalid-token')).toBe(true);
    });

    it('should return true for token without exp claim', () => {
      const payload = { sub: 'user123' };
      const token = `header.${Buffer.from(JSON.stringify(payload)).toString('base64')}.signature`;

      expect(AuthService.isTokenExpired(token)).toBe(true);
    });

    it('should return false for token expiring in more than 5 seconds', () => {
      // Token expires in 10 seconds (more than 5 second buffer)
      const exp = Math.floor(Date.now() / 1000) + 10;
      const payload = { exp };
      const token = `header.${Buffer.from(JSON.stringify(payload)).toString('base64')}.signature`;

      expect(AuthService.isTokenExpired(token)).toBe(false);
    });
  });
});

