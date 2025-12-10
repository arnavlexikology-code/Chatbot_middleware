/**
 * Authentication service for managing JWT tokens
 * Uses expo-secure-store for secure token storage
 */

import * as SecureStore from 'expo-secure-store';

const TOKEN_KEY = 'auth_token';

/**
 * Decode JWT token to extract payload
 * Note: This is a simple base64 decode, not cryptographic verification
 */
function decodeJWT(token: string): { exp?: number; [key: string]: any } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    const payload = parts[1];
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return decoded;
  } catch (error) {
    console.error('Failed to decode JWT:', error);
    return null;
  }
}

/**
 * Get stored authentication token
 * @returns Promise<string | null> The token if found, null otherwise
 */
export async function getToken(): Promise<string | null> {
  try {
    return await SecureStore.getItemAsync(TOKEN_KEY);
  } catch (error) {
    console.error('Failed to get token:', error);
    return null;
  }
}

/**
 * Store authentication token
 * @param token The JWT token to store
 */
export async function setToken(token: string): Promise<void> {
  try {
    await SecureStore.setItemAsync(TOKEN_KEY, token);
  } catch (error) {
    console.error('Failed to set token:', error);
    throw error;
  }
}

/**
 * Clear stored authentication token
 */
export async function clearToken(): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(TOKEN_KEY);
  } catch (error) {
    console.error('Failed to clear token:', error);
    // Don't throw - clearing is best effort
  }
}

/**
 * Check if a token is expired
 * @param token The JWT token to check
 * @returns boolean True if token is expired or invalid, false otherwise
 */
export function isTokenExpired(token: string): boolean {
  const decoded = decodeJWT(token);
  if (!decoded || !decoded.exp) {
    // If we can't decode or there's no exp claim, consider it expired
    return true;
  }
  
  // exp is in seconds, Date.now() is in milliseconds
  const expirationTime = decoded.exp * 1000;
  const currentTime = Date.now();
  
  // Add a small buffer (5 seconds) to account for clock skew
  return currentTime >= (expirationTime - 5000);
}

