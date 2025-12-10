/**
 * Authentication WebView component
 * Handles OAuth/login flow via WebView
 */

import React, { useEffect, useRef } from 'react';
import { View, StyleSheet, ActivityIndicator, Text } from 'react-native';
import { router } from 'expo-router';
import * as AuthService from './services/auth';

// Note: For WebView, you may need to install react-native-webview
// For now, using a simple redirect approach
// In production, use: import { WebView } from 'react-native-webview';

const AUTH_URL = process.env.EXPO_PUBLIC_MIDDLEWARE_URL 
  ? `${process.env.EXPO_PUBLIC_MIDDLEWARE_URL}/auth/login`
  : 'http://localhost:8080/auth/login';

export default function AuthWebView() {
  const webViewRef = useRef<WebView>(null);

  useEffect(() => {
    // Check if we already have a token
    AuthService.getToken().then((token) => {
      if (token && !AuthService.isTokenExpired(token)) {
        // Already authenticated, go back
        router.back();
      }
    });
  }, []);

  const handleNavigationStateChange = (navState: any) => {
    const { url } = navState;
    
    // Check if URL contains token (adjust based on your auth flow)
    // This is a placeholder - adjust based on your actual auth callback URL pattern
    if (url.includes('/auth/callback')) {
      // Extract token from URL or wait for postMessage
      // This depends on your auth implementation
    }
  };

  const handleMessage = (event: any) => {
    try {
      const data = JSON.parse(event.nativeEvent.data);
      if (data.type === 'auth_token' && data.token) {
        // Store token and navigate back
        AuthService.setToken(data.token).then(() => {
          router.back();
        });
      }
    } catch (error) {
      console.error('Failed to parse WebView message:', error);
    }
  };

  // For now, using a simple approach - in production, use WebView
  // This is a placeholder that redirects to auth URL
  useEffect(() => {
    // In a real implementation, you'd use WebView here
    // For now, we'll just show a loading state
    // The actual auth flow should be handled via WebView or deep linking
    console.log('AuthWebView: Should open', AUTH_URL);
  }, []);

  return (
    <View style={styles.container}>
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" />
        <Text style={styles.text}>Redirecting to login...</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(255, 255, 255, 0.8)',
  },
  text: {
    marginTop: 16,
    fontSize: 16,
  },
});

