import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

export function TypingIndicator() {
  return (
    <View style={styles.container}>
      <Text style={styles.text}>Bot is typing...</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 12,
    marginVertical: 4,
  },
  text: {
    fontSize: 14,
    fontStyle: 'italic',
    color: '#666',
  },
});

