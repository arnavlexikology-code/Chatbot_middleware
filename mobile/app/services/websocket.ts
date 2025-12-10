/**
 * WebSocket service for real-time communication with middleware
 */

type WebSocketEvent = {
  type: string;
  [key: string]: any;
};

type EventCallback = (event: WebSocketEvent) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string | null = null;
  private token: string | null = null;
  private eventCallbacks: EventCallback[] = [];
  private reconnectTimeout: NodeJS.Timeout | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000; // Start with 1 second
  private isConnecting = false;
  private isIntentionallyClosed = false;

  /**
   * Connect to WebSocket server
   * @param middlewareUrl Base URL of middleware (http/https)
   * @param token Authentication token
   */
  connect(middlewareUrl: string, token: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.isConnecting) {
        reject(new Error('Connection already in progress'));
        return;
      }

      this.isConnecting = true;
      this.isIntentionallyClosed = false;
      this.token = token;
      
      // Convert http/https to ws/wss
      const wsUrl = middlewareUrl.replace(/^http/, 'ws');
      const fullUrl = `${wsUrl}/realtime/ws?token=${encodeURIComponent(token)}`;
      this.url = fullUrl;

      try {
        this.ws = new WebSocket(fullUrl);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          this.reconnectDelay = 1000;
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleEvent(data);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.isConnecting = false;
          reject(error);
        };

        this.ws.onclose = (event) => {
          console.log('WebSocket closed:', event.code, event.reason);
          this.isConnecting = false;
          this.ws = null;

          // Attempt to reconnect if not intentionally closed
          if (!this.isIntentionallyClosed && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };
      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  /**
   * Schedule reconnection attempt
   */
  private scheduleReconnect(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }

    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), 10000);
    
    console.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    this.reconnectTimeout = setTimeout(() => {
      if (this.url && this.token && !this.isIntentionallyClosed) {
        this.connect(this.url.replace(/\/realtime\/ws.*$/, ''), this.token)
          .catch((error) => {
            console.error('Reconnection failed:', error);
          });
      }
    }, delay);
  }

  /**
   * Send JSON message through WebSocket
   * @param message Object to send as JSON
   */
  send(message: Record<string, any>): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected');
    }
    this.ws.send(JSON.stringify(message));
  }

  /**
   * Subscribe to a conversation
   * @param conversationId Conversation ID to subscribe to
   */
  subscribe(conversationId: string): void {
    this.send({
      type: 'subscribe',
      conversationId,
    });
  }

  /**
   * Unsubscribe from a conversation
   * @param conversationId Conversation ID to unsubscribe from
   */
  unsubscribe(conversationId: string): void {
    this.send({
      type: 'unsubscribe',
      conversationId,
    });
  }

  /**
   * Register callback for WebSocket events
   * @param callback Function to call when event is received
   * @returns Unsubscribe function
   */
  onEvent(callback: EventCallback): () => void {
    this.eventCallbacks.push(callback);
    
    // Return unsubscribe function
    return () => {
      const index = this.eventCallbacks.indexOf(callback);
      if (index > -1) {
        this.eventCallbacks.splice(index, 1);
      }
    };
  }

  /**
   * Handle incoming event and notify all callbacks
   */
  private handleEvent(event: WebSocketEvent): void {
    this.eventCallbacks.forEach((callback) => {
      try {
        callback(event);
      } catch (error) {
        console.error('Error in event callback:', error);
      }
    });
  }

  /**
   * Disconnect WebSocket
   */
  disconnect(): void {
    this.isIntentionallyClosed = true;
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.eventCallbacks = [];
  }

  /**
   * Check if WebSocket is connected
   */
  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}

// Export singleton instance
export const websocketService = new WebSocketService();

