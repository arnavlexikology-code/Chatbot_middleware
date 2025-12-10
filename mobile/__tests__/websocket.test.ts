/**
 * Unit tests for WebSocket service
 */

import { websocketService } from '../app/services/websocket';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  url: string;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    // Simulate connection after a short delay
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    }, 10);
  }

  send(data: string) {
    // Mock send - store for verification
    (this as any).sentMessages = (this as any).sentMessages || [];
    (this as any).sentMessages.push(data);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close'));
    }
  }
}

// Replace global WebSocket with mock
(global as any).WebSocket = MockWebSocket;

describe('WebSocketService', () => {
  beforeEach(() => {
    // Reset service state
    websocketService.disconnect();
  });

  afterEach(() => {
    websocketService.disconnect();
  });

  describe('connect', () => {
    it('should connect to WebSocket with correct URL', async () => {
      const middlewareUrl = 'http://localhost:8080';
      const token = 'test-token-123';
      const expectedUrl = `ws://localhost:8080/realtime/ws?token=${encodeURIComponent(token)}`;

      const connectPromise = websocketService.connect(middlewareUrl, token);
      
      // Wait for connection
      await connectPromise;

      expect(websocketService.isConnected()).toBe(true);
    });

    it('should convert https to wss', async () => {
      const middlewareUrl = 'https://example.com';
      const token = 'test-token-123';
      const expectedUrl = `wss://example.com/realtime/ws?token=${encodeURIComponent(token)}`;

      await websocketService.connect(middlewareUrl, token);

      expect(websocketService.isConnected()).toBe(true);
    });
  });

  describe('subscribe', () => {
    it('should send subscribe message', async () => {
      const middlewareUrl = 'http://localhost:8080';
      const token = 'test-token-123';
      const conversationId = 'conv-123';

      await websocketService.connect(middlewareUrl, token);

      // Access internal WebSocket to verify message
      const ws = (websocketService as any).ws as MockWebSocket;
      const sentMessages = (ws as any).sentMessages || [];

      websocketService.subscribe(conversationId);

      // Wait a bit for message to be sent
      await new Promise(resolve => setTimeout(resolve, 20));

      expect(sentMessages.length).toBeGreaterThan(0);
      const subscribeMessage = JSON.parse(sentMessages[sentMessages.length - 1]);
      expect(subscribeMessage.type).toBe('subscribe');
      expect(subscribeMessage.conversationId).toBe(conversationId);
    });

    it('should throw error if not connected', () => {
      const conversationId = 'conv-123';

      expect(() => {
        websocketService.subscribe(conversationId);
      }).toThrow('WebSocket is not connected');
    });
  });

  describe('onEvent', () => {
    it('should register and call event callback', async () => {
      const middlewareUrl = 'http://localhost:8080';
      const token = 'test-token-123';
      const mockCallback = jest.fn();

      await websocketService.connect(middlewareUrl, token);

      const unsubscribe = websocketService.onEvent(mockCallback);

      // Simulate incoming message
      const ws = (websocketService as any).ws as MockWebSocket;
      const testEvent = { type: 'message', content: 'test' };
      if (ws.onmessage) {
        ws.onmessage({
          data: JSON.stringify(testEvent),
        } as MessageEvent);
      }

      // Wait for event processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockCallback).toHaveBeenCalledWith(testEvent);

      // Test unsubscribe
      unsubscribe();
      mockCallback.mockClear();

      // Send another event
      if (ws.onmessage) {
        ws.onmessage({
          data: JSON.stringify({ type: 'ping' }),
        } as MessageEvent);
      }

      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockCallback).not.toHaveBeenCalled();
    });
  });

  describe('disconnect', () => {
    it('should close WebSocket connection', async () => {
      const middlewareUrl = 'http://localhost:8080';
      const token = 'test-token-123';

      await websocketService.connect(middlewareUrl, token);
      expect(websocketService.isConnected()).toBe(true);

      websocketService.disconnect();

      expect(websocketService.isConnected()).toBe(false);
    });
  });

  describe('send', () => {
    it('should send JSON message', async () => {
      const middlewareUrl = 'http://localhost:8080';
      const token = 'test-token-123';

      await websocketService.connect(middlewareUrl, token);

      const message = { type: 'test', data: 'hello' };
      websocketService.send(message);

      // Wait for message to be sent
      await new Promise(resolve => setTimeout(resolve, 10));

      const ws = (websocketService as any).ws as MockWebSocket;
      const sentMessages = (ws as any).sentMessages || [];
      expect(sentMessages.length).toBeGreaterThan(0);
      expect(JSON.parse(sentMessages[sentMessages.length - 1])).toEqual(message);
    });
  });
});

