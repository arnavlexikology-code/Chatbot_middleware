import React, { useState, useEffect, useRef } from "react";
import { timeAgo } from "../utils/timeAgo";
import {
  SafeAreaView,
  View,
  Text,
  TextInput,
  FlatList,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  Linking,
} from "react-native";
import { router } from "expo-router";

import { chatStyles as styles } from "../styles/chatStyles";
import * as AuthService from "../services/auth";
import { websocketService } from "../services/websocket";
import { TypingIndicator } from "../components/TypingIndicator";

// Middleware URL - should be set via environment variable
const MIDDLEWARE_URL = process.env.EXPO_PUBLIC_MIDDLEWARE_URL || "http://localhost:8080";

// Limits
const MAX_MESSAGE_LENGTH = 1500;
const TYPING_DEBOUNCE_MS = 200;

// =============================
// Types aligned with backend
// =============================

// Minimal shape of an Adaptive Card attachment inside the Bot Framework activity
type AgentAttachment = {
  contentType: string;
  content: any; // AdaptiveCard JSON (we keep it flexible here)
};

// Minimal Bot Framework Activity representation from backend
type AgentActivity = {
  id: string;
  type: string;
  text?: string;
  attachments?: AgentAttachment[];
  [key: string]: any; // allow extra fields like serviceUrl, conversation, etc.
};

type LearningModule = {
  title: string;
  description: string;
  dailyPlan?: string[];
};

type LearningPlan = {
  topic: string;
  level: string;
  durationWeeks: number;
  modules: LearningModule[];
  youtubeLinks: string[];
  linkedinLinks: string[];
};

type MessageKind = "normal" | "weeklyPrompt" | "dailyPlan";

type Message = {
  id: string;
  from: "user" | "bot";
  text: string;
  timestamp: string;
  learningPlan?: LearningPlan;
  kind?: MessageKind;
  relatedToId?: string;
  // MS Agent SDK-style activity returned by backend
  agentActivity?: AgentActivity | null;
};

export default function Page() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [tick, setTick] = useState(0);
  const [hasLoadedIntro, setHasLoadedIntro] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const wsUnsubscribeRef = useRef<(() => void) | null>(null);

  // Check authentication and connect WebSocket on mount
  useEffect(() => {
    const initializeAuthAndWebSocket = async () => {
      try {
        const token = await AuthService.getToken();
        
        if (!token || AuthService.isTokenExpired(token)) {
          // No valid token, navigate to auth
          router.push("/AuthWebView");
          return;
        }

        // Generate or use existing conversation ID
        const currentConversationId = conversationId || `conv-${Date.now()}`;
        setConversationId(currentConversationId);

        // Connect WebSocket
        try {
          await websocketService.connect(MIDDLEWARE_URL, token);
          
          // Subscribe to conversation
          websocketService.subscribe(currentConversationId);

          // Register event handler
          const unsubscribe = websocketService.onEvent((event) => {
            handleWebSocketEvent(event);
          });
          wsUnsubscribeRef.current = unsubscribe;

          console.log("WebSocket connected and subscribed to", currentConversationId);
        } catch (error) {
          console.error("Failed to connect WebSocket:", error);
        }
      } catch (error) {
        console.error("Failed to initialize auth:", error);
        router.push("/AuthWebView");
      }
    };

    initializeAuthAndWebSocket();

    // Cleanup on unmount
    return () => {
      if (wsUnsubscribeRef.current) {
        wsUnsubscribeRef.current();
      }
      websocketService.disconnect();
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, []);

  // Handle WebSocket events
  const handleWebSocketEvent = (event: any) => {
    if (event.type === "assistant.typing.start") {
      // Debounce typing start by 200ms
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
      typingTimeoutRef.current = setTimeout(() => {
        setIsTyping(true);
      }, TYPING_DEBOUNCE_MS);
    } else if (event.type === "assistant.typing.end") {
      // Clear any pending typing start
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
        typingTimeoutRef.current = null;
      }
      setIsTyping(false);
    } else if (event.type === "message") {
      // Handle incoming messages
      const botMessage: Message = {
        id: `msg-${Date.now()}`,
        from: "bot",
        text: event.content || event.text || "",
        timestamp: event.timestamp || new Date().toISOString(),
        kind: "normal",
        agentActivity: event.agentActivity || null,
      };
      setMessages((prev) => [...prev, botMessage]);
    }
  };

  // Re-render timeAgo() every 60 seconds
  useEffect(() => {
    const id = setInterval(() => {
      setTick((t) => t + 1);
    }, 60000);
    return () => clearInterval(id);
  }, []);
  

  // =============================================
  // SEND MESSAGE TO MIDDLEWARE
  // =============================================
  const sendMessage = async () => {
    const trimmed = input.trim();
    if (!trimmed || isSending || !conversationId) return;

    const token = await AuthService.getToken();
    if (!token || AuthService.isTokenExpired(token)) {
      router.push("/AuthWebView");
      return;
    }

    const nowIso = new Date().toISOString();

    const userMessage: Message = {
      id: Date.now().toString(),
      from: "user",
      text: trimmed,
      timestamp: nowIso,
      kind: "normal",
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsSending(true);

    try {
      const response = await fetch(`${MIDDLEWARE_URL}/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({
          message: trimmed,
          conversationId: conversationId,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      const baseId = Date.now().toString();

      const botMessage: Message = {
        id: baseId + "-bot",
        from: "bot",
        text: data.reply || "(no reply)",
        timestamp: data.timestamp || new Date().toISOString(),
        learningPlan: data.learning_plan ?? undefined,
        // this now holds the full Bot Framework activity with Adaptive Card attachments
        agentActivity: data.agent_activity ?? null,
        kind: "normal",
      };

      const hasLearningPlan = !!botMessage.learningPlan;

      if (hasLearningPlan) {
        const promptMessage: Message = {
          id: baseId + "-weeklyPrompt",
          from: "bot",
          text:
            "If you want to know the detailed daily plan for this curriculum, click the View button.",
          timestamp: new Date().toISOString(),
          kind: "weeklyPrompt",
          relatedToId: botMessage.id,
        };

        setMessages((prev) => [...prev, botMessage, promptMessage]);
      } else {
        setMessages((prev) => [...prev, botMessage]);
      }
    } catch (err) {
      console.error("Failed to send message:", err);
      const errorMessage: Message = {
        id: Date.now().toString() + "-err",
        from: "bot",
        text: "Server error. Check backend.",
        timestamp: new Date().toISOString(),
        kind: "normal",
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsSending(false);
    }
  };

  // =============================================
  // BUILD DAILY PLAN TABLE DATA
  // =============================================
  const buildDailyPlanRows = (source: Message) => {
    const rows: {
      key: string;
      day: string;
      focus: string;
      activity: string;
    }[] = [];

    if (source.learningPlan) {
      source.learningPlan.modules.forEach((mod, index) => {
        const week = index + 1;
        const daily = mod.dailyPlan ?? [];

        daily.forEach((activity, dayIndex) => {
          rows.push({
            key: `${week}-${dayIndex}`,
            day: `Week ${week} · Day ${dayIndex + 1}`,
            focus: mod.title,
            activity: activity,
          });
        });
      });
    }

    return rows;
  };

  // =============================================
  // HANDLE VIEW BUTTON
  // =============================================
  const handleViewWeeklyPlan = (relatedToId?: string) => {
    if (!relatedToId) return;

    setMessages((prev) => {
      const curriculumMsg = prev.find(
        (m) => m.id === relatedToId && m.learningPlan
      );
      if (!curriculumMsg) return prev;

      const dailyPlanMsg: Message = {
        id: Date.now().toString() + "-dailyPlan",
        from: "bot",
        text: "",
        timestamp: new Date().toISOString(),
        kind: "dailyPlan",
        relatedToId,
      };

      return [...prev, dailyPlanMsg];
    });
  };

  // =============================================
  // RENDER ITEM
  // =============================================
  const renderItem = ({ item }: { item: Message }) => {
    // ================= DAILY PLAN TABLE =================
    if (item.kind === "dailyPlan") {
      const curriculumMsg = messages.find((m) => m.id === item.relatedToId);
      if (!curriculumMsg) return null;

      const rows = buildDailyPlanRows(curriculumMsg);

      return (
        <View style={styles.messageGroup}>
          <Text style={[styles.timeAbove, styles.timeLeft]}>
            {timeAgo(item.timestamp)}
          </Text>

          <View style={[styles.bubble, styles.botBubble]}>
            <View style={styles.bubbleHeader}>
              <Text style={styles.label}>Bot</Text>
            </View>

            <Text style={styles.msg}>
              Here is your detailed daily learning plan:
            </Text>

            <View style={styles.tableContainer}>
              {/* table header */}
              <View style={styles.tableHeaderRow}>
                <Text style={[styles.tableHeaderCell, styles.tableColDay]}>
                  Day
                </Text>
                <Text style={[styles.tableHeaderCell, styles.tableColFocus]}>
                  Focus
                </Text>
                <Text
                  style={[styles.tableHeaderCell, styles.tableColActivity]}
                >
                  Activity
                </Text>
              </View>

              {rows.map((row) => (
                <View key={row.key} style={styles.tableRow}>
                  <Text style={[styles.tableCell, styles.tableColDay]}>
                    {row.day}
                  </Text>
                  <Text style={[styles.tableCell, styles.tableColFocus]}>
                    {row.focus}
                  </Text>
                  <Text style={[styles.tableCell, styles.tableColActivity]}>
                    {row.activity}
                  </Text>
                </View>
              ))}
            </View>
          </View>
        </View>
      );
    }

    // ================= WEEKLY PROMPT =================
    if (item.kind === "weeklyPrompt") {
      return (
        <View style={styles.messageGroup}>
          <Text style={[styles.timeAbove, styles.timeLeft]}>
            {timeAgo(item.timestamp)}
          </Text>

          <View style={[styles.bubble, styles.botBubble]}>
            <View style={styles.bubbleHeader}>
              <Text style={styles.label}>Bot</Text>
            </View>

            <Text style={styles.msg}>{item.text}</Text>

            <TouchableOpacity
              style={styles.inlineButton}
              onPress={() => handleViewWeeklyPlan(item.relatedToId)}
            >
              <Text style={styles.inlineButtonText}>View</Text>
            </TouchableOpacity>
          </View>
        </View>
      );
    }

    // ================= NORMAL MESSAGES =================
    return (
      <View style={styles.messageGroup}>
        <Text
          style={[
            styles.timeAbove,
            item.from === "user" ? styles.timeRight : styles.timeLeft,
          ]}
        >
          {timeAgo(item.timestamp)}
        </Text>

        <View
          style={[
            styles.bubble,
            item.from === "user" ? styles.userBubble : styles.botBubble,
          ]}
        >
          <View style={styles.bubbleHeader}>
            <Text style={styles.label}>
              {item.from === "user" ? "You" : "Bot"}
            </Text>
          </View>

          <Text style={styles.msg}>{item.text}</Text>

          {/* Learning plan UI */}
          {item.from === "bot" && item.learningPlan && (
            <View style={styles.learningContainer}>
              <Text style={styles.learningTitle}>
                {item.learningPlan.topic} – {item.learningPlan.level}
              </Text>
              <Text style={styles.learningMeta}>
                Duration: {item.learningPlan.durationWeeks} weeks
              </Text>

              <Text style={styles.learningSectionTitle}>Curriculum</Text>
              {item.learningPlan.modules.map((mod, index) => (
                <View key={index} style={styles.learningModule}>
                  <Text style={styles.learningModuleTitle}>
                    {index + 1}. {mod.title}
                  </Text>
                  <Text style={styles.learningModuleDesc}>
                    {mod.description}
                  </Text>
                </View>
              ))}

              <Text style={styles.learningSectionTitle}>YouTube videos</Text>
              {item.learningPlan.youtubeLinks.map((url, index) => (
                <Text
                  key={index}
                  style={styles.linkText}
                  onPress={() => Linking.openURL(url)}
                >
                  {url}
                </Text>
              ))}

              <Text style={styles.learningSectionTitle}>
                LinkedIn Learning videos
              </Text>
              {item.learningPlan.linkedinLinks.map((url, index) => (
                <Text
                  key={index}
                  style={styles.linkText}
                  onPress={() => Linking.openURL(url)}
                >
                  {url}
                </Text>
              ))}
            </View>
          )}

          {/* Optional: show some info from the Agent SDK activity */}
          {item.from === "bot" && item.agentActivity && (
            <View style={{ marginTop: 8 }}>
              <Text style={styles.learningSectionTitle}>
                Agent Activity (SDK)
              </Text>
              {item.agentActivity.text ? (
                <Text style={styles.learningModuleDesc}>
                  {item.agentActivity.text}
                </Text>
              ) : null}
              {/* 
                If you later integrate the real Microsoft Agent SDK client,
                you can pass `item.agentActivity` directly into it instead
                of just displaying this text.
              */}
            </View>
          )}
        </View>
      </View>
    );
  };

  // =============================================
  // MAIN VIEW
  // =============================================
  const inputTooLong = input.length > MAX_MESSAGE_LENGTH;

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView
        style={styles.container}
        behavior={Platform.OS === "ios" ? "padding" : undefined}
      >
        <FlatList
          data={messages}
          keyExtractor={(item) => item.id}
          renderItem={renderItem}
          contentContainerStyle={styles.list}
          extraData={tick}
          ListFooterComponent={isTyping ? <TypingIndicator /> : null}
        />

        <View style={styles.inputRow}>
          <View style={{ flex: 1 }}>
            <TextInput
              style={styles.input}
              value={input}
              onChangeText={setInput}
              placeholder="Type a message..."
              multiline
            />

            <Text
              style={[
                styles.charCount,
                inputTooLong && styles.charCountExceeded,
              ]}
            >
              {input.length}/{MAX_MESSAGE_LENGTH}
              {inputTooLong ? " – too long" : ""}
            </Text>
          </View>

          <TouchableOpacity
            onPress={sendMessage}
            disabled={!input.trim() || isSending || inputTooLong}
            style={[
              styles.button,
              (!input.trim() || isSending || inputTooLong) &&
                styles.buttonDisabled,
            ]}
          >
            <Text style={styles.buttonText}>{isSending ? "..." : "Send"}</Text>
          </TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}
