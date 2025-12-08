import React, { useState, useEffect } from "react";
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

import { chatStyles as styles } from "../styles/chatStyles";

// Backend URL
// const BACKEND_URL = "http://10.0.2.2:8000/chat"; // in the laptop, run with emulator
const BACKEND_URL = "http://192.168.1.34:8000/chat"; // run in the mobile phone

// Limits
const MAX_MESSAGE_LENGTH = 1500;

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

  // Re-render timeAgo() every 60 seconds
  useEffect(() => {
    const id = setInterval(() => {
      setTick((t) => t + 1);
    }, 60000);
    return () => clearInterval(id);
  }, []);

  // Load intro message on first app open
  useEffect(() => {
    const loadIntroMessage = async () => {
      if (hasLoadedIntro) return;
      
      try {
        // Send empty message to trigger Copilot's intro
        const response = await fetch(BACKEND_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: "" }), // Empty to get intro
        });

        const data = await response.json();
        
        if (data.reply) {
          const introMessage: Message = {
            id: "intro-" + Date.now(),
            from: "bot",
            text: data.reply,
            timestamp: new Date().toISOString(),
            kind: "normal",
          };
          setMessages([introMessage]);
        }
        
        setHasLoadedIntro(true);
      } catch (error) {
        console.error("Failed to load intro:", error);
        setHasLoadedIntro(true); // Don't retry on error
      }
    };

    loadIntroMessage();
  }, [hasLoadedIntro]);
  

  // =============================================
  // SEND MESSAGE TO BACKEND
  // =============================================
  const sendMessage = async () => {
    const trimmed = input.trim();
    if (!trimmed || isSending) return;

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
      const response = await fetch(BACKEND_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: trimmed }),
      });

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
