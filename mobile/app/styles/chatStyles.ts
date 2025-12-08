import { StyleSheet } from "react-native";

export const chatStyles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f2f2f2" },
  list: { padding: 16 },

  bubble: {
    maxWidth: "80%",
    padding: 10,
    borderRadius: 12,
    marginBottom: 8,
  },
  userBubble: {
    alignSelf: "flex-end",
    backgroundColor: "#d1e7ff",
  },
  botBubble: {
    alignSelf: "flex-start",
    backgroundColor: "#ffffff",
  },

  bubbleHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 2,
  },
  label: { fontSize: 10, color: "#444" },
  msg: { fontSize: 14, color: "#111" },

  inputRow: {
    flexDirection: "row",
    paddingHorizontal: 8,
    paddingTop: 8,
    paddingBottom: 12,
    borderTopWidth: 1,
    borderColor: "#ddd",
    backgroundColor: "#fff",
  },
  input: {
    flex: 1,
    padding: 12,
    borderWidth: 1,
    borderColor: "#ccc",
    borderRadius: 8,
    marginRight: 8,
    minHeight: 40,
    maxHeight: 120,
  },

  charCount: {
    fontSize: 10,
    textAlign: "right",
    marginTop: 2,
    color: "#666",
  },
  charCountExceeded: {
    color: "#dc2626",
    fontWeight: "600",
  },

  button: {
    paddingHorizontal: 16,
    justifyContent: "center",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#007AFF",
  },
  buttonDisabled: { opacity: 0.5 },
  buttonText: { color: "#007AFF", fontWeight: "600" },

  // learning plan card
  learningContainer: {
    marginTop: 8,
    padding: 10,
    borderRadius: 8,
    backgroundColor: "#eef2ff",
    borderWidth: 1,
    borderColor: "#c7d2fe",
  },
  learningTitle: {
    fontSize: 13,
    fontWeight: "700",
    color: "#111827",
  },
  learningMeta: {
    fontSize: 11,
    color: "#4b5563",
    marginBottom: 6,
  },
  learningSectionTitle: {
    marginTop: 6,
    fontSize: 12,
    fontWeight: "600",
    color: "#1f2937",
  },
  learningModule: { marginTop: 4 },
  learningModuleTitle: {
    fontSize: 11,
    fontWeight: "600",
    color: "#111827",
  },
  learningModuleDesc: { fontSize: 11, color: "#4b5563" },
  linkText: {
    fontSize: 11,
    color: "#2563eb",
    textDecorationLine: "underline",
    marginTop: 2,
  },

  // agent UI stress test
  agentContainer: {
    marginTop: 8,
    padding: 10,
    borderRadius: 8,
    backgroundColor: "#f9fafb",
    borderWidth: 1,
    borderColor: "#e5e7eb",
  },
  agentTitle: {
    fontSize: 13,
    fontWeight: "700",
    marginBottom: 4,
    color: "#111827",
  },
  agentSummary: { fontSize: 11, color: "#4b5563" },
  agentSectionTitle: {
    marginTop: 8,
    fontSize: 12,
    fontWeight: "600",
    color: "#1f2937",
  },
  agentModule: { marginTop: 4 },
  agentModuleTitle: {
    fontSize: 11,
    fontWeight: "600",
    color: "#111827",
  },
  agentModuleDesc: { fontSize: 11, color: "#4b5563" },
  agentLink: {
    fontSize: 11,
    color: "#2563eb",
    textDecorationLine: "underline",
    marginTop: 2,
  },

  // (legacy) timestamp under bubble — no longer used, safe to keep or remove
  timeUnder: {
    fontSize: 10,
    color: "#777",
    marginTop: 4,
  },

  // message group + timestamp above bubble
  messageGroup: {
    marginBottom: 8,
  },
  timeAbove: {
    fontSize: 10,
    color: "#777",
    marginBottom: 2,
  },
  timeRight: {
    alignSelf: "flex-end",
  },
  timeLeft: {
    alignSelf: "flex-start",
  },

  // "View" inline button
  inlineButton: {
    marginTop: 8,
    alignSelf: "flex-start",
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: "#2563eb",
  },
  inlineButtonText: {
    fontSize: 11,
    color: "#2563eb",
    fontWeight: "600",
  },

  // ===== Daily plan table styles =====
  tableContainer: {
    marginTop: 8,
    borderWidth: 1,
    borderColor: "#e5e7eb",
    borderRadius: 8,
    overflow: "hidden",
  },
  tableHeaderRow: {
    flexDirection: "row",
    backgroundColor: "#f3f4f6",
  },
  tableRow: {
    flexDirection: "row",
    borderTopWidth: 1,
    borderTopColor: "#e5e7eb",
  },
  tableHeaderCell: {
    paddingHorizontal: 6,
    paddingVertical: 6,
    fontSize: 11,
    fontWeight: "700",
    color: "#111827",
  },
  tableCell: {
    paddingHorizontal: 6,
    paddingVertical: 6,
    fontSize: 11,
    color: "#374151",
  },
  tableColDay: {
    flex: 1.4,
  },
  tableColFocus: {
    flex: 1.2,
  },
  tableColActivity: {
    flex: 1.6,
  },
});
