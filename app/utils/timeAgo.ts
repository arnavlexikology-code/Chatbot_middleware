// mobile/app/utils/timeAgo.ts
export function timeAgo(timestamp: string): string {
  if (!timestamp) return "";

  let date = new Date(timestamp);

  // If parsing failed, try treating it as UTC by adding Z
  if (isNaN(date.getTime())) {
    date = new Date(timestamp + "Z");
  }

  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec} seconds ago`;

  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 2) return "1 minute ago";
  if (diffMin < 60) return `${diffMin} minutes ago`;

  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 2) return "1 hour ago";
  if (diffHours < 24) return `${diffHours} hours ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 2) return "1 day ago";
  return `${diffDays} days ago`;
}
