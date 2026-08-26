"use client";

import React, { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";

interface MarkdownMessageProps {
  content: string;
  className?: string;
  size?: "sm" | "base" | "lg";
}

export function MarkdownMessage({
  content,
  className = "",
  size = "base",
}: MarkdownMessageProps) {
  // Split content by code blocks: ```lang ... ```
  const parts = splitCodeBlocks(content);

  const textSizeClasses =
    size === "sm"
      ? "text-xs leading-relaxed"
      : size === "lg"
      ? "text-base leading-[1.8]"
      : "text-[0.9375rem] leading-[1.75]";

  return (
    <div
      className={`space-y-4 font-normal text-[#ececec] antialiased ${textSizeClasses} ${className}`}
      style={{
        fontFamily:
          'Söhne, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      }}
    >
      {parts.map((part, index) => {
        if (part.type === "code") {
          return (
            <CodeBlock
              key={index}
              code={part.content}
              language={part.language || "text"}
            />
          );
        }
        return <FormattedText key={index} text={part.content} size={size} />;
      })}
    </div>
  );
}

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code.trim());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="my-4 overflow-hidden rounded-xl border border-white/15 bg-[#090d15] shadow-xl">
      <div className="flex items-center justify-between border-b border-white/10 bg-white/[0.04] px-4 py-2.5 text-xs text-slate-400">
        <div className="flex items-center gap-2 font-mono lowercase text-slate-300">
          <Terminal className="h-3.5 w-3.5 text-[var(--accent-cyan)]" />
          <span>{language || "code"}</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs text-slate-300 transition hover:bg-white/10 hover:text-white"
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-medium">Copied</span>
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              <span>Copy code</span>
            </>
          )}
        </button>
      </div>
      <div className="chat-scroll overflow-x-auto p-4">
        <pre className="font-mono text-[0.82rem] leading-relaxed text-emerald-300">
          <code>{code.trim()}</code>
        </pre>
      </div>
    </div>
  );
}

function FormattedText({ text, size }: { text: string; size?: "sm" | "base" | "lg" }) {
  const lines = text.split("\n");
  const elements: React.ReactNode[] = [];

  let currentList: { type: "ul" | "ol"; items: string[] } | null = null;
  let currentTable: string[] | null = null;

  const flushList = (keyPrefix: string) => {
    if (!currentList) return;
    if (currentList.type === "ul") {
      elements.push(
        <ul
          key={`${keyPrefix}-ul`}
          className="my-3 space-y-2 pl-6 list-disc text-[#ececec]"
        >
          {currentList.items.map((item, i) => (
            <li key={i} className="leading-relaxed">
              {renderInlineMarkdown(item)}
            </li>
          ))}
        </ul>
      );
    } else {
      elements.push(
        <ol
          key={`${keyPrefix}-ol`}
          className="my-3 space-y-2 pl-6 list-decimal text-[#ececec]"
        >
          {currentList.items.map((item, i) => (
            <li key={i} className="leading-relaxed">
              {renderInlineMarkdown(item)}
            </li>
          ))}
        </ol>
      );
    }
    currentList = null;
  };

  const flushTable = (keyPrefix: string) => {
    if (!currentTable || currentTable.length < 2) {
      if (currentTable) {
        currentTable.forEach((tblLine, idx) => {
          elements.push(
            <p key={`${keyPrefix}-tblp-${idx}`} className="my-2 leading-relaxed text-[#ececec]">
              {renderInlineMarkdown(tblLine)}
            </p>
          );
        });
      }
      currentTable = null;
      return;
    }

    const headerLine = currentTable[0];
    const headerCols = headerLine
      .split("|")
      .map((c) => c.trim())
      .filter((c) => c.length > 0);

    const bodyLines = currentTable.slice(2); // skip header separator

    elements.push(
      <div key={`${keyPrefix}-table`} className="my-4 overflow-x-auto rounded-xl border border-white/10 bg-[#090d15]">
        <table className="w-full text-left text-xs sm:text-[0.85rem]">
          <thead className="border-b border-white/10 bg-white/[0.04] text-white">
            <tr>
              {headerCols.map((col, idx) => (
                <th key={idx} className="px-4 py-2.5 font-semibold">
                  {renderInlineMarkdown(col)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-slate-200">
            {bodyLines.map((row, rIdx) => {
              const rowCols = row
                .split("|")
                .map((c) => c.trim())
                .filter((c) => c.length > 0);
              if (rowCols.length === 0) return null;
              return (
                <tr key={rIdx} className="hover:bg-white/[0.02]">
                  {rowCols.map((col, cIdx) => (
                    <td key={cIdx} className="px-4 py-2">
                      {renderInlineMarkdown(col)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
    currentTable = null;
  };

  lines.forEach((line, idx) => {
    const trimmed = line.trim();

    // Table line
    if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
      flushList(`tbl-${idx}`);
      if (!currentTable) {
        currentTable = [trimmed];
      } else {
        currentTable.push(trimmed);
      }
      return;
    } else {
      flushTable(`tbl-flush-${idx}`);
    }

    // Empty line
    if (!trimmed) {
      flushList(`empty-${idx}`);
      return;
    }

    // Horizontal Rule: ---, ***, ___
    if (/^(\-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      flushList(`hr-${idx}`);
      elements.push(<hr key={`hr-${idx}`} className="my-5 border-white/15" />);
      return;
    }

    // Blockquote: > text
    if (trimmed.startsWith("> ")) {
      flushList(`quote-${idx}`);
      elements.push(
        <blockquote
          key={`quote-${idx}`}
          className="my-3 border-l-4 border-[var(--accent-cyan)]/70 bg-white/[0.03] px-4 py-2.5 text-slate-200 rounded-r-lg"
        >
          {renderInlineMarkdown(trimmed.slice(2))}
        </blockquote>
      );
      return;
    }

    // Headers: #, ##, ###, ####, #####, ######
    const headerMatch = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (headerMatch) {
      flushList(`header-${idx}`);
      const level = headerMatch[1].length;
      const headingText = headerMatch[2];

      if (level === 1) {
        elements.push(
          <h1 key={`h1-${idx}`} className="mt-6 mb-3 text-xl sm:text-2xl font-bold text-white tracking-tight">
            {renderInlineMarkdown(headingText)}
          </h1>
        );
      } else if (level === 2) {
        elements.push(
          <h2 key={`h2-${idx}`} className="mt-5 mb-2.5 text-lg sm:text-xl font-bold text-white tracking-tight border-b border-white/10 pb-1.5">
            {renderInlineMarkdown(headingText)}
          </h2>
        );
      } else if (level === 3) {
        elements.push(
          <h3 key={`h3-${idx}`} className="mt-4 mb-2 text-base sm:text-lg font-semibold text-white tracking-normal">
            {renderInlineMarkdown(headingText)}
          </h3>
        );
      } else if (level === 4) {
        elements.push(
          <h4 key={`h4-${idx}`} className="mt-3.5 mb-1.5 text-[0.95rem] sm:text-base font-semibold text-white tracking-normal">
            {renderInlineMarkdown(headingText)}
          </h4>
        );
      } else {
        elements.push(
          <h5 key={`h5-${idx}`} className="mt-3 mb-1 text-[0.9rem] font-semibold text-slate-100 tracking-normal">
            {renderInlineMarkdown(headingText)}
          </h5>
        );
      }
      return;
    }

    // Bullet list: -, *, +, including indented (+ Security, * CC6.1, - item)
    const bulletMatch = trimmed.match(/^[-*+]\s+(.*)$/);
    if (bulletMatch) {
      const itemText = bulletMatch[1];
      if (!currentList || currentList.type !== "ul") {
        flushList(`ul-switch-${idx}`);
        currentList = { type: "ul", items: [itemText] };
      } else {
        currentList.items.push(itemText);
      }
      return;
    }

    // Numbered list: 1. , 2. , etc.
    const numberedMatch = trimmed.match(/^(\d+)[.)]\s+(.*)$/);
    if (numberedMatch) {
      const itemText = numberedMatch[2];
      if (!currentList || currentList.type !== "ol") {
        flushList(`ol-switch-${idx}`);
        currentList = { type: "ol", items: [itemText] };
      } else {
        currentList.items.push(itemText);
      }
      return;
    }

    // Standalone bold header line, e.g. "**Quick Recap:**"
    const isFullBoldLine = /^(\*\*[^*]+\*\*[:]?)$/.test(trimmed);
    if (isFullBoldLine) {
      flushList(`boldhead-${idx}`);
      elements.push(
        <div key={`boldhead-${idx}`} className="mt-4 mb-1.5 font-bold text-white text-[0.95rem]">
          {renderInlineMarkdown(trimmed)}
        </div>
      );
      return;
    }

    // Regular paragraph line
    flushList(`p-flush-${idx}`);
    elements.push(
      <p key={`p-${idx}`} className="my-2.5 leading-[1.75] text-[#ececec]">
        {renderInlineMarkdown(line)}
      </p>
    );
  });

  flushList("end");
  flushTable("end-tbl");

  return <>{elements}</>;
}

function renderInlineMarkdown(text: string): React.ReactNode {
  // Strip dangerous markdown image injection tags: ![alt](url) -> [Image: alt]
  const safeText = text.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, "[$1]($2)");

  // Match tokens: `code`, **bold**, *italic*, [link](url)
  const tokens: React.ReactNode[] = [];
  let remaining = safeText;
  let keyIndex = 0;

  // Regex matching `inline code`, **bold**, *italic*, or [link](url)
  const regex = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\))/;

  while (remaining.length > 0) {
    const match = remaining.match(regex);
    if (!match || match.index === undefined) {
      tokens.push(remaining);
      break;
    }

    // Push text before match
    if (match.index > 0) {
      tokens.push(remaining.substring(0, match.index));
    }

    const matchedStr = match[0];

    // Inline code: `...`
    if (matchedStr.startsWith("`") && matchedStr.endsWith("`")) {
      const codeContent = matchedStr.slice(1, -1);
      tokens.push(
        <code
          key={keyIndex++}
          className="rounded-md border border-white/15 bg-white/[0.08] px-1.5 py-0.5 font-mono text-[0.8rem] text-[var(--accent-cyan)] font-medium"
        >
          {codeContent}
        </code>
      );
    }
    // Bold: **...**
    else if (matchedStr.startsWith("**") && matchedStr.endsWith("**")) {
      const boldContent = matchedStr.slice(2, -2);
      tokens.push(
        <strong key={keyIndex++} className="font-semibold text-white">
          {boldContent}
        </strong>
      );
    }
    // Italic: *...*
    else if (matchedStr.startsWith("*") && matchedStr.endsWith("*")) {
      const italicContent = matchedStr.slice(1, -1);
      tokens.push(
        <em key={keyIndex++} className="italic text-slate-300">
          {italicContent}
        </em>
      );
    }
    // Link: [text](url)
    else if (matchedStr.startsWith("[") && matchedStr.includes("](") && matchedStr.endsWith(")")) {
      const linkMatch = matchedStr.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      if (linkMatch) {
        const linkText = linkMatch[1];
        const rawUrl = linkMatch[2].trim();
        
        // Strict URL protocol validation (prevent javascript:, data:, file:)
        const isSafeUrl = rawUrl.startsWith("http://") || rawUrl.startsWith("https://") || rawUrl.startsWith("/");
        
        if (isSafeUrl) {
          tokens.push(
            <a
              key={keyIndex++}
              href={rawUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#60a5fa] hover:text-[#93c5fd] underline decoration-blue-400/40 hover:decoration-blue-300 transition-colors"
            >
              {linkText}
            </a>
          );
        } else {
          tokens.push(linkText);
        }
      } else {
        tokens.push(matchedStr);
      }
    }

    remaining = remaining.substring(match.index + matchedStr.length);
  }

  return <>{tokens}</>;
}

function splitCodeBlocks(content: string): { type: "text" | "code"; content: string; language?: string }[] {
  const parts: { type: "text" | "code"; content: string; language?: string }[] = [];
  const regex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;

  let lastIndex = 0;
  let match;

  while ((match = regex.exec(content)) !== null) {
    // Text before code block
    if (match.index > lastIndex) {
      parts.push({
        type: "text",
        content: content.substring(lastIndex, match.index),
      });
    }

    // Code block
    parts.push({
      type: "code",
      language: match[1] || "text",
      content: match[2],
    });

    lastIndex = regex.lastIndex;
  }

  // Remaining text after last code block
  if (lastIndex < content.length) {
    parts.push({
      type: "text",
      content: content.substring(lastIndex),
    });
  }

  return parts;
}
