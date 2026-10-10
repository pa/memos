// Transparent memo encryption at the transport boundary. Outgoing memo content
// is encrypted before it leaves the browser; incoming memos are decrypted before
// the rest of the app sees them. Components and caches only ever handle
// plaintext, and the server only ever handles ciphertext.

import type { Interceptor } from "@connectrpc/connect";
import { analyzeMemoContent } from "@/utils/remark-plugins/remark-tag";
import { blindTag, decryptMemoContent, encryptMemoContent, isEncryptedContent, PERSONAL_KEY_ID } from "./memo";
import { flushTagDictionary, labelTagCounts, rememberTag } from "./tags";
import { vault } from "./vault";

/** Placeholder shown for content this session cannot open. */
export const LOCKED_CONTENT = "🔒 Encrypted. Unlock to read.";

interface MemoLike {
  name: string;
  content: string;
  snippet: string;
  tags: string[];
  relations?: { memo?: { name: string; snippet: string }; relatedMemo?: { name: string; snippet: string } }[];
}

const memoUid = (name: string) => name.slice(name.lastIndexOf("/") + 1);

/** Turns decrypted markdown into a one-line preview like the server's snippet. */
export function snippetOf(markdown: string, max = 64): string {
  const text = markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/[#*_`>~[\]()!-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** Encrypts markdown for `name` with the personal key, computing blind tags and flags. */
export async function sealMemoMarkdown(name: string, markdown: string): Promise<string> {
  const secrets = vault.current;
  if (!secrets) throw new Error("Unlock your notes before saving.");
  const facts = analyzeMemoContent(markdown);
  const blindTags = await Promise.all(facts.tags.map((tag) => blindTag(secrets.tagKey, tag)));
  facts.tags.forEach((tag, i) => rememberTag(blindTags[i], tag));
  return encryptMemoContent(markdown, {
    memoUid: memoUid(name),
    keyId: PERSONAL_KEY_ID,
    key: secrets.contentKey,
    blindTags,
    flags: facts,
  });
}

/** Decrypts a memo in place. Content this session cannot open becomes a placeholder. */
export async function openMemo(memo: MemoLike): Promise<void> {
  if (!isEncryptedContent(memo.content)) return;
  try {
    const markdown = await decryptMemoContent(memo.content, memoUid(memo.name), vault.resolveKey);
    memo.content = markdown;
    memo.snippet = snippetOf(markdown);
    const facts = analyzeMemoContent(markdown);
    const secrets = vault.current;
    if (secrets) {
      const indexes = await Promise.all(facts.tags.map((tag) => blindTag(secrets.tagKey, tag)));
      facts.tags.forEach((tag, i) => rememberTag(indexes[i], tag));
    }
    memo.tags = facts.tags;
  } catch {
    memo.content = LOCKED_CONTENT;
    memo.snippet = LOCKED_CONTENT;
    memo.tags = [];
  }
}

function newMemoName(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from(bytes, (b) => alphabet[b % alphabet.length])
    .join("")
    .slice(0, 22);
}

type Message = Record<string, unknown>;

/**
 * Rewrites tag literals in a CEL filter to blind indexes, so the server can
 * match tags it cannot read. Handles `tag in ["a", "b"]` and `"a" in tags`.
 */
export async function blindTagFilter(filter: string): Promise<string> {
  const secrets = vault.current;
  if (!secrets || !/\btags?\b/.test(filter)) return filter;
  const literal = /"((?:[^"\\]|\\.)*)"/g;
  const replaceInList = async (list: string) => {
    const parts: string[] = [];
    let last = 0;
    for (const match of list.matchAll(literal)) {
      parts.push(list.slice(last, match.index));
      parts.push(JSON.stringify(await blindTag(secrets.tagKey, JSON.parse(match[0]) as string)));
      last = (match.index ?? 0) + match[0].length;
    }
    parts.push(list.slice(last));
    return parts.join("");
  };
  let out = "";
  let last = 0;
  for (const match of filter.matchAll(/\btag\s+in\s+\[([^\]]*)\]|("(?:[^"\\]|\\.)*")\s+in\s+tags\b/g)) {
    out += filter.slice(last, match.index);
    if (match[1] !== undefined) {
      out += `tag in [${await replaceInList(match[1])}]`;
    } else {
      out += `${JSON.stringify(await blindTag(secrets.tagKey, JSON.parse(match[2]) as string))} in tags`;
    }
    last = (match.index ?? 0) + match[0].length;
  }
  return out + filter.slice(last);
}

/**
 * Splits `content.contains("x")` terms out of a filter. The server cannot
 * search ciphertext, so these run in the browser over decrypted results.
 */
export function splitContentSearch(filter: string): { serverFilter: string; terms: string[] } {
  const terms: string[] = [];
  const pattern = /!?\s*content\.contains\(\s*("(?:[^"\\]|\\.)*")\s*\)/g;
  const serverFilter = filter.replace(pattern, (whole, literal: string) => {
    if (whole.trimStart().startsWith("!")) return whole;
    terms.push((JSON.parse(literal) as string).toLowerCase());
    return "true";
  });
  return { serverFilter, terms };
}

async function sealOutgoing(method: string, message: Message): Promise<void> {
  switch (method) {
    case "CreateMemo": {
      const memo = message.memo as MemoLike | undefined;
      if (!memo || !memo.content || isEncryptedContent(memo.content)) return;
      // The memo uid is part of the AAD, so the client must pick it up front.
      if (!message.memoId) message.memoId = newMemoName();
      memo.content = await sealMemoMarkdown(`memos/${message.memoId}`, memo.content);
      return;
    }
    case "CreateMemoComment": {
      const comment = message.comment as MemoLike | undefined;
      if (!comment || !comment.content || isEncryptedContent(comment.content)) return;
      if (!message.commentId) message.commentId = newMemoName();
      comment.content = await sealMemoMarkdown(`memos/${message.commentId}`, comment.content);
      return;
    }
    case "UpdateMemo": {
      const memo = message.memo as MemoLike | undefined;
      const paths = ((message.updateMask as { paths?: string[] } | undefined)?.paths ?? []) as string[];
      if (!memo || !paths.includes("content") || isEncryptedContent(memo.content)) return;
      memo.content = await sealMemoMarkdown(memo.name, memo.content);
      return;
    }
  }
}

async function openIncoming(message: Message): Promise<void> {
  const memos: MemoLike[] = [];
  const collect = (value: unknown) => {
    if (value && typeof value === "object" && typeof (value as MemoLike).content === "string" && "name" in value) {
      memos.push(value as MemoLike);
    }
  };
  collect(message);
  for (const key of ["memos", "comments"]) {
    const list = message[key];
    if (Array.isArray(list)) list.forEach(collect);
  }
  await Promise.all(memos.map(openMemo));
  // Relation snippets of encrypted memos are empty from the server; fill what we can.
  for (const memo of memos) {
    for (const relation of memo.relations ?? []) {
      for (const ref of [relation.memo, relation.relatedMemo]) {
        if (ref && !ref.snippet) {
          const opened = memos.find((m) => m.name === ref.name);
          if (opened) ref.snippet = opened.snippet;
        }
      }
    }
  }
}

const MEMO_SERVICE = "memos.api.MemoService";
const USER_SERVICE = "memos.api.UserService";
const WRITE_METHODS = new Set(["CreateMemo", "CreateMemoComment", "UpdateMemo"]);

/** Saves newly learned tag names after a write, without blocking the response. */
let persistTagDictionary: (() => void) | undefined;

/** Lets the app provide the save function once a client exists (avoids an import cycle). */
export function setTagDictionaryPersister(update: (request: { userSetting: unknown; updateMask: unknown }) => Promise<unknown>) {
  persistTagDictionary = () => {
    if (vault.owner) void flushTagDictionary(vault.owner, update);
  };
}

function labelStats(message: Message) {
  const label = (stats: unknown) => {
    if (stats && typeof stats === "object" && "tagCounts" in stats) {
      const s = stats as { tagCounts: Record<string, number> };
      s.tagCounts = labelTagCounts(s.tagCounts);
    }
  };
  label(message);
  if (Array.isArray(message.userStats)) message.userStats.forEach(label);
}

/** Connect interceptor that encrypts and decrypts memo content. */
export const e2eeInterceptor: Interceptor = (next) => async (req) => {
  if (req.stream) return next(req);
  if (req.service.typeName === USER_SERVICE) {
    const res = await next(req);
    if (vault.unlocked && !res.stream && (req.method.name === "GetUserStats" || req.method.name === "ListUserStats")) {
      labelStats(res.message as unknown as Message);
    }
    return res;
  }
  if (req.service.typeName !== MEMO_SERVICE) return next(req);
  const method = req.method.name;
  const message = req.message as unknown as Message;
  let contentTerms: string[] = [];
  if (vault.unlocked) {
    await sealOutgoing(method, message);
    if (method === "ListMemos" && typeof message.filter === "string" && message.filter) {
      const { serverFilter, terms } = splitContentSearch(message.filter);
      contentTerms = terms;
      message.filter = await blindTagFilter(serverFilter);
    }
  }
  const res = await next(req);
  if (!res.stream) {
    const response = res.message as unknown as Message;
    await openIncoming(response);
    if (contentTerms.length > 0 && Array.isArray(response.memos)) {
      response.memos = (response.memos as MemoLike[]).filter((memo) => {
        const text = memo.content.toLowerCase();
        return contentTerms.every((term) => text.includes(term));
      });
    }
    if (WRITE_METHODS.has(method)) persistTagDictionary?.();
  }
  return res;
};
