// @vitest-environment node
import { afterEach, describe, expect, it } from "vitest";
import { blindTag } from "@/crypto/memo";
import { labelTagCounts, rememberTag } from "@/crypto/tags";
import { blindTagFilter, openMemo, sealMemoMarkdown, splitContentSearch } from "@/crypto/transport";
import { vault } from "@/crypto/vault";
import { analyzeMemoContent } from "@/utils/remark-plugins/remark-tag";

const secrets = () => ({
  contentKey: crypto.getRandomValues(new Uint8Array(32)),
  tagKey: crypto.getRandomValues(new Uint8Array(32)),
  privateKey: new Uint8Array(48),
  publicKey: crypto.getRandomValues(new Uint8Array(32)),
});

afterEach(() => vault.lock(false));

describe("analyzeMemoContent", () => {
  it("finds tags with their ancestors and content flags", () => {
    const facts = analyzeMemoContent("Plan #work/q4 and #home\n\n- [ ] todo\n- [x] done\n\nSee [link](https://x.y) and `code`");
    expect(facts.tags.sort()).toEqual(["home", "work", "work/q4"]);
    expect(facts.hasTaskList).toBe(true);
    expect(facts.hasIncompleteTasks).toBe(true);
    expect(facts.hasLink).toBe(true);
    expect(facts.hasCode).toBe(true);
  });

  it("ignores tags in code", () => {
    expect(analyzeMemoContent("`#nottag` and #real").tags).toEqual(["real"]);
  });
});

describe("encrypted round trip", () => {
  it("seals markdown and opens it back with tags restored", async () => {
    vault.setSignedInUser("users/alice");
    vault.unlock("users/alice", secrets(), false);
    const content = await sealMemoMarkdown("memos/abc", "hello #work");
    expect(content).not.toContain("hello");
    const memo = { name: "memos/abc", content, snippet: "", tags: ["ignored"] };
    await openMemo(memo);
    expect(memo.content).toBe("hello #work");
    expect(memo.tags).toEqual(["work"]);
    expect(memo.snippet).toContain("hello");
  });

  it("shows a placeholder when the key is missing", async () => {
    vault.setSignedInUser("users/alice");
    vault.unlock("users/alice", secrets(), false);
    const content = await sealMemoMarkdown("memos/abc", "secret");
    vault.unlock("users/alice", secrets(), false);
    const memo = { name: "memos/abc", content, snippet: "", tags: [] };
    await openMemo(memo);
    expect(memo.content).toContain("Encrypted");
  });
});

describe("filters", () => {
  it("rewrites tag literals to blind indexes", async () => {
    const s = secrets();
    vault.setSignedInUser("users/alice");
    vault.unlock("users/alice", s, false);
    const work = await blindTag(s.tagKey, "work");
    const home = await blindTag(s.tagKey, "home");
    expect(await blindTagFilter('pinned && tag in ["work", "home"]')).toBe(`pinned && tag in ["${work}", "${home}"]`);
    expect(await blindTagFilter('"work" in tags')).toBe(`"${work}" in tags`);
    expect(await blindTagFilter("pinned")).toBe("pinned");
  });

  it("moves content search to the browser", () => {
    expect(splitContentSearch('content.contains("Hello") && pinned')).toEqual({ serverFilter: "true && pinned", terms: ["hello"] });
  });

  it("labels blind tag counts with known names", () => {
    vault.setSignedInUser("users/alice");
    vault.unlock("users/alice", secrets(), false);
    rememberTag("a".repeat(32), "work");
    expect(labelTagCounts({ ["a".repeat(32)]: 2, ["b".repeat(32)]: 1 })).toEqual({ work: 2 });
  });
});

describe("vault", () => {
  it("drops keys of a different signed-in user", () => {
    vault.setSignedInUser("users/alice");
    vault.unlock("users/alice", secrets(), false);
    expect(vault.unlocked).toBe(true);
    vault.setSignedInUser("users/bob");
    expect(vault.unlocked).toBe(false);
  });
});
