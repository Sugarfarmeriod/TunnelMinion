import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import type { RunView } from "../src/features/chat/contracts";

for (const width of [1280, 320]) {
  test(`${width}px 只公开核对结论，旧说明与模型原文按需查看`, async ({
    page,
  }, testInfo) => {
    const timestamp = "2026-10-15T08:00:00Z";
    const threadId = `thread_${"a".repeat(32)}`;
    const runId = `run_${"b".repeat(32)}`;
    const toolRunId = `toolrun_${"c".repeat(32)}`;
    const answer =
      "这个连接入口只接受这台电脑连接。网页是否正常、另一台电脑能否实际打开，还没有验证。";
    const draft = "程序本身正常，请开放防火墙。";
    const oldDraft = "旧说明：一切正常，可以扩大访问范围。";
    const thread = {
      thread_id: threadId,
      created_at: timestamp,
      updated_at: timestamp,
      message_count: 3,
    };
    const run: RunView = {
      run_id: runId,
      thread_id: threadId,
      status: "completed",
      created_at: timestamp,
      finished_at: timestamp,
      error_code: null,
      error_message: null,
      failure: null,
      result: {
        answer,
        answer_checked: true,
        checked_service_id: `service_${"d".repeat(32)}`,
        model_rounds: 2,
        tool_calls: 1,
        tool_run_ids: [toolRunId],
        selected_tools: ["list_network_listeners"],
        stop_reason: "completed",
        elapsed_ms: 25,
        usage: {
          input_tokens: 10,
          output_tokens: 5,
          total_tokens: 15,
          estimated_cost: null,
        },
        limits: {
          max_model_rounds: 8,
          max_tool_calls: 12,
          timeout_seconds: 120,
        },
        context_records: [],
        failures: [],
        evidence_answer: {
          summary: answer,
          confirmed_facts: [{ statement: answer, evidence_refs: [toolRunId] }],
          inferences: [draft],
          unknowns: ["网页和跨电脑访问还没有验证。"],
          evidence: [
            {
              tool_run_id: toolRunId,
              tool_name: "list_network_listeners",
              status: "success",
            },
          ],
          stop_reason: "completed",
        },
      },
    };
    let writes = 0;
    page.on("request", (request) => {
      if (request.method() !== "GET") writes += 1;
    });
    await page.route("**/api/threads", (route) =>
      route.fulfill({ json: [thread] }),
    );
    await page.route(`**/api/threads/${threadId}`, (route) =>
      route.fulfill({
        json: {
          thread,
          messages: [
            {
              role: "assistant",
              content: oldDraft,
              created_at: timestamp,
              run_id: runId,
            },
            {
              role: "user",
              content: "为什么另一台电脑打不开？",
              created_at: timestamp,
              run_id: runId,
            },
            {
              role: "assistant",
              content: answer,
              answer_checked: true,
              created_at: timestamp,
              run_id: runId,
            },
          ],
        },
      }),
    );
    await page.route(`**/api/runs/${runId}`, (route) =>
      route.fulfill({ json: run }),
    );
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`/app/overview?thread=${threadId}`);
    await expect(page.getByText(answer, { exact: true })).toBeVisible();
    await expect(
      page.getByText("本次检查已结束", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(oldDraft, { exact: true })).not.toBeVisible();
    await expect(page.getByText(draft, { exact: true })).not.toBeVisible();
    await page.getByText(answer, { exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({
      path: testInfo.outputPath(`checked-answer-${width}.png`),
    });
    await page.getByText("查看原始说明（未核对）", { exact: true }).click();
    await expect(page.getByText(oldDraft, { exact: true })).toBeVisible();
    await page.getByText("查看用了哪些工具与证据", { exact: true }).click();
    await expect(page.getByText(draft, { exact: true })).not.toBeVisible();
    await page.getByText("查看模型原始说明（未核对）", { exact: true }).click();
    await expect(page.getByText(draft, { exact: true })).toBeVisible();
    expect(writes).toBe(0);
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth + 1,
      ),
    ).toBe(true);
    const accessibility = await new AxeBuilder({ page }).analyze();
    expect(
      accessibility.violations.filter(
        ({ impact }) => impact === "serious" || impact === "critical",
      ),
    ).toEqual([]);
  });
}
