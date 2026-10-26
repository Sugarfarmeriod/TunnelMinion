import type { Page } from "@playwright/test";
import type { ThreadDetail } from "../src/features/chat/contracts";
import {
  completedRun,
  makeEvent,
  makeRun,
  makeThread,
  timestamp,
} from "../src/features/chat/testFixtures";
import {
  makeLocalServices,
  makeMapOverview,
  makeService,
} from "../src/features/service-map/testFixtures";

export async function mockMapChat(page: Page, services = [makeService()]) {
  const local = makeLocalServices(services);
  const overview = makeMapOverview();
  overview.model.status = "available";
  let detail: ThreadDetail = {
    thread: { ...makeThread(), title: null, context: null },
    messages: [],
    context: null,
  };
  let run = makeRun();
  const questions: Array<{
    question: string;
    about?: { node_id: string; service_key: string | null };
    tool_names: string[];
  }> = [];
  let release: () => void = () => {};
  const ready = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/services/local", (route) =>
    route.fulfill({ json: local }),
  );
  await page.route("**/api/ui/overview", (route) =>
    route.fulfill({ json: overview }),
  );
  await page.route("**/api/operations", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/threads", (route) =>
    route.fulfill({
      json:
        route.request().method() === "POST" ? detail.thread : [detail.thread],
    }),
  );
  await page.route(/\/api\/(?:ui\/)?threads\/thread_[0-9a-f]+$/, (route) =>
    route.fulfill({ json: detail }),
  );
  await page.route(/\/api\/threads\/thread_[0-9a-f]+\/runs$/, async (route) => {
    const value = route.request().postDataJSON() as (typeof questions)[number];
    questions.push(value);
    const service = services.find(
      (item) => item.key === value.about?.service_key,
    );
    const context = value.about
      ? { ...value.about, service_name: service?.name ?? null }
      : null;
    detail = {
      thread: {
        ...detail.thread,
        title: value.question.slice(0, 40),
        context,
        message_count: 1,
      },
      context,
      messages: [
        {
          role: "user",
          content: value.question,
          created_at: timestamp,
          run_id: run.run_id,
        },
      ],
    };
    await route.fulfill({ json: run });
  });
  await page.route(/\/api\/runs\/run_[0-9a-f]+$/, (route) =>
    route.fulfill({ json: run }),
  );
  await page.route(
    /\/api\/runs\/run_[0-9a-f]+\/events\?after=\d+$/,
    async (route) => {
      await ready;
      const event = makeEvent(1, "finished", {
        stop_reason: run.status === "cancelled" ? "cancelled" : "completed",
      });
      await route.fulfill({
        contentType: "text/event-stream",
        body: `id: 1\nevent: finished\ndata: ${JSON.stringify(event)}\n\n`,
      });
    },
  );
  return {
    local,
    questions,
    threadId: detail.thread.thread_id,
    cancel() {
      run = makeRun("cancelled");
      release();
      return run;
    },
    finish(content = "已检查这台电脑，服务运行正常。") {
      run = completedRun(content);
      run.result!.answer_basis = "inferred";
      detail = {
        ...detail,
        messages: [
          ...detail.messages,
          {
            role: "assistant",
            content,
            created_at: timestamp,
            run_id: run.run_id,
            answer_checked: true,
            answer_basis: "inferred",
          },
        ],
      };
      release();
    },
  };
}
