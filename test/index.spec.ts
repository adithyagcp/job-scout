import { env, evictDurableObject, introspectWorkflow, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { encode } from "@auth/core/jwt";
import { getAgentByName } from "agents";
import worker, { JobScoutAgent } from "../src/index";

describe("JobScout API", () => {
	it("rejects an empty analysis request", async () => {
		const response = await SELF.fetch("http://localhost/api/analyze", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-JobScout-Id": "8c52a230-dc90-4b79-9c75-6d50353fba43",
			},
			body: JSON.stringify({}),
		});
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "resumeFacts is required." });
	});

	it("lists an empty saved-opportunity collection", async () => {
		const response = await SELF.fetch("http://localhost/api/opportunities");
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "A valid browser ID is required." });
	});

	it("lists an empty saved-opportunity collection for a valid browser ID", async () => {
		const response = await SELF.fetch("http://localhost/api/opportunities", {
			headers: { "X-JobScout-Id": "8c52a230-dc90-4b79-9c75-6d50353fba43" },
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ opportunities: [] });
	});

	it("fails closed when Access is not configured", async () => {
		const response = await worker.fetch(new Request("https://example.com/"), {
			...env,
			LOCAL_AUTH_BYPASS: "false",
		});
		expect(response.status).toBe(503);
	});

	it("does not allow the development bypass on public origins", async () => {
		const response = await worker.fetch(new Request("https://example.com/"), {
			...env,
			LOCAL_AUTH_BYPASS: "true",
		});
		expect(response.status).toBe(503);
	});

	it("rejects requests without a valid Access token", async () => {
		const accessEnv = {
			...env,
			LOCAL_AUTH_BYPASS: "false",
			AUTH_ORIGIN: undefined,
			AUTH_GITHUB_ID: undefined,
			GITHUB_ALLOWED_USER_ID: undefined,
			ACCESS_TEAM_DOMAIN: "https://example.cloudflareaccess.com",
			ACCESS_AUD: "example-audience",
		};
		const missing = await worker.fetch(new Request("https://example.com/api/opportunities"), accessEnv);
		const invalid = await worker.fetch(new Request("https://example.com/", {
			headers: { "Cf-Access-Jwt-Assertion": "invalid-token" },
		}), accessEnv);
		expect(missing.status).toBe(403);
		expect(invalid.status).toBe(403);
	});

	it("restricts GitHub sessions to the configured account and origin", async () => {
		const secret = "test-secret-with-at-least-thirty-two-characters";
		const githubEnv = {
			...env,
			LOCAL_AUTH_BYPASS: "false",
			AUTH_ORIGIN: "https://jobscout.example.workers.dev",
			AUTH_SECRET: secret,
			AUTH_GITHUB_ID: "test-client",
			AUTH_GITHUB_SECRET: "test-client-secret",
			GITHUB_ALLOWED_USER_ID: "112728711",
		};
		const path = "https://jobscout.example.workers.dev/api/session";
		const unauthenticated = await worker.fetch(new Request(path), githubEnv);
		expect(unauthenticated.status).toBe(401);
		const signIn = await worker.fetch(new Request("https://jobscout.example.workers.dev/"), githubEnv);
		expect(signIn.status).toBe(302);
		expect(signIn.headers.get("Location")).toBe("https://jobscout.example.workers.dev/auth/signin");
		const cookieName = "__Host-jobscout.session-token";
		const token = await encode({ token: { sub: "112728711" }, secret, salt: cookieName });
		const allowed = await worker.fetch(new Request(path, { headers: { Cookie: `${cookieName}=${token}` } }), githubEnv);
		expect(await allowed.json()).toEqual({ method: "github" });
		const otherToken = await encode({ token: { sub: "1" }, secret, salt: cookieName });
		const other = await worker.fetch(new Request(path, { headers: { Cookie: `${cookieName}=${otherToken}` } }), githubEnv);
		expect(other.status).toBe(401);
		const wrongOrigin = await worker.fetch(new Request("https://untrusted.example/api/session", { headers: { Cookie: `${cookieName}=${token}` } }), githubEnv);
		expect(wrongOrigin.status).toBe(403);
	});

	it("requires a valid GitHub OAuth handshake and rejects another account", async () => {
		const origin = "https://jobscout.example.workers.dev";
		const githubEnv = {
			...env,
			LOCAL_AUTH_BYPASS: "false",
			AUTH_ORIGIN: origin,
			AUTH_SECRET: "test-secret-with-at-least-thirty-two-characters",
			AUTH_GITHUB_ID: "test-client",
			AUTH_GITHUB_SECRET: "test-client-secret",
			GITHUB_ALLOWED_USER_ID: "112728711",
		};
		const csrfResponse = await worker.fetch(new Request(`${origin}/auth/csrf`), githubEnv);
		const { csrfToken } = await csrfResponse.json() as { csrfToken: string };
		const csrfCookie = csrfResponse.headers.getSetCookie().map((cookie) => cookie.split(";")[0]).join("; ");
		const signIn = await worker.fetch(new Request(`${origin}/auth/signin/github`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: csrfCookie, "X-Forwarded-Host": "untrusted.example", "X-Forwarded-Proto": "http" },
			body: new URLSearchParams({ csrfToken, callbackUrl: origin }),
		}), githubEnv);
		expect(signIn.status).toBe(302);
		const authorization = new URL(signIn.headers.get("Location")!);
		expect(authorization.origin).toBe("https://github.com");
		expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
		expect(authorization.searchParams.get("redirect_uri")).toBe(`${origin}/auth/callback/github`);
		expect(authorization.searchParams.get("state")).toBeTruthy();
		const cookies = [csrfCookie, ...signIn.headers.getSetCookie().map((cookie) => cookie.split(";")[0])].join("; ");
		let githubUserId = 112728711;
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
			const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith("https://github.com/login/oauth/access_token")) return Response.json({ access_token: "fake-provider-token", token_type: "bearer", scope: "read:user" });
			if (url.startsWith("https://api.github.com/user")) return Response.json({ id: githubUserId, login: "example", name: "Example", avatar_url: "https://example.com/avatar" });
			throw new Error(`Unexpected request: ${url}`);
		});
		try {
			const callbackUrl = `${origin}/auth/callback/github?code=fake-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}`;
			const valid = await worker.fetch(new Request(callbackUrl, { headers: { Cookie: cookies } }), githubEnv);
			expect(valid.status).toBe(302);
			const session = valid.headers.getSetCookie().find((cookie) => cookie.startsWith("__Host-jobscout.session-token="));
			expect(session).toBeDefined();
			expect(session).toContain("HttpOnly");
			expect(session).toContain("Secure");
			expect(session).toContain("SameSite=Lax");
			const authorized = await worker.fetch(new Request(`${origin}/api/session`, { headers: { Cookie: session!.split(";")[0] } }), githubEnv);
			expect(await authorized.json()).toEqual({ method: "github" });
			const forged = await worker.fetch(new Request(`${origin}/auth/callback/github?code=fake-code&state=forged-state`, { headers: { Cookie: cookies } }), githubEnv);
			expect(forged.headers.getSetCookie().some((cookie) => cookie.startsWith("__Host-jobscout.session-token="))).toBe(false);
			githubUserId = 1;
			const denied = await worker.fetch(new Request(callbackUrl, { headers: { Cookie: cookies } }), githubEnv);
			expect(denied.headers.get("Location")).toContain("error=AccessDenied");
			expect(denied.headers.getSetCookie().some((cookie) => cookie.startsWith("__Host-jobscout.session-token="))).toBe(false);
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("accepts only signed assertions for the configured audience and issuer", async () => {
		const { publicKey, privateKey } = await generateKeyPair("RS256");
		const key = { ...await exportJWK(publicKey), kid: "test-key", alg: "RS256", use: "sig" };
		const teamDomain = "https://signed-test.cloudflareaccess.com";
		const accessEnv = {
			...env,
			LOCAL_AUTH_BYPASS: "false",
			AUTH_ORIGIN: undefined,
			AUTH_GITHUB_ID: undefined,
			GITHUB_ALLOWED_USER_ID: undefined,
			ACCESS_TEAM_DOMAIN: teamDomain,
			ACCESS_AUD: "jobscout-test",
		};
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response(JSON.stringify({ keys: [key] }), { headers: { "Content-Type": "application/json" } }),
		);
		try {
			const makeToken = (audience: string, expiration: string) => new SignJWT({})
				.setProtectedHeader({ alg: "RS256", kid: "test-key" })
				.setIssuer(teamDomain)
				.setAudience(audience)
				.setSubject("test-user")
				.setExpirationTime(expiration)
				.sign(privateKey);
			const requestFor = (token: string) => new Request("https://example.com/api/opportunities", {
				headers: { "Cf-Access-Jwt-Assertion": token },
			});
			const valid = await worker.fetch(requestFor(await makeToken("jobscout-test", "5m")), accessEnv);
			const wrongAudience = await worker.fetch(requestFor(await makeToken("other-app", "5m")), accessEnv);
			const expired = await worker.fetch(requestFor(await makeToken("jobscout-test", "-1m")), accessEnv);
			expect(valid.status).toBe(200);
			expect(await valid.json()).toEqual({ opportunities: [] });
			expect(wrongAudience.status).toBe(403);
			expect(expired.status).toBe(403);
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("rejects cross-origin mutations", async () => {
		const response = await SELF.fetch("http://localhost/api/analyze", {
			method: "POST",
			headers: { Origin: "https://untrusted.example" },
		});
		expect(response.status).toBe(403);
	});

	it("runs a durable review and restricts status to its owning Agent", async () => {
		const introspector = await introspectWorkflow(env.REVIEW_WORKFLOW);
		try {
			await introspector.modifyAll(async (instance) => {
				await instance.mockStepResult({ name: "analyze-job" }, {
					matchScore: 80,
					verdict: "Relevant experience.",
					strengths: ["Kubernetes", "Linux troubleshooting", "Invented skill"],
					gaps: [],
					evidence: [
						{ claim: "Kubernetes", resumeEvidence: "Kubernetes   experience", jobRequirement: "SEATTLE engineering role", status: "supported" },
						{ claim: "Linux troubleshooting", resumeEvidence: "Advanced Linux troubleshooting skills", jobRequirement: "Seattle engineering role", status: "supported" },
						{ claim: "Certification", resumeEvidence: "Kubernetes experience", jobRequirement: "Not stated", status: "supported" },
						{ claim: "Python", resumeEvidence: "Python", jobRequirement: "Seattle engineering role", status: "supported" },
					],
					location: "Seattle",
					salary: "Not stated",
				});
			});
			const ownerHeaders = { "Content-Type": "application/json", "X-JobScout-Id": "8c52a230-dc90-4b79-9c75-6d50353fba43" };
			const response = await SELF.fetch("http://localhost/api/analyze", {
				method: "POST",
				headers: ownerHeaders,
				body: JSON.stringify({ company: "Example", role: "Engineer", resumeFacts: "Kubernetes experience and Python", jobPosting: "Seattle engineering role; salary not stated" }),
			});
			expect(response.status).toBe(202);
			const { workflowId } = await response.json() as { workflowId: string };
			const instances = await introspector.get();
			expect(instances).toHaveLength(1);
			await instances[0].waitForStatus("complete");
			const result = await SELF.fetch(`http://localhost/api/reviews/${workflowId}`, { headers: ownerHeaders });
			expect(result.status).toBe(200);
			const data = await result.json() as { status: string; opportunity: { id: string; company: string; role: string; analysis: { matchScore: number; strengths: string[]; evidence: unknown[] } } };
			expect(data).toMatchObject({ status: "complete", opportunity: { id: workflowId, company: "Example", role: "Engineer", analysis: { matchScore: 80 } } });
			expect(data.opportunity.analysis.strengths).toEqual(["Kubernetes"]);
			expect(data.opportunity.analysis.evidence).toMatchObject([
				{ claim: "Kubernetes", status: "supported", sourceChecks: { resume: "found", job: "found" } },
				{ claim: "Linux troubleshooting", status: "unclear", sourceChecks: { resume: "not_found", job: "found" } },
				{ claim: "Certification", status: "unclear", sourceChecks: { resume: "found", job: "insufficient" } },
				{ claim: "Python", status: "unclear", sourceChecks: { resume: "insufficient", job: "found" } },
			]);
			const other = await SELF.fetch(`http://localhost/api/reviews/${workflowId}`, {
				headers: { "X-JobScout-Id": "6f174870-9867-4e42-9f2d-cf17f5ca5158" },
			});
			expect(other.status).toBe(404);
		} finally {
			await introspector.dispose();
		}
	});

	it("does not duplicate a review when its save step is replayed", async () => {
		const agent = await getAgentByName(env.JOB_SCOUT, "idempotency-test");
		const input = { company: "Example", role: "Engineer", url: "" };
		const analysis = { matchScore: 80, verdict: "Relevant experience.", strengths: [], gaps: [], evidence: [], location: "Seattle", salary: "Not stated" };
		const first = await agent.saveWorkflowReview("workflow-id", input, analysis);
		const replay = await agent.saveWorkflowReview("workflow-id", input, analysis);
		expect(replay).toEqual(first);
		expect(await agent.listOpportunities()).toHaveLength(1);
	});

	it("enables one daily schedule and cancels it without affecting saved reviews", async () => {
		const agent = await getAgentByName(env.JOB_SCOUT, "discovery-schedule-test");
		const input = { company: "Example", role: "Engineer", url: "" };
		const analysis = { matchScore: 80, verdict: "Relevant experience.", strengths: [], gaps: [], evidence: [], location: "Seattle", salary: "Not stated" };
		await agent.saveWorkflowReview("saved-review", input, analysis);
		const first = await agent.setDiscoverySchedule(true);
		const second = await agent.setDiscoverySchedule(true);
		expect(first.enabled).toBe(true);
		expect(second.nextRunAt).toBe(first.nextRunAt);
		await evictDurableObject(agent);
		expect(await agent.discoveryStatus()).toMatchObject({ enabled: true, nextRunAt: first.nextRunAt });
		expect(await agent.setDiscoverySchedule(false)).toMatchObject({ enabled: false, nextRunAt: null });
		expect(await agent.listOpportunities()).toHaveLength(1);
	});

	it("executes a scheduled discovery callback through the Agent alarm", async () => {
		const agent = await getAgentByName(env.JOB_SCOUT, "discovery-alarm-test");
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
			if (String(input).includes("/coreweave/")) return Response.json({ jobs: [{ id: 123, title: "Engineer", location: { name: "Seattle" }, absolute_url: "https://example.com/job/123" }] });
			return Response.json({ jobs: [] });
		});
		try {
			await runInDurableObject(agent, async (instance: JobScoutAgent) => { await instance.schedule(0, "refreshDiscovery"); });
			await runDurableObjectAlarm(agent);
			expect(await agent.discoveryStatus()).toMatchObject({ discovery: { jobs: [{ id: 123, company: "CoreWeave" }], unavailable: [] } });
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("isolates and validates the discovery scheduling API", async () => {
		const headers = { "Content-Type": "application/json", "X-JobScout-Id": "7da1f172-12f3-479c-90af-9087bb63bc23" };
		const url = "http://localhost/api/discovery/schedule";
		const invalid = await SELF.fetch(url, { method: "PUT", headers, body: JSON.stringify({ enabled: "true" }) });
		expect(invalid.status).toBe(400);
		const enabled = await SELF.fetch(url, { method: "PUT", headers, body: JSON.stringify({ enabled: true }) });
		expect(await enabled.json()).toMatchObject({ enabled: true, nextRunAt: expect.any(String) });
		const other = await SELF.fetch(url, { headers: { "X-JobScout-Id": "d4673ad8-c5fa-47e1-a7ba-06360b9c7734" } });
		expect(await other.json()).toMatchObject({ enabled: false });
		const disabled = await SELF.fetch(url, { method: "PUT", headers, body: JSON.stringify({ enabled: false }) });
		expect(await disabled.json()).toMatchObject({ enabled: false, nextRunAt: null });
		const crossOrigin = await SELF.fetch(url, { method: "PUT", headers: { ...headers, Origin: "https://untrusted.example" }, body: JSON.stringify({ enabled: true }) });
		expect(crossOrigin.status).toBe(403);
	});

	it("stores discovery results and preserves the last snapshot on failure", async () => {
		const agent = await getAgentByName(env.JOB_SCOUT, "discovery-scan-test");
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
			if (String(input).includes("/coreweave/")) return Response.json({ jobs: [{ id: 123, title: "Engineer", location: { name: "Seattle" }, absolute_url: "https://example.com/job/123" }] });
			return new Response("Unavailable", { status: 503 });
		});
		try {
			const snapshot = await agent.refreshDiscovery();
			expect(snapshot).toMatchObject({ jobs: [{ id: 123, company: "CoreWeave" }], unavailable: ["Cloudflare"] });
			await agent.saveWorkflowReview("saved-after-scan", { company: "Example", role: "Engineer", url: "" }, { matchScore: 80, verdict: "Relevant experience.", strengths: [], gaps: [], evidence: [], location: "Seattle", salary: "Not stated" });
			await agent.updateStatus("saved-after-scan", "Applied");
			await agent.deleteOpportunity("saved-after-scan");
			expect(await agent.discoveryStatus()).toMatchObject({ discovery: snapshot });
			fetchSpy.mockResolvedValue(new Response("Unavailable", { status: 503 }));
			const failed = await runInDurableObject(agent, async (instance: JobScoutAgent) => {
				try { await instance.refreshDiscovery(); return false; }
				catch { return true; }
			});
			expect(failed).toBe(true);
			expect(await agent.discoveryStatus()).toMatchObject({ discovery: snapshot, errorAt: expect.any(String) });
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("returns valid public jobs and reports unavailable boards", async () => {
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
			if (String(input).includes("/coreweave/")) {
				return Response.json({ jobs: [
					{ id: 123, title: "Senior Engineer", location: { name: "Seattle, WA" }, absolute_url: "https://example.com/job/123", updated_at: "2026-01-01" },
					{ id: 124, title: "Invalid link", location: { name: "Seattle" }, absolute_url: "javascript:alert(1)" },
				] });
			}
			return new Response("Unavailable", { status: 503 });
		});
		try {
			const response = await worker.fetch(new Request("http://localhost/api/discover"), env);
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({
				jobs: [{ id: 123, board: "coreweave", company: "CoreWeave", title: "Senior Engineer", location: "Seattle, WA", url: "https://example.com/job/123", updatedAt: "2026-01-01" }],
				unavailable: ["Cloudflare"],
			});
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("imports a public job as text and rejects unknown boards", async () => {
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({
			title: "Senior Engineer",
			location: { name: "Seattle, WA" },
			absolute_url: "https://example.com/job/123",
			content: "&lt;p&gt;Build &amp; deploy systems.&lt;/p&gt;",
			pay_input_ranges: [{ title: "Annual base salary", min_cents: 21000000, max_cents: 24000000, currency_type: "USD" }],
		}));
		try {
			const response = await worker.fetch(new Request("http://localhost/api/discover/coreweave/123"), env);
			expect(response.status).toBe(200);
			expect(await response.json()).toMatchObject({ company: "CoreWeave", role: "Senior Engineer", jobPosting: "Role: Senior Engineer\nLocation: Seattle, WA\nAnnual base salary: $210,000 - $240,000 (USD)\n\nBuild & deploy systems.", truncated: false });
			const unknown = await worker.fetch(new Request("http://localhost/api/discover/unknown/123"), env);
			expect(unknown.status).toBe(404);
			expect(fetchSpy).toHaveBeenCalledTimes(1);
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("reports when all employer boards are unavailable", async () => {
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Unavailable", { status: 503 }));
		try {
			const response = await worker.fetch(new Request("http://localhost/api/discover"), env);
			expect(response.status).toBe(502);
			expect(await response.json()).toMatchObject({ jobs: [], unavailable: ["CoreWeave", "Cloudflare"] });
		} finally {
			fetchSpy.mockRestore();
		}
	});

	it("flags imported job descriptions that exceed the review limit", async () => {
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({
			title: "Engineer",
			location: { name: "Seattle" },
			absolute_url: "https://example.com/job/123",
			content: "Long job description. ".repeat(1000),
		}));
		try {
			const response = await worker.fetch(new Request("http://localhost/api/discover/cloudflare/123"), env);
			const job = await response.json() as { jobPosting: string; truncated: boolean };
			expect(response.status).toBe(200);
			expect(job.truncated).toBe(true);
			expect(job.jobPosting.length).toBe(16_000);
		} finally {
			fetchSpy.mockRestore();
		}
	});
});
