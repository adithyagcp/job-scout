# JobScout

Run `npm install` and `npm run dev`, then open the local URL printed by Wrangler. Local development uses a browser ID rather than authentication; it is not a secure private vault. A review sends its input to Cloudflare Workers AI. Run tests with `npm test -- --run`.

## Search and review

Search the public CoreWeave and Cloudflare Greenhouse job boards by title and location. Results do not cover the whole market, and pay is not verified in the search list. Select a role to import its published description and any structured pay ranges into the review form; check the original posting, especially if the import is truncated. Paste verified experience to generate a proposed review and save it to the shortlist. The app does not apply for jobs.

Enable the optional 24-hour scan and use **Scan now** to capture an initial snapshot. View the latest saved scan from the discovery panel. Scans fetch public job listings only; they do not call AI or submit applications. The schedule and snapshot belong to the same Agent as the shortlist. In local development, scans run only while the dev server is running; the first scheduled scan is 24 hours after enabling it. Partial source failures are shown, and a total failure preserves the previous snapshot.

No Cloudflare Access checkout or credit card is required to run the local app. Workers AI calls still use the configured Cloudflare account and its applicable usage limits and pricing. Resume facts and job descriptions are sent to Workers AI; review generated claims for accuracy.

Each review runs as a Cloudflare AgentWorkflow with separate AI, evidence-check, and save steps. Workflow inputs and step results are retained by the Workflow runtime; the app requests one-day retention for completed and failed runs. Locally these records are stored in Wrangler's local state. A failed AI step may retry once and may incur additional inference usage. The browser resumes a pending review after refresh; saved reviews remain in the Agent's state until deleted.

New reviews check whether proposed evidence excerpts appear in the supplied experience and posting, ignoring case and whitespace. An unmatched, very short, or unspecified excerpt downgrades a supported entry to unclear, and the strengths list is built only from entries with matching excerpts. Matching text does not prove that the AI's claim or score is correct, and older saved reviews are marked as not checked.

## GitHub Sign-in And Deployment

The deployed Worker uses GitHub OAuth and permits only the GitHub user ID configured in `wrangler.jsonc`. It fails closed if its authentication configuration is incomplete. Local `dev` and `start` scripts use `LOCAL_AUTH_BYPASS`, which is accepted only for loopback HTTP requests. Do not configure this bypass in production.

The GitHub OAuth application must use the exact deployed origin as its homepage and `<origin>/auth/callback/github` as its callback URL, without wildcard matching. Configure `AUTH_ORIGIN`, `AUTH_GITHUB_ID`, and `GITHUB_ALLOWED_USER_ID` in `wrangler.jsonc`, then set these Worker secrets using `wrangler secret put`:

- `AUTH_SECRET`: a randomly generated session secret of at least 32 characters.
- `AUTH_GITHUB_SECRET`: the GitHub OAuth application's client secret.

Enter secrets at Wrangler's prompt, never as command arguments or in source control. Deploy with `npm run deploy`. GitHub sign-in requests read-only profile access and uses the verified GitHub account ID to identify the Agent; local browser data is not automatically transferred to the deployed account. Verify that unauthenticated API requests are denied and the intended account can sign in before using real data.

Cloudflare Access is an alternative if configured with `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` instead of GitHub OAuth. It is not required for this deployment. Workers, Workflows, SQLite-backed Durable Objects, and Workers AI have free allocations; operations fail at free limits unless the account is upgraded to a paid plan. See [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/) and [Workers AI pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/).