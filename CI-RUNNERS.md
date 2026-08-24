# CI runners: this repo shares a pool with cream

**If CI here is queued forever and nothing is running, the runners are probably pointed at
[`cream`](https://github.com/rchiofalo/cream).** They are self-hosted on chio-server, there are
eleven of them, and they can only serve one repository at a time.

## Unblock this repo in one command

Every workflow here chooses its pool from a repo variable:

```yaml
runs-on: ${{ vars.RUNNER_POOL == 'self-hosted' && fromJSON('["self-hosted","Linux","X64"]') || 'ubuntu-latest' }}
```

So you do not need to touch any runner — send this repo back to GitHub-hosted runners:

```bash
gh variable set RUNNER_POOL --repo rchiofalo/rustgate --body github-hosted
```

and back again when the pool returns:

```bash
gh variable set RUNNER_POOL --repo rchiofalo/rustgate --body self-hosted
```

Prefer this whenever you just need a build to run. It is instant, reversible, aborts nothing, and
does not disturb whatever the other project is doing.

## Or take the runners back

```bash
ssh chio-server '~/ci-runners.sh status'                     # who serves what
REG_TOKEN=$(gh api -X POST repos/rchiofalo/rustgate/actions/runners/registration-token -q .token) \
  ssh chio-server "REG_TOKEN=$REG_TOKEN ~/ci-runners.sh point rchiofalo/rustgate"
```

This deregisters the pool from its current repo and re-registers it here. It refuses to touch a
pool where a job is running, so it will not abort a build in progress.

## Why it is like this

GitHub scopes self-hosted runners to a **repository**, an **organization**, or an **enterprise**.
`rchiofalo` is a **User** account, which has no account-level pool — so eleven runners on one box
cannot be shared by registering them once. Each belongs to exactly one repo until it is moved.

The real fix is to move these repos under an organization and register a single org-level pool.
That is planned but not done: it changes `ghcr.io/${{ github.repository }}`, and cream's deploy
hardcodes its image path in three places, so cream's transfer has to be done deliberately. **This
repo is the intended rehearsal for that migration.**

## Full documentation

`~/RUNNERS.md` on chio-server — pool layout, CPU limits, token handling, and the failure modes that
have actually bitten. The script itself lives at `deploy/ci-runners.sh` in the cream repo.
