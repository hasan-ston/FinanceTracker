# Personal Finance Tracker

Expense tracker built with Flask, React, Redis, and JWT. Focused on learning production backend: caching strategies, database optimization, and scalable deployment.
🔗 Try it: [App](https://experiement-ijm4-lpui9zc72-hasan-stons-projects.vercel.app/)

## What it does
- User authentication with CRUD operations for expenses.
- Redis caches category summaries per user (cache miss ~3ms → hit ~0.6ms server-side). Cache invalidates automatically on writes (when user deletes or adds another expense).
- AI-powered spending insights using Gemini/OpenAI APIs (with fallback to rule based tips)
- Logs cache hits and misses

## Tech Stack
- **Backend**: Flask, SQLAlchemy, Flask-JWT-Extended, Flask-Limiter, Redis client, CORS
- **Database**: SQLite (in development), Postgres (in production)
- **Cache**: Redis with 5 minute TTL per user
- **Frontend**: Vite + React
- **Deployment**: Backend deployed on Render, and Frontend on Vercel

## Performance Metrics (server-side)
- Summary endpoint: ~3ms on cache miss, ~0.6ms on cache hit (observable in logs)
- Caching reduces database query load by ~80% under typical usage (read-heavy workload with ~80% cache hit rate)
- Most response time is just network travel, but caching significantly improves server capacity without overloading the database.

## Key Learnings

### Caching Impact
Implemented Redis caching to the summary endpoint. As a result, response time dropped from ~3ms to ~0.6ms on cache hits. This cuts down on a ton of database queries since requests are reads more often then writes.

### Database Indexing
Learned why indexing matters. Without it, you have to scan every row in the database. With indexes, you jump straight to what you need. The effect is less noticeable on a small dataset but considerable on a large one. 

### Network Latency vs Server Performance
Most of the response time is just the data traveling over the internet. Caching doesn't speed that up, but it does mean your server can handle more users, concurrent requests and your database doesn't get overloaded.
The optimization matters for scalability and cost, even if individual users don't feel the difference.

### CORS (Cross-Origin Resource Sharing)
Had to configure CORS in Flask to allow my React frontend (hosted on Vercel at a different domain) to call my Flask API (hosted on Render). Without CORS headers, browsers block these cross-origin requests as a security measure. Basically, when your frontend and backend are on different domains, you need to explicitly tell the browser "yes, this cross-origin communication is intentional."

### JWT vs Session-Based Authentication
Most beginner tutorials use session-based authentication, but I implemented JWTs after learning about their scaling advantages:

**The problem with sessions**: The server must store session data for every logged-in user. With multiple servers (required for horizontal scaling), this session data isn't automatically shared. You either need:
- A shared session store (adds complexity and a single point of failure)
- Sticky sessions (users must always hit the same server, limiting load balancing)

Either way, servers become stateful, which makes horizontal scaling way harder.

**How JWTs solve this**: When a user logs in, the server generates a token that has the user data (like user id) baked into it. It's cryptographically signed with a secret key so it can't be tampered with. 
On each request, the frontend includes this token in the `Authorization` header. The server validates the signature, extracts the user ID from the payload and executes the request.

No server-side session storage needed. This makes servers stateless; they don't need to remember anything between requests. Any server can validate any token, enabling true horizontal scaling. Just spin up more servers behind a load balancer and you're good.

**Tradeoffs**: JWTs can't be easily invalidated before expiry (would need a blacklist, reintroducing state). They're also larger than session IDs, slightly increasing bandwidth. For this project, the stateless architecture and scaling benefits outweighed these concerns.

### Rate Limiting and Cache Invalidation
Implemented rate limits to prevent API abuse via spamming, while  the cache invalidation logic ensured no stale data when users modified their expenses. Also, logging was invaluable for debugging these edge cases in production.

---

Built by a first-year engineering student exploring and implementing production concepts beyond basic CRUD applications. Open to feedback and contributions!
