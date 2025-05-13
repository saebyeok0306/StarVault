# StarVault

StarCraft Data Repository 역할을 할 수 있는 런처 연구 중.<br>
개인 토이프로젝트 목적으로 시작했으며, 최종목표는 치지직 API 연동까지.

## Roadmap

starcraft ↔ launcher(client) ↔ backend(server) ↔ database

- [x] search process, scan memory, read & write memory
- [ ] Launcher core logic development (core feature, developer eps build)
- [ ] Launcher UI development (winform)
- [ ] backend development (java spring)
- [ ] database setup (pending, PostgreSQL or MongoDB)
- [ ] chzzk api

## Features

1. Save&Load Game Data
2. Query top/bottom N Players by various metrics
3. Implement a global variable concept for game data (e.g., Boss monster HP)