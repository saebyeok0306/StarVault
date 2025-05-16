# StarVault

This is a personal toy project to develop a launcher that functions as a StarCraft Data Repository.<br>
The final goal is Chzzk API integration.

## Roadmap

starcraft ↔ launcher(client) ↔ backend(server) ↔ database

- [x] search process, scan memory, read & write memory
- [ ] Launcher core logic development (core feature, developer eps build)
- [ ] Launcher UI development (winform)
- [ ] backend development (java spring)
- [ ] database setup (pending, PostgreSQL or MongoDB)
- [ ] chzzk api

## Features

1. Save & Load Game Data
2. Load Top/Bottom N Game Data
3. Load Text Data
4. Add a global variable that can be changed in-game (e.g., Boss Monster HP)
5. Controlling transmission speed by MSQC
6. Encrypting communication between the SCMap and the StarVault Launcher (▲)