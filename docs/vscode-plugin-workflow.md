# VS Code Plugin Workflow

## Prerequisite

Start backend (embedded or daemon mode), and make sure at least one session exists.

## Workflow

1. Run `AI-DecompVis: Select Project Session`
2. Pick project and session
3. Browse functions in `AI-DecompVis Functions` tree
4. Open summary (`AI-DecompVis: Show Function Summary`)
5. Request explanation (`AI-DecompVis: Show Explanation`)
6. Write back:
   - `AI-DecompVis: Add Annotation`
   - `AI-DecompVis: Add Bookmark`
7. Apply user-guided reanalysis:
   - `AI-DecompVis: Apply No-Return Constraint`
   - plugin triggers backend reanalysis and refreshes function tree/session

## Thin-client boundary

Plugin only calls backend APIs; analysis remains in C++ core via backend runtime.
