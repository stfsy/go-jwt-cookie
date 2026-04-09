---
name: create-skill
description: Create or update a GitHub Copilot agent skill (SKILL.md), including required frontmatter, folder layout, and safe tool guidance.
---

# Purpose

Use this skill when asked to create a new Copilot agent skill or improve an existing one.

# What a Skill Is

An agent skill is a folder containing:

- A required SKILL.md file
- Optional supporting files (scripts, examples, helper docs)

Copilot chooses skills based on the user prompt and the skill description. When selected, SKILL.md and files in the same skill folder are available to the agent.

# Where to Put Skills

Create a skills folder in one of these supported locations:

- Repository scoped: .github/skills

Create one subfolder per skill, for example:

- .github/skills/webapp-testing/

Directory naming rules:

- Lowercase
- Hyphen-separated words

# Required SKILL.md Structure

Every skill file must be named exactly SKILL.md and include YAML frontmatter.

Required frontmatter fields:

- name: unique lowercase identifier (typically matches skill directory)
- description: what the skill does and when Copilot should use it

Optional frontmatter fields:

- license
- allowed-tools

Minimal example:

```markdown
---
name: github-actions-failure-debugging
description: Guide for debugging failing GitHub Actions workflows. Use this when asked to debug failing GitHub Actions workflows.
---

1. Check recent workflow runs for failures.
2. Summarize failed job logs.
3. Reproduce locally when possible.
4. Apply and verify a fix.
```

# Writing Good Skill Instructions

In the Markdown body, provide:

- Clear trigger language: "Use this when..."
- Ordered, actionable steps
- Tool guidance for each step
- Validation steps and completion criteria
- Safety limits (for example, avoid destructive operations)

# Using Scripts in Skills

If the skill relies on scripts, place them in the same folder and reference them explicitly.

Example layout:

```text
.github/skills/image-convert/
├── SKILL.md
└── convert-svg-to-png.sh
```

Instruction example:

Run convert-svg-to-png.sh from the skill directory and pass the input SVG path as the first argument.

# Tool Pre-Approval Guidance

You can optionally set allowed-tools in frontmatter.

Example:

```yaml
---
name: image-convert
description: Converts SVG images to PNG format. Use when asked to convert SVG files.
allowed-tools: shell
---
```

Security guidance:

- Only pre-approve shell or bash when you trust the skill source and scripts
- If uncertain, omit shell or bash so the user is prompted before command execution

# Skills vs Custom Instructions

Use custom instructions for broad, always-on repository guidance.
Use skills for detailed, task-specific workflows that should be loaded only when relevant.

# Completion Checklist

Before finishing:

1. Confirm SKILL.md filename and valid frontmatter
2. Confirm name is lowercase and hyphenated
3. Confirm description states when to use the skill
4. Confirm body includes concrete, testable steps
5. Confirm script references are correct if scripts are included
6. Confirm allowed-tools is minimal and safe
