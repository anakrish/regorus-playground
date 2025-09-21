# Regorus Playground

**🚀 [Launch Playground](https://anakrish.github.io/regorus-playground/)**

This repository deploys the interactive Regorus Playground - a web-based environment for experimenting with Rego policies using the Regorus engine.

## About

The playground provides:
- **Interactive Code Editor** with Rego syntax highlighting
- **Real-time Policy Evaluation** powered by WebAssembly
- **20+ Example Policies** across multiple domains
- **Coverage Visualization** and debugging tools
- **Multiple Layout Options** (split, tabs, full-screen)

## Deployment

This repository automatically deploys the playground from the [Regorus source repository](https://github.com/anakrish/regorus/tree/playground) using GitHub Actions:

- **Source**: Built playground files from `anakrish/regorus` (playground branch)  
- **Deployment**: Automated via GitHub Actions to GitHub Pages
- **Schedule**: Daily updates at 6 AM UTC to pick up changes

## Development

To modify the playground itself, make changes to the [source repository](https://github.com/anakrish/regorus/tree/playground/docs/playground) on the `playground` branch.

### Triggers

The deployment can be triggered by:
- **Push to main**: Manual updates to this deployment repo
- **Manual trigger**: Via GitHub Actions "Run workflow" button  
- **Schedule**: Daily at 6 AM UTC to check for source updates
- **Repository dispatch**: Triggered by the source repo on changes

### Configuration

- **GitHub Pages**: Must be set to "GitHub Actions" as source
- **Permissions**: Workflow needs `pages: write` and `id-token: write`
- **Secrets**: Optional `SOURCE_REPO_TOKEN` for private source repos

## Links

- **🎮 [Launch Playground](https://anakrish.github.io/regorus-playground/)**
- **📁 [Source Repository](https://github.com/anakrish/regorus)**
- **🌿 [Playground Source](https://github.com/anakrish/regorus/tree/playground/docs/playground)**
- **📖 [Rego Language Docs](https://www.openpolicyagent.org/docs/latest/policy-language/)**