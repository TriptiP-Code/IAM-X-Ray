# Contributing to IAM X-Ray

First off — **thank you** for taking the time to contribute!  
IAM X-Ray is built for the community, by the community. Every PR matters.

We welcome contributions of all kinds:
- Bug fixes
- New privilege escalation detection rules
- Performance improvements
- UI/UX enhancements
- Documentation
- Real-world (anonymized) IAM snapshots for testing
- Translations

## How to Contribute

### 1. Found a Bug?
- Check existing [Issues](https://github.com/0x6flaw/IAM-X-Ray/issues) first
- If not found, open a new issue with:
  - Clear title
  - Steps to reproduce
  - Expected vs actual behavior
  - Screenshots (if UI-related)
  - Your OS, Python version, AWS setup (if relevant)

### 2. Want to Add a Feature?
- Open an issue first with `[Feature Request]` in title
- Discuss the idea — we love new ideas but want to keep scope tight
- Wait for maintainer approval before starting big changes

### 3. Ready to Code?
```bash
git clone https://github.com/0x6flaw/IAM-X-Ray.git
cd IAM-X-Ray
python -m venv venv && source venv/bin/activate  # or use Docker
pip install -r requirements.txt
streamlit run app/main.py
```

### Code Style & Quality

- Follow PEP 8
- Use type hints where possible
- Write clear commit messages
- Add comments for complex logic
- Keep functions small and focused

### Pull Request Guidelines

1. Fork the repo and create your branch from main
2. Name your branch clearly: fix/xyz, feature/search-improvement, docs/readme-update
3. Run the app locally — ensure nothing breaks
4. Update documentation if needed
5. Submit PR with:
    - Clear description of changes
    - Screenshots (if UI changes)
    - Reference to issue number (Closes #123)

### Testing

- Test on at least one real AWS account (or demo mode)
- Large accounts (>500 policies)? Bonus points
- Test both light and dark mode

### Special Request

If you have **real-world IAM snapshots** (anonymized), please share them! They help improve graph layout and risk detection massively.

## Recognition

Every merged contributor gets:

- Name in CONTRIBUTORS.md (coming soon)
- Shoutout in release notes
- Eternal respect from the cloud security community

## Questions?

Open an issue or DM on GitHub — we usually respond within 24 hours.

**Your contribution today can save someone 10 hours of IAM pain tomorrow.**

Let’s make AWS IAM understandable for everyone.

— 0x6flaw & the IAM X-Ray community
```