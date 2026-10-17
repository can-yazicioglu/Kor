# GitHub repository presentation settings

README, artwork, screenshots, animation and documentation are versioned in Git. GitHub's **About description**, **website** and **Topics** are separate repository settings and require an authenticated maintainer API/browser session; a Git push alone cannot change them.

## Prepared metadata

**Description**

> Privacy-aware session-risk prototype: local AI, expiring evidence, MFA/review recommendations and inspectable security controls. Synthetic demo for the IBM Z Datathon.

**Website**

Use the repository's demo guide, not an invented live deployment:

`https://github.com/can-yazicioglu/TurAz-Security/blob/main/docs/datathon_demo.md`

**Topics**

`cybersecurity`, `privacy`, `privacy-by-design`, `machine-learning`, `anomaly-detection`, `risk-scoring`, `authentication`, `authorization`, `identity-access-management`, `mfa`, `responsible-ai`, `data-minimization`, `python`, `javascript`, `ibm-z`, `datathon`

The `ibm-z` topic indicates the challenge/integration target. Actual IBM Z execution is not claimed. Topics are discovery labels, not release tags or certification badges.

## Apply with GitHub CLI

Sign in locally if needed. Never put a token or password in an issue, documentation or AI conversation:

```bash
gh auth login --hostname github.com --git-protocol ssh --web
```

Then apply the prepared settings:

```bash
gh repo edit can-yazicioglu/TurAz-Security \
  --description 'Privacy-aware session-risk prototype: local AI, expiring evidence, MFA/review recommendations and inspectable security controls. Synthetic demo for the IBM Z Datathon.' \
  --homepage 'https://github.com/can-yazicioglu/TurAz-Security/blob/main/docs/datathon_demo.md' \
  --add-topic 'cybersecurity,privacy,privacy-by-design,machine-learning,anomaly-detection,risk-scoring,authentication,authorization,identity-access-management,mfa,responsible-ai,data-minimization,python,javascript,ibm-z,datathon'
```

Verify the actual server settings rather than assuming a commit applied them:

```bash
gh repo view can-yazicioglu/TurAz-Security --json description,homepageUrl,repositoryTopics
```
