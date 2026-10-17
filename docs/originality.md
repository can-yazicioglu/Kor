# Originality: what we can honestly claim

Sentinel is an original implementation and a focused product experiment. It is **not a new category of authentication, a new cryptographic scheme, or a new ML algorithm**. The strongest contribution is the combination of short-lived evidence, inspectable decisions and explicit release limits in a working local demonstration.

This is a scoped comparison with public product documentation, checked on 17 October 2026. It is not an exhaustive literature review, patent search or proof that a feature has never been built elsewhere.

## Established ideas

| Idea in Sentinel | Existing approach | Assessment |
|---|---|---|
| Login risk followed by an MFA step | Auth0 Adaptive MFA evaluates new-device, impossible-travel and untrusted-IP signals before additional verification. | Established product pattern. |
| Risk at user/sign-in level, unfamiliar properties and risk-based policies | Microsoft Entra ID Protection documents these detections and risk-based MFA/password-reset policies. | Established identity-security capability. |
| Logistic/boosted models, rolling counts and threshold selection | Standard statistical modeling and security engineering methods. | Implementation work, not algorithmic novelty. |
| scrypt, HMAC-SHA-256, TLS and role checks | Established cryptography and access-control mechanisms. | Security controls, not invented primitives. |

The first two comparisons are supported by [Auth0's Adaptive MFA documentation](https://auth0.com/docs/secure/multi-factor-authentication/adaptive-mfa) and [Microsoft's risk-detection documentation](https://learn.microsoft.com/en-us/entra/id-protection/concept-risk-detection-types). They demonstrate prior art for the broad product idea; they do not establish that Sentinel is more accurate or more private than either product as a whole.

## The contribution demonstrated here

1. **Useful evidence under a short retention budget.** A fixed two-minute decision window operates within bounded, expiring state. The UI exposes the remaining demo lifetime and count-only inventory. This makes a privacy choice observable rather than just a slogan.
2. **An evidence workbench inside the login story.** Users compare three rule windows, inspect changes within one account/session, and distinguish the current score from the retained peak. These are diagnostics, not causal explanations of every ML score point.
3. **A decision receipt that expires with the demonstration.** A random per-demo key authenticates the current receipt. An altered score fails verification; reset removes the receipt and key references. HMAC itself is standard, and the receipt does not protect against a compromised process.
4. **A visible negative result.** An experimental candidate improved aggregate ranking but missed a required attack scenario. The release loader refuses it. That is responsible engineering and reproducible evidence, not proof of a new research method.
5. **A complete, local teaching/demo journey.** Fictional authentication, risk evidence, authorization denial, integrity checks and expiry can all be exercised in one small application without a cloud inference service.

These points are distinct within this project's design. Claiming that this exact combination is globally unique would require a broader comparison than has been performed.

## How original is it?

| Dimension | Qualitative assessment |
|---|---|
| New algorithm or cryptography | **Low:** established methods are deliberately reused. |
| Product combination and demonstration | **Moderate:** the privacy lifecycle, evidence inspection and failure disclosure form a coherent experience. |
| Evidence of research novelty | **Not established:** no novel-method benchmark, formal privacy guarantee or exhaustive prior-art review. |
| Evidence of production advantage | **Not established:** no real customer pilot, validated deployment thresholds or independent field evaluation. |

These are engineering judgments, not measured scores. A defensible pitch is:

> Sentinel explores how much useful sign-in risk evidence we can provide while keeping identity exposure and retention small—and makes both the evidence and its limitations inspectable.

Avoid “the first,” “zero data stored,” “unhackable,” “quantum-safe,” “production-ready,” or a synthetic result presented as real-world accuracy.

## What would strengthen the contribution next?

- Predefine a privacy-versus-detection study across retention budgets, keeping evaluation cohorts separate from design decisions.
- Compare a minimal baseline and the proposed evidence approach under identical conditions; report coverage, false alarms and attack-specific misses.
- Resolve suspicious-success coverage without automatically flagging benign travel or VPN use, then evaluate on genuinely new, frozen cohorts.
- Integrate a selected customer-side IdP in shadow mode and validate event trust, minimization and operational friction with consented local data.
- Run on an actual IBM Z environment before claiming platform execution or hardware-backed security.

These are future research/deployment steps, not capabilities established by the current demo. See the [model release decision](model_tuning.md), [retention boundaries](retention_policy.md) and [Datathon brief](datathon_demo.md).
