"""Separate contextual safeguard; frozen ML studies keep the original engine.

This rule is advisory and uncalibrated. It requests verification for a new
device AND unfamiliar network AND unusual context, even without failures.
VPN, travel or a new device alone is insufficient. Context can be wrong;
legitimate combined changes can also trigger it. No numeric bonus is added.
"""
import copy
from src.runtime.risk import RiskEngine

GUARD_VERSION = 'els-context-guard-v1'
REASON = 'Successful password login from a new device and unfamiliar network with unusual time or travel velocity; verify the change.'


class GuardedRiskEngine(RiskEngine):
    def ingest(self, event):
        result = super().ingest(event)
        signals = result['signals']
        triggered = (event['event_type']=='login_success' and event['auth_method']=='password'
                     and signals['new_unfamiliar_context'] and signals['unusual_context'])
        if triggered:
            if result['action']=='monitor':
                result['action']='mfa'
                result['action_label']='Recommend additional verification'
            if signals['sequence_action_floor']=='monitor':
                signals['sequence_action_floor']='mfa'
            if REASON not in result['reasons']:
                result['reasons'].append(REASON)
            # Carry this independently triggered evidence across this session's
            # existing two-minute window, including after strong verification.
            self._records[-1]['originating_floors'].append(('mfa',REASON))
        result['context_guard']={'version':GUARD_VERSION, 'triggered':bool(triggered),
                                 'carried':not triggered and REASON in result['reasons'],
                                 'score_changed':False}
        self._records[-1]['result']=copy.deepcopy(result)
        return result
