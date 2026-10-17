"""Bounded standard-library candidate inference, separate from the baseline.

Candidate artifacts are data-only JSON, never arbitrary pickle/code uploads.
This module does not activate a model; experiment gates control eligibility.
"""
from __future__ import annotations
import hashlib
import json
import math

from .tuning_features import columns, vector, vector_names


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def seal(model):
    model['integrity'] = digest({k: v for k, v in model.items() if k != 'integrity'})
    return model


def validate(model):
    try:
        if model['schema_version'] not in ('els-tuned-logistic-v1','els-tuned-boosted-v1') or model['synthetic_only'] is not True or model['missing_policy'] != 'abstain':
            raise ValueError
        if model['feature_columns'] != columns(model['variant']) or model['vector_names'] != vector_names(model['variant']):
            raise ValueError
        if not isinstance(model['model_version'], str) or not 1 <= len(model['model_version']) <= 100:
            raise ValueError
        for name in ('training_digest', 'protocol_digest'):
            if not isinstance(model[name], str) or len(model[name]) != 64 or any(c not in '0123456789abcdef' for c in model[name]):
                raise ValueError
        def finite(x):
            return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)
        n = len(model['vector_names'])
        names = ('means','scales','coefficients') if model['schema_version']=='els-tuned-logistic-v1' else ('means','scales')
        for name in names:
            if not isinstance(model[name], list) or len(model[name]) != n or not all(finite(x) for x in model[name]):
                raise ValueError
        if any(x <= 0 for x in model['scales']) or not finite(model['intercept']):
            raise ValueError
        if model.get('sequence_policy','baseline_v2') not in ('baseline_v2','corroborated_context_v3'):
            raise ValueError
        if model['schema_version']=='els-tuned-boosted-v1':
            if not finite(model['learning_rate']) or not 0 < model['learning_rate'] <= 1 or not 1 <= len(model['trees']) <= 200:
                raise ValueError
            for tree in model['trees']:
                if set(tree) != {'left','right','feature','threshold','value'}:
                    raise ValueError
                size = len(tree['left'])
                if not 1 <= size <= 127 or any(not isinstance(values,list) or len(values)!=size for values in tree.values()):
                    raise ValueError
                for i in range(size):
                    left,right,feature = tree['left'][i],tree['right'][i],tree['feature'][i]
                    if any(type(v) is not int for v in (left,right,feature)) or not finite(tree['threshold'][i]) or not finite(tree['value'][i]):
                        raise ValueError
                    if left == right == -1:
                        if feature != -2: raise ValueError
                    elif not (i < left < size and i < right < size and left != right and 0 <= feature < n):
                        raise ValueError
        cal = model['calibration']
        if set(cal) != {'slope', 'intercept'} or not all(finite(x) for x in cal.values()) or cal['slope'] <= 0:
            raise ValueError
        if set(model['thresholds']) != {'mfa', 'review'}:
            raise ValueError
        for threshold in model['thresholds'].values():
            if threshold is not None and (type(threshold) is not int or not 0 <= threshold <= 100):
                raise ValueError
        mfa, review = model['thresholds']['mfa'], model['thresholds']['review']
        if mfa is not None and review is not None and review < mfa:
            raise ValueError
        if model['integrity'] != digest({k: v for k, v in model.items() if k != 'integrity'}):
            raise ValueError
    except (TypeError, KeyError, ValueError, OverflowError, AttributeError):
        raise ValueError('Candidate artifact is invalid or corrupted.') from None
    return model


def sigmoid(value):
    return 1/(1+math.exp(-value)) if value >= 0 else math.exp(value)/(1+math.exp(value))


def predict(model, row):
    """Caller validates the artifact once at the immutable engine boundary."""
    values = vector(row, model['variant'])
    if values is None:
        return None
    scaled = [(value-mean)/scale for value,mean,scale in zip(values,model['means'],model['scales'])]
    if not all(math.isfinite(x) for x in scaled):
        return None
    if model['schema_version']=='els-tuned-boosted-v1':
        # sklearn tree traversal casts inputs to float32. Preserve its exact
        # split semantics in standard-library inference without numpy.
        import struct
        try:
            scaled = [struct.unpack('f',struct.pack('f',x))[0] for x in scaled]
        except (OverflowError,struct.error):
            return None
        contributions = []
        for tree in model['trees']:
            index = 0
            for _ in range(127):
                if tree['left'][index] == -1:
                    contributions.append(model['learning_rate']*tree['value'][index]); break
                index = tree['left'][index] if scaled[tree['feature'][index]] <= tree['threshold'][index] else tree['right'][index]
            else:
                return None
        reasons = ['Combined nonlinear assessment of prior login evidence and current context; not a causal attribution.']
    else:
        contributions = [value*coef for value,coef in zip(scaled,model['coefficients'])]
        ranked = sorted(zip(model['vector_names'],contributions),key=lambda item:-item[1])
        reasons = [f"{name.replace('_', ' ')}: positive model contribution (+{value:.2f})"
                   for name,value in ranked if value>0][:3] or ['Combined candidate feature assessment']
    linear = model['intercept'] + sum(contributions)
    calibrated = model['calibration']['slope']*linear + model['calibration']['intercept']
    if not all(math.isfinite(x) for x in (*contributions, linear, calibrated)):
        return None
    probability = sigmoid(linear)
    return {'probability': probability, 'risk_score': math.floor(probability*100+.5),
            'calibrated_probability': sigmoid(calibrated), 'score': math.floor(sigmoid(calibrated)*100+.5),
            'raw_margin':linear, 'reasons':reasons,
            'model_version': model['model_version']}


def action(model, score):
    mfa, review = model['thresholds']['mfa'], model['thresholds']['review']
    if score is None or mfa is None or review is not None and score >= review:
        return 'review'
    return 'mfa' if score >= mfa else 'monitor'
