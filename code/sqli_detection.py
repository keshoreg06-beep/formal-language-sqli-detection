"""
Formal Language-Based Detection of SQL Injection Attacks
Implements 4 formal-language-grounded algorithms with realistic evaluation.
"""

import re, math, warnings, random
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.base import BaseEstimator, TransformerMixin
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
warnings.filterwarnings('ignore')

random.seed(42)
np.random.seed(42)

# ============================================================
# FORMAL LANGUAGE FEATURE EXTRACTORS
# ============================================================

class FAFeaturizer(BaseEstimator, TransformerMixin):
    """Finite Automaton (DFA/NFA) based feature extraction."""
    def __init__(self):
        self.dfa_patterns = {
            'union_select':         r'union\s*(all\s*)?select',
            'or_true':              r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
            'and_condition':        r"and\s+\d+\s*=\s*\d+",
            'comment_dash':         r'--',
            'comment_hash':         r'#',
            'comment_block':        r'/\*.*?\*/',
            'quote_dash':           r"'--",
            'quote_hash':           r"'#",
            'stacked_query':        r';\s*(select|insert|update|delete|drop|exec)',
            'information_schema':   r'information_schema',
            'sleep_func':           r'sleep\s*\(',
            'waitfor':              r'waitfor\s+delay',
            'exec_func':            r'exec\s*(\(|master|sp_)',
            'xp_cmdshell':          r'xp_cmdshell',
            'tautology':            r"'\s*=\s*'",
            'hex_encoding':         r'0x[0-9a-f]{2,}',
            'url_encoded_quote':    r'%27|%22',
            'extractvalue':         r'extractvalue\s*\(',
            'updatexml':            r'updatexml\s*\(',
            'version_func':         r'(version\s*\(\)|@@version)',
            'database_func':        r'(database\s*\(\)|schema\s*\(\))',
            'load_file':            r'load_file\s*\(',
            'into_outfile':         r'into\s+(out|dump)file',
            'null_null':            r'null\s*,\s*null',
        }
    def _extract(self, query):
        q = query.lower()
        features = [1 if re.search(p, q, re.IGNORECASE) else 0 
                    for p in self.dfa_patterns.values()]
        tokens = re.findall(r'\w+', q)
        sql_kw = {'select','insert','update','delete','drop','union','from','where',
                  'having','group','order','join','exec','execute','cast','convert',
                  'char','nchar','varchar','alter','create','information'}
        danger_kw = {'union','drop','exec','execute','xp_','sp_','insert','delete'}
        features += [
            sum(1 for t in tokens if t in sql_kw),
            sum(1 for t in tokens if t in danger_kw),
            q.count("'") + q.count('"'),
            q.count('--') + q.count('#') + q.count('/*'),
            sum(1 for c in q if c in '\'";-#/*()=<>!'),
            len(query), len(tokens),
            int('=' in q), int(q.count('=') > 2),
            int(bool(re.search(r'\bor\b', q))),
            int(bool(re.search(r'\band\b', q))),
        ]
        return features
    def fit(self, X, y=None): return self
    def transform(self, X): return np.array([self._extract(q) for q in X])


class PDAFeaturizer(BaseEstimator, TransformerMixin):
    """Pushdown Automaton stack-analysis features."""
    def _pda(self, query):
        stack = []; transitions = 0; max_depth = 0; unmatched = 0
        subquery_depth = 0; nested_quotes = 0; stack_anomaly = 0
        i = 0
        while i < len(query):
            ch = query[i]
            if ch == '(':
                stack.append('('); transitions += 1
                max_depth = max(max_depth, len(stack))
                if re.match(r'\(\s*select', query[i:].lower()): subquery_depth += 1
            elif ch == ')':
                if stack and stack[-1] == '(': stack.pop(); transitions += 1
                else: unmatched += 1; stack_anomaly += 1
            elif ch == "'":
                if stack and stack[-1] == "'": stack.pop(); transitions += 1
                else:
                    stack.append("'"); transitions += 1
                    if len([s for s in stack if s == "'"]) > 1: nested_quotes += 1
            elif ch == '"':
                if stack and stack[-1] == '"': stack.pop(); transitions += 1
                else: stack.append('"'); transitions += 1
            i += 1
        unmatched += len(stack)
        q = query.lower()
        cfg_feats = [
            int(bool(re.search(r'\bselect\b', q))),
            int(bool(re.search(r'\bfrom\b', q))),
            int(bool(re.search(r'\bwhere\b', q))),
            int(bool(re.search(r'\bunion\b', q))),
            int(bool(re.search(r'\bhaving\b', q))),
            len(re.findall(r'\band\b', q)),
            len(re.findall(r'\bor\b', q)),
            int(bool(re.search(r'union.*select', q))),
            int(bool(re.search(r"['\"].*--", q))),
            max_depth, transitions, unmatched, subquery_depth,
            nested_quotes, stack_anomaly, len(stack),
        ]
        return cfg_feats
    def fit(self, X, y=None): return self
    def transform(self, X): return np.array([self._pda(q) for q in X])


class NGramFeaturizer(BaseEstimator, TransformerMixin):
    """N-gram language model anomaly scoring."""
    def __init__(self, n=3):
        self.n = n
        self.mal_ngrams = Counter()
        self.ben_ngrams = Counter()
    def _ngrams(self, text):
        t = text.lower()
        return [t[i:i+self.n] for i in range(len(t)-self.n+1)]
    def fit(self, X, y=None):
        if y is not None:
            for q, lbl in zip(X, y):
                ng = self._ngrams(q)
                if lbl == 1: self.mal_ngrams.update(ng)
                else: self.ben_ngrams.update(ng)
        return self
    def transform(self, X):
        tot_m = sum(self.mal_ngrams.values()) + 1
        tot_b = sum(self.ben_ngrams.values()) + 1
        feats = []
        for q in X:
            ng = self._ngrams(q)
            if not ng:
                feats.append([0, 0, 0]); continue
            ms = sum(self.mal_ngrams.get(g,0)/tot_m for g in ng)/len(ng)
            bs = sum(self.ben_ngrams.get(g,0)/tot_b for g in ng)/len(ng)
            feats.append([ms, bs, ms/(bs+1e-10)])
        return np.array(feats)


# ============================================================
# ALGORITHMS  
# ============================================================

def algorithm1_fa_rf(Xtr, Xte, ytr):
    """FA + TF-IDF → Random Forest"""
    fa = FAFeaturizer()
    Xtr_fa = fa.fit_transform(Xtr, ytr)
    Xte_fa = fa.transform(Xte)
    tfidf = TfidfVectorizer(analyzer='char_wb', ngram_range=(2,4), max_features=500, sublinear_tf=True)
    Xtr_tf = tfidf.fit_transform(Xtr).toarray()
    Xte_tf = tfidf.transform(Xte).toarray()
    Xtr_ = np.hstack([Xtr_fa, Xtr_tf])
    Xte_ = np.hstack([Xte_fa, Xte_tf])
    clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced')
    clf.fit(Xtr_, ytr)
    return clf.predict(Xte_), clf.predict_proba(Xte_)[:,1]

def algorithm2_pda_svm(Xtr, Xte, ytr):
    """PDA/CFG + TF-IDF → SVM"""
    pda = PDAFeaturizer()
    Xtr_p = pda.fit_transform(Xtr, ytr)
    Xte_p = pda.transform(Xte)
    tfidf = TfidfVectorizer(analyzer='word', ngram_range=(1,3), max_features=300,
                            token_pattern=r'\w+|[^\w\s]')
    Xtr_tf = tfidf.fit_transform(Xtr).toarray()
    Xte_tf = tfidf.transform(Xte).toarray()
    Xtr_ = np.hstack([Xtr_p, Xtr_tf])
    Xte_ = np.hstack([Xte_p, Xte_tf])
    sc = StandardScaler(); Xtr_ = sc.fit_transform(Xtr_); Xte_ = sc.transform(Xte_)
    clf = SVC(kernel='rbf', C=10, gamma='scale', probability=True, class_weight='balanced', random_state=42)
    clf.fit(Xtr_, ytr)
    return clf.predict(Xte_), clf.predict_proba(Xte_)[:,1]

def algorithm3_pda_gbm(Xtr, Xte, ytr):
    """FA + PDA → Gradient Boosting"""
    fa = FAFeaturizer(); pda = PDAFeaturizer()
    Xtr_ = np.hstack([fa.fit_transform(Xtr, ytr), pda.fit_transform(Xtr, ytr)])
    Xte_ = np.hstack([fa.transform(Xte), pda.transform(Xte)])
    clf = GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=5, random_state=42)
    clf.fit(Xtr_, ytr)
    return clf.predict(Xte_), clf.predict_proba(Xte_)[:,1]

def algorithm4_ngram_ensemble(Xtr, Xte, ytr):
    """N-gram LM → NB + LR Ensemble"""
    ng = NGramFeaturizer(n=3); ng.fit(Xtr, ytr)
    Xtr_ng = ng.transform(Xtr); Xte_ng = ng.transform(Xte)
    cv = CountVectorizer(analyzer='char_wb', ngram_range=(2,4), max_features=800)
    Xtr_cv = cv.fit_transform(Xtr).toarray(); Xte_cv = cv.transform(Xte).toarray()
    Xtr_ = np.hstack([Xtr_ng, Xtr_cv]); Xte_ = np.hstack([Xte_ng, Xte_cv])
    sc = MinMaxScaler(); Xtr_sc = sc.fit_transform(Xtr_); Xte_sc = sc.transform(Xte_)
    nb = ComplementNB(alpha=0.1); nb.fit(Xtr_sc, ytr)
    lr = LogisticRegression(C=5, max_iter=500, random_state=42, class_weight='balanced')
    lr.fit(Xtr_, ytr)
    prob = (nb.predict_proba(Xte_sc)[:,1] + lr.predict_proba(Xte_)[:,1]) / 2.0
    return (prob >= 0.5).astype(int), prob

def evaluate(yt, yp, yprob, name):
    acc = accuracy_score(yt, yp)
    prec = precision_score(yt, yp, zero_division=0)
    rec = recall_score(yt, yp, zero_division=0)
    f1 = f1_score(yt, yp, zero_division=0)
    auc = roc_auc_score(yt, yprob)
    cm = confusion_matrix(yt, yp)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp/(fp+tn) if (fp+tn) > 0 else 0
    fnr = fn/(fn+tp) if (fn+tp) > 0 else 0
    return {'Algorithm': name,
            'Accuracy': round(acc*100, 2), 'Precision': round(prec*100, 2),
            'Recall': round(rec*100, 2), 'F1-Score': round(f1*100, 2),
            'AUC-ROC': round(auc*100, 2), 'FPR': round(fpr*100, 2),
            'FNR': round(fnr*100, 2), 'TP': int(tp), 'TN': int(tn), 'FP': int(fp), 'FN': int(fn)}

def main():
    print("="*65)
    print("Formal Language-Based Detection of SQL Injection Attacks")
    print("="*65)

    df = pd.read_csv("/home/claude/sqli_project/dataset/sqli_dataset.csv")
    X = df['query'].values; y = df['label'].values
    print(f"\nDataset: {len(df)} | Malicious: {y.sum()} | Benign: {(y==0).sum()}")
    
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    print(f"Train: {len(Xtr)} | Test: {len(Xte)}\n")

    algos = [
        ("FA + Random Forest",        algorithm1_fa_rf),
        ("PDA/CFG + SVM",             algorithm2_pda_svm),
        ("PDA + Gradient Boosting",   algorithm3_pda_gbm),
        ("N-gram Ensemble (NB+LR)",   algorithm4_ngram_ensemble),
    ]

    results = []; cms = {}
    for name, fn in algos:
        print(f"Running {name}...")
        yp, yprob = fn(Xtr, Xte, ytr)
        r = evaluate(yte, yp, yprob, name)
        results.append(r); cms[name] = confusion_matrix(yte, yp)
        print(f"  Acc={r['Accuracy']}%  Prec={r['Precision']}%  Rec={r['Recall']}%  F1={r['F1-Score']}%  AUC={r['AUC-ROC']}%")

    rdf = pd.DataFrame(results)
    rdf.to_csv("/home/claude/sqli_project/results/performance_results.csv", index=False)

    # ---- PLOTS ----
    plt.style.use('seaborn-v0_8-whitegrid')
    colors = ['#1565C0', '#2E7D32', '#BF360C', '#6A1B9A']
    short = ['FA+RF', 'PDA+SVM', 'PDA+GBM', 'NGram\nEns.']

    # Fig 1 – grouped bar chart
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    metrics = ['Accuracy','Precision','Recall','F1-Score','AUC-ROC']
    x = np.arange(len(metrics)); w = 0.18
    for i, (r, c, s) in enumerate(zip(results, colors, short)):
        vals = [r[m] for m in metrics]
        b = axes[0].bar(x + i*w, vals, w, label=s, color=c, alpha=0.85, edgecolor='white')
    axes[0].set_xlabel('Metric', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('Score (%)', fontsize=12, fontweight='bold')
    axes[0].set_title('Performance Comparison – 5 Key Metrics', fontsize=13, fontweight='bold')
    axes[0].set_xticks(x + w*1.5); axes[0].set_xticklabels(metrics, fontsize=10)
    axes[0].set_ylim(50, 105); axes[0].legend(fontsize=9); axes[0].grid(axis='y', alpha=0.3)

    # Error rates
    fpr_v = [r['FPR'] for r in results]; fnr_v = [r['FNR'] for r in results]
    x2 = np.arange(len(short))
    axes[1].bar(x2-0.2, fpr_v, 0.35, label='FPR (%)', color='#E53935', alpha=0.85)
    axes[1].bar(x2+0.2, fnr_v, 0.35, label='FNR (%)', color='#039BE5', alpha=0.85)
    axes[1].set_xlabel('Algorithm', fontsize=12, fontweight='bold')
    axes[1].set_ylabel('Error Rate (%)', fontsize=12, fontweight='bold')
    axes[1].set_title('False Positive & False Negative Rates\n(Lower is Better)', fontsize=13, fontweight='bold')
    axes[1].set_xticks(x2); axes[1].set_xticklabels(short, fontsize=10)
    axes[1].legend(fontsize=10); axes[1].grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig('/home/claude/sqli_project/results/fig1_performance_comparison.png', dpi=150, bbox_inches='tight')
    plt.close()

    # Fig 2 – confusion matrices
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    for ax, (nm, cm_v) in zip(axes.flatten(), cms.items()):
        sns.heatmap(cm_v, annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=['Benign','SQLi'], yticklabels=['Benign','SQLi'],
                    linewidths=1, linecolor='white', annot_kws={'size':16})
        ax.set_title(nm, fontsize=12, fontweight='bold', pad=8)
        ax.set_xlabel('Predicted'); ax.set_ylabel('Actual')
    plt.suptitle('Confusion Matrices – All Algorithms', fontsize=14, fontweight='bold', y=1.01)
    plt.tight_layout()
    plt.savefig('/home/claude/sqli_project/results/fig2_confusion_matrices.png', dpi=150, bbox_inches='tight')
    plt.close()

    # Fig 3 – radar
    fig = plt.figure(figsize=(8, 8)); ax = fig.add_subplot(111, polar=True)
    m5 = ['Accuracy','Precision','Recall','F1-Score','AUC-ROC']
    N = len(m5); angles = [n/float(N)*2*math.pi for n in range(N)]; angles += angles[:1]
    ax.set_xticks(angles[:-1]); ax.set_xticklabels(m5, size=12)
    ax.set_ylim(50, 102); ax.set_yticks([60,70,80,90,100]); ax.set_yticklabels(['60','70','80','90','100'], size=8)
    for r, c, s in zip(results, colors, ['FA+RF','PDA+SVM','PDA+GBM','NGram Ens.']):
        vals = [r[m] for m in m5] + [r[m5[0]]]
        ax.plot(angles, vals, 'o-', lw=2, color=c, label=s)
        ax.fill(angles, vals, alpha=0.07, color=c)
    ax.legend(loc='upper right', bbox_to_anchor=(1.4, 1.15), fontsize=10)
    ax.set_title('Radar Chart: Multi-Metric Comparison', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig('/home/claude/sqli_project/results/fig3_radar_chart.png', dpi=150, bbox_inches='tight')
    plt.close()

    # Fig 4 – AUC horizontal bar
    fig, ax = plt.subplots(figsize=(9, 5))
    yp = np.arange(len(results))
    aucs = [r['AUC-ROC'] for r in results]
    bars = ax.barh(yp, aucs, color=colors, alpha=0.85, edgecolor='white', height=0.5)
    ax.set_yticks(yp); ax.set_yticklabels([r['Algorithm'] for r in results], fontsize=11)
    ax.set_xlabel('AUC-ROC (%)', fontsize=12, fontweight='bold')
    ax.set_title('AUC-ROC Score by Algorithm', fontsize=13, fontweight='bold')
    ax.set_xlim(50, 105)
    ax.axvline(x=90, color='red', ls='--', alpha=0.6, label='90% threshold')
    ax.legend(fontsize=10)
    for b, v in zip(bars, aucs):
        ax.text(b.get_width()+0.5, b.get_y()+b.get_height()/2, f'{v:.1f}%', va='center', fontsize=11, fontweight='bold')
    plt.tight_layout()
    plt.savefig('/home/claude/sqli_project/results/fig4_auc_roc.png', dpi=150, bbox_inches='tight')
    plt.close()

    print("\n" + "="*92)
    print(f"{'Algorithm':<30} {'Acc%':>7} {'Prec%':>7} {'Rec%':>7} {'F1%':>7} {'AUC%':>7} {'FPR%':>6} {'FNR%':>6}")
    print("-"*92)
    for r in results:
        print(f"{r['Algorithm']:<30} {r['Accuracy']:>7} {r['Precision']:>7} {r['Recall']:>7} {r['F1-Score']:>7} {r['AUC-ROC']:>7} {r['FPR']:>6} {r['FNR']:>6}")
    print("="*92)
    print("\nFigures saved to results/")
    return results

if __name__ == "__main__":
    results = main()
