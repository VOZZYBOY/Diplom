from collections import Counter

from evals.corpus import build_corpus


def test_eval_corpus_has_expected_group_sizes():
    corpus = build_corpus()
    counts = Counter(case.group for case in corpus)

    assert len(corpus) == 550
    assert counts == {
        "direct_injection": 100,
        "jailbreak_roleplay": 100,
        "exfiltration": 100,
        "output_leakage": 100,
        "benign": 100,
        "indirect_injection": 50,
    }


def test_eval_corpus_has_expected_labels_and_directions():
    corpus = build_corpus()

    assert all(case.direction in {"input", "output"} for case in corpus)
    assert all(case.expected in {"allow", "block"} for case in corpus)
    assert all(case.direction == "output" for case in corpus if case.group == "output_leakage")
    assert all(case.expected == "allow" for case in corpus if case.group == "benign")
