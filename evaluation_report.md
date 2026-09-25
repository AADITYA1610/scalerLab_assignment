# Evaluation report: KSH prospectus redaction

## Scope and method

The script ran on the supplied DOCX, visiting 4,635 unique Word paragraphs, including text in 76 top-level tables as well as headers and footers. It wrote a new DOCX and 607 logged replacement events: 207 PERSON, 52 EMAIL, 36 PHONE, 236 COMPANY, 67 ADDRESS and 9 CIN. Those are **predictions**, not a count of every true PII occurrence. No SSN, credit-card, date-of-birth or IP-address replacement was logged on this document.

I manually labelled true PII spans in selected **original-document** paragraphs. Each JSON label supplies a paragraph location, type and exact source phrase; repeated phrases can be labelled more than once. The evaluation joins the original paragraph text, labels and CSV predictions by location and character offsets. A true positive (TP) requires the correct type **and identical start/end positions**. A wrong type or an overlong/short match counts as a false positive (FP) plus a false negative (FN). Unlabelled paragraphs are never assumed to be free of PII.

Precision = TP/(TP + FP); recall = TP/(TP + FN); F1 = 2 × precision × recall/(precision + recall). There is no natural number of “true negative entities” in span extraction, so the requested **accuracy** is binary *character-level accuracy* within the labelled paragraphs: the fraction of characters classified correctly as either PII or non-PII, without considering PII type. Ordinary characters greatly outnumber PII characters, so accuracy can look high even with missed names. Exact-span precision and recall are the primary quality measures.

The samples deliberately mix body text, tables, likely contact/entity paragraphs and ordinary legal/financial text. The same developer selected and annotated them, so annotation error and selection bias remain possible. Earlier disjoint samples exposed errors and were used to change the rules; their final scores are **regression checks**. The final 28-paragraph sample was labelled from previously unused locations after the code was frozen. Its predictions were scored once, and **no detector changes were made afterward**. Some names recur in other locations, so this tests new paragraphs, not entirely unseen entities. It is a small, stratified sample, not a random estimate of the complete prospectus.

## Final frozen-code sample

The final_frozen_labels.json file contains 28 paragraphs and 23 labelled PII spans, including 11 paragraphs labelled with no PII. Results for the unchanged submitted code and output/detections.csv:

| Type | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ADDRESS | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| CIN (additional type) | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| COMPANY | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| PERSON | 7 | 0 | 3 | 1.000 | 0.700 | 0.824 |
| **Overall** | **20** | **0** | **3** | **1.000** | **0.870** | **0.930** |

**Binary character accuracy: 2,131 / 2,186 = 0.975.** The three misses are full names with middle initials in a share-allotment narrative: Karunakar N. Bhandary, Narayna B. Shetty and Jayaram N. Shetty. They remain visible in the produced document. This sample contained no EMAIL or PHONE gold spans, so its perfect precision is **not** an email/phone result, and it says nothing empirical about SSNs, cards, DOBs or IP addresses.

To reproduce the **final-run** numbers from the project directory:

```powershell
python evaluate.py --gold final_frozen_labels.json --log "output\detections.csv"
```

## Development history and the 1.000 scores

Each row below records a separate set **before the errors it exposed were fixed**. The code was revised between rows. The first seven samples were subsequently used for rule changes, so their current 1.000 rerun scores measure only whether those previously observed cases still work.

| Sample | Labelled paragraphs | Gold spans | TP | FP | FN | Precision | Recall | F1 | Character accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fresh 1 | 34 | 42 | 33 | 6 | 9 | 0.846 | 0.786 | 0.815 | 0.972 |
| Fresh 2 | 31 | 30 | 23 | 1 | 7 | 0.958 | 0.767 | 0.852 | 0.939 |
| Fresh 3 | 25 | 38 | 33 | 3 | 5 | 0.917 | 0.868 | 0.892 | 0.993 |
| Fresh 4 | 22 | 28 | 23 | 1 | 5 | 0.958 | 0.821 | 0.885 | 0.968 |
| Fresh 5 | 23 | 20 | 19 | 1 | 1 | 0.950 | 0.950 | 0.950 | 0.974 |
| Fresh 6 | 18 | 23 | 21 | 0 | 2 | 1.000 | 0.913 | 0.955 | 0.967 |
| Fresh 7 | 20 | 14 | 13 | 0 | 1 | 1.000 | 0.929 | 0.963 | 0.996 |
| **Final frozen code** | **28** | **23** | **20** | **0** | **3** | **1.000** | **0.870** | **0.930** | **0.975** |

For example, early checks revealed two separate companies merged into one replacement, a company prefix left visible, a generic “Refund Bank” incorrectly flagged, and addresses split across document paragraphs. These examples drove specific revisions. On the earlier 36-paragraph verification_labels.json development set, the current code gives 36 TP, 0 FP, 0 FN and 1.000 character accuracy; similarly, rerunning Fresh 7 now gives 14 TP, 0 FP and 0 FN. **Neither is a valid estimate of whole-document precision or recall**: both were used for tuning. The historical pre-fix numbers above are recorded observations; the current code and CSV reproduce the final row and post-fix regression results, not those historical states.

The 36-paragraph development set itself initially had 33 TP, 0 FP and 3 FN: precision 1.000, recall 0.917, F1 0.957 and binary character accuracy 2,976/3,133 = 0.950. Its subsequent 1.000 result is the same tuning effect, not proof that recall across the document is perfect.

## Required categories without real positive examples

The visited prospectus text yielded no candidates for a US-style SSN, a Luhn-valid credit-card number, an explicitly birth-labelled date or an IPv4 address. Their real-document precision, recall and F1 are **undefined**, not 1.000 or 0.000. The 11 constructed checks in test_detectors.py exercise SSN/card/DOB/IPv4 rules, a non-birth date, a bad card checksum, company boundaries, an address layout and a table-name column. They confirm those examples behave as expected; they are not prevalence or real-world accuracy estimates. Ordinary dates of incorporation and offer activity are intentionally left unchanged.

## Interpretation and limitations

The final sample's three missed names show a remaining recall limitation for some initial-style person names; other uncommon names, unlabelled birthdays, unusual phone formats and fragmented addresses may also be missed. Named companies and trusts are in scope even when publicly listed in the prospectus; broad rules formerly caused false positives on role names and overlong organization spans, which were reduced by context and boundary checks. The mapping is deterministic pseudonymization, not irreversible anonymization. Some aliases of the same real company can receive different synthetic labels. Unprocessed text in embedded images, drawings/text boxes, comments or footnotes may survive.

Cross-paragraph organization replacements are recorded in CSV with a special cross-location; this paragraph-level evaluator does not score cross-paragraph spans. Only the labelled locations were manually checked, so **no full-document recall, precision or accuracy is claimed**. The CSV contains original sensitive strings and must be kept with the unredacted input. A stronger estimate would require independently annotating a larger random selection, and a complete-document claim would require ground truth for the entire document.
