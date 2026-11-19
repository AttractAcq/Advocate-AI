# Preliminary review of the 50 stored answers

This is an internal review of the historical [generated-answer run](answer-evaluation.json),
made on 19 November 2026. The run used the synthetic `qwen3.5:2b` model on
15 November at source commit `16ee5a4`. The 50 questions are in
[`fixtures/evaluation.csv`](../../fixtures/evaluation.csv); the cited fictional
documents and their hashes are in
[`fixtures/manifest.csv`](../../fixtures/manifest.csv). Those fixture files have
not changed since the run's source commit. All 40 allowed-source hashes still
match the manifest, and all 40 expected markers occur in both the source text
and the stored answer. All ten restricted cases have no retrieved source and
return the no-answer response. This checks the **stored run**, not a fresh model
sample or a production document corpus.

I read each stored answer against its matching source. Of the 40 allowed
answers, 34 stay within the source's marker, title, version and fictional
context. Six have an additional wording problem:

| Case | Source fact | Answer issue |
|---|---|---|
| Q-MAN-004 | [MAN-004](../../fixtures/sources/MAN-004.txt) is titled “Port call”. | Calls it “Port Call Collection”, apparently blending the title with a collection field. |
| Q-ENG-006 | [ENG-006](../../fixtures/sources/ENG-006.txt) includes a required fictional action to isolate test equipment. | Says the document “contains no instructions on how to operate machinery or issue control commands”; that overstates what the source establishes. |
| Q-ENG-009 | [ENG-009](../../fixtures/sources/ENG-009.txt) is titled “Spare parts”. | Calls it “Spare parts Collection”. |
| Q-ENG-010 | [ENG-010](../../fixtures/sources/ENG-010.txt) labels its marker synthetic. | Adds that it does not correspond to any real-world security or engineering standard; the source does not make that comparison. |
| Q-INT-009 | [INT-009](../../fixtures/sources/INT-009.txt) is titled “Table setting”. | Calls it “Table setting Collection”. |
| Q-DEC-006 | [DEC-006](../../fixtures/sources/DEC-006.txt) says the fixture tests retrieval and source permissions. | Says it is “used to train retrieval and source permissions”, changing the source's meaning. |

The other allowed cases reviewed without a substantive claim-support exception
are Q-MAN-001–003 and 005–010; Q-ENG-001–005, 007–008; Q-INT-001–008 and
010; and Q-DEC-001–005 and 007–010. Q-RES-001–010 are the ten reviewed
no-answer cases. This classification is a preliminary human reading, not the
independent AT-09 assessment.

The automated report's `source_label_in_answer` field is a text proxy: only
32 of 40 answers include an ID/version label in the model's prose. The report
stores retrieved document IDs but does **not** capture the Core API's citation
object, passage ordinal, source hash or the exact passage sent to the model.
It therefore cannot establish citation correctness for the end-to-end chat
path. The Phase 3 gate still needs an independent claim/citation reviewer, an
agreed AT-09 quality threshold, and a new evaluation that retains structured
citation evidence. The six wording exceptions should be included in that
review, and any mitigation should be judged against a broader, non-marker
corpus before claiming improved grounding.
