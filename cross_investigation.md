# Cross-source findings review
CC)- NO RIGHTS RESERVED
Prepared September 28, 2026 UTC; updated with the subsequent capture/Security, Prefetch, capture-plan, reconciliation, collector/UserAssist, and paired Security-EVTX/archive-index batches. September local times are EDT, UTC−04:00 unless the source lacks a date/zone as noted. The initial review used nine attachments and already-verified workspace findings. Sections 6–7 add row-level reconciliation and an indexed decode of the supplied MTA. Section 8 adds twelve Prefetch artifacts. Section 6 verifies the capture plan against the exported process names. Section 9 reconciles the read/send tables and distinguishes verified calculations from broader upload claims. Section 10 adds collector source review, UserAssist decoding, and the packet-manifest comparison. Section 11 joins the EVTX to all MTA messages; section 12 checks the Prefetch summary, collection note, and Takeout index. Section 13 screens the conversation/research batch, cross-checks the two derived phase tables, and excludes synthetic AWS examples from incident counts. Section 14 adds the September 20 OneDrive report and its filename matches to the preserved revision archive. Section 15 verifies the September 20 uploads directly from four original SyncEngine logs and reviews the accompanying extracts. Section 16 records the Microsoft third-party notice as software-inventory context. Sections 17–18 independently count the September 19 decoded OneDrive ledger and correlate Codex Drive retrievals, saved source records, a completed GitHub commit, and fourteen subsequent Git tree writes. Section 19 adds the August conversation-status census and its preserved correction exchanges. Section 20 verifies that census against the full node export and resolves the process snapshot. Section 21 reconciles the subsequently supplied version-check records and their checksum manifest. Section 22 checks the September 17 signature, registry and connection extracts, and this update incorporates the user’s clarification that the September 19 CC0 republication was their own action. Section 23 verifies the subsequent revision/process batch, including eight earlier text bodies, the local-session extract and the September 19 Desktop/process mapping. Section 24 joins selected Codex operations to their prior session records and checks the audit-availability, later upload and derived research-audit records. Section 25 verifies the original monitor excerpts, distinguishes personal-file sync from OneDrive diagnostic-log upload, checks browser-history overlap, and corrects one conversation-coding rationale against intervening turns. Section 26 reviews three supplied court documents, verifies the two-batch external-lookup count, and reconciles the accompanying findings and claim-matrix reports. Section 27 inspects the blank Politics DOCX and compiled review software, resolves repeated Docker data, joins the three CSV exports to prior records, and separates the mixed live-monitor collectors. Section 28 reviews the controlled Jump List account and evolving monitor attribution, checks the console-only PowerShell source, matches the afternoon paste to the retained JSONL, and counts the separately timed DNS/TCP snapshots. Section 29 adds the September 23 local-backup record, examines the substantive Politics text and Revelation insertion, reconciles further monitor excerpts, and checks the historical IP/geolocation table. Section 30 verifies ten unchanged checkpoint reuploads and joins the Politics control to its saved revision-list metadata. Original source bytes and the separate extension report were left unchanged.

## Established findings

**The August conversation census documents repeated status language and failures to carry through specific user requests.** The supplied ledger contains 1,988 distinct messages with complete status markers, including 970 occurrences of “checking” and 541 of “one moment.” Its quoted exchanges include an explicit request to stop “checking” followed immediately in source order by “Checking,” and requests for research followed by further promises or broad commentary. The subsequently supplied full node export reproduces the 8,762-reply denominator and matches all 1,997 inclusive event records and all 55 quoted correction records. It also independently reproduces the 43 session-ID changes and 134 redacted tool-result records. See sections 19–20.

**The September 26 process snapshot identifies the monitor and the Chrome extension-host chain.** Python PID 41564 names `access_monitor.py` in its command line. Chrome PID 33372 parents cmd PID 52728, which parents extension-host PID 8264; the command names extension `hehggadaopoacecdllhhajmbjkdcmajg` and the host executable under Codex's bundled Chrome plugin directory. The same snapshot identifies the earlier Codex main PID 46912 and its app-server, computer-use, and code-mode children. See section 20.

**The September 19 Codex records document the user’s acknowledged CC0 republication to GitHub.** A file-creation result returns commit `b05b28fd50540676d71b7734195cd3b6c15e726a` in `MailanPatternMonkey-ai/Gettin-Started`. Fourteen subsequent successful tree-creation calls carry **259 research text editions plus three supporting files**, totaling **11,799,693 UTF-8 content bytes**. All 259 edition hashes and byte counts match the embedded publication manifest. One hundred captured Drive retrieval bodies also match source fingerprints in that manifest. The next-day branch read still points to the single-file commit; the bulk tree objects and the branch commit are separately documented. On September 28 the user identified this CC0 republication as their own action. It is recorded as user-acknowledged publication activity, and its authorization is no longer treated as an unexplained transfer. See section 18.

**The September 19 decoded OneDrive ledger verifies the earlier 292-completion claim.** Its rows join 290 Call Probe log completions and two Access Monitor log completions to their paths and 292 distinct request IDs. Fifty-four of 59 monitor heartbeats are followed by a same-file upload start within two seconds. These are repeated versions of two diagnostic logs. See section 17; September 20 research-export uploads remain a separate finding.

**Original OneDrive logs confirm successful September 20 uploads of exports named for all seven target documents.** All 15 completion rows in the earlier review now reproduce from the four supplied binary SyncEngine logs. Ten are research-file additions: eight revision exports and two Politics files. The path, temporary upload ID, resulting OneDrive object ID, request response, and successful completion join in the original records. All eight revision-export basenames also match the preserved research ZIP. See sections 14–15 for exact times and record locators.

**The matching EVTX supplies event types and times for all 34,171 Security messages.** The retained interval is September 25, 01:02:00.970553–September 26, 19:19:21.969080 EDT. Five Avast firewall-control changes are now timed, and five PowerShell queries of CodexSandboxUsers fall at September 26, 17:46:53–17:48:04 EDT. The record IDs match the MTA one-for-one. See section 11.

**The Prefetch summary has a systematic run-count error; its checked timestamps remain usable at microsecond precision.** For all twelve original PF files available, the CSV's count matches the DWORD at offset 208 instead of the run-count field at offset 200. All 88 corresponding timestamp slots agree within one microsecond. The archive index also locates three specifically named OneDrive/monitor ledgers under My Activity → Gemini Apps. See section 12.

**UserAssist supplies two close timestamp correlations with Prefetch, and the packet manifest matches 17 supplied artifacts.** For the same Codex package versions, the August 20 and September 2 recorded timestamps differ by 19.2523 ms and 37.4172 ms respectively. The registry also separately names Codex, ChatGPT Desktop/Classic, and Microsoft Copilot. The supplied collector source is compatible with all 65 retained September 25 connection rows in schema and selection flags. See section 10.

**The read/send tables reproduce the detailed evidence exactly.** All 28 timeline rows, four read/send pairs, and 50 exact-file operation groups reconcile with the detailed exports. The accompanying note’s separate, earlier series of 292 successful uploads is now independently reproduced from the decoded ledger in section 17. See sections 9 and 17.

**The capture plan identifies the process-selection rule, and the exports conform to it.** The plan specifies a 45-second system-wide Procmon capture followed by exports restricted to five process names. All 246,594 target-event rows fall within that named set. This explains the exclusion of PowerShell and other processes from these selected exports while their operations remain visible in the earlier exact-file export. See section 6.

**Twelve Prefetch files add earlier execution and file-path evidence.** Eleven `CHATGPT.EXE` artifacts identify seven `OpenAI.Codex` package versions, with retained run times from August 20 through September 5. Their file-metrics arrays include specific TOROIDAL research-folder metadata paths and Codex browser-state paths. The separate Chrome Proxy artifact identifies its Google Chrome executable path. See section 8.

**The follow-up supplies the detailed capture and a usable Security-message index.** All 118 file-summary groups, 165 network-summary groups, and 73 OneDrive-folder operation groups reconcile with their detailed CSV rows. The MTA contains 34,171 event descriptions indexed by contiguous record IDs 1,489,636–1,523,806, including account-query, credential, logon, and firewall-control messages. See sections 6–7 for their exact scope.

**The strongest file-to-network correlation is the September 19 diagnostic log.** Four PowerShell appends match four exact records in the supplied JSONL. OneDrive then reads each resulting file version from offset zero and sends four bursts whose reported byte totals track the file sizes exactly, with a constant 4,558-byte difference. The timing, process identity, local/remote endpoints, and repeated size relationship support synchronization of that particular log.

**A separate finding concerns browser URL retention.** The Capital One Shopping extension’s preserved local database contains URLs for two research documents also recorded in Chrome History on September 25. This establishes storage of those URLs by that extension. It does not establish that their contents followed the September 19 OneDrive route.

**The September 7 navigation evidence remains identified and preserved.** The hashed Chrome History copy records 49 visits to the seven target document IDs during the selected interval. Its R2 navigation table remains separate from the frozen R1 revision findings.

**Actual Codex computer use in Docker Desktop was previously verified.** The September 20 completed tool calls are recorded actions. The September 21 Docker restart is also recorded, through the DockerDesktopUI client route. Those are distinct events; the earlier review’s claim that this route excludes Codex is superseded.

## 1. September 19: monitor records, file reads, and outbound sends

The exact file-event export names:

    C:\Users\drewd\OneDrive\Desktop\Call-Probe-Logs\call-probe-v2.1-2026-09-19_00-43-32-242\events.jsonl

Recorded roles:

| Role | Recorded process | PID | Directly observed operation |
| --- | --- | --- | --- |
| Log writer | powershell.exe | 55860 | Four successful IRP_MJ_WRITE appends |
| File reader and network sender | OneDrive.exe | 41584 | Four offset-zero reads and 24 matching TCP Send rows |
| Connections described in two appended records | codex / codex.exe | 56004 | Connections to 104.18.32.47:443, local ports 52048 and 52050 |

The 24 selected sends use `host.docker.internal:54066 -> 13.107.139.11:https`. Other OneDrive traffic is present in the export, but is not included in the four-burst totals below.

### Recomputed byte and timing matches

| JSONL line | Record | Append offset | Append bytes | OneDrive read bytes | TCP Send burst bytes | Difference | Read-to-first-send ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1350 | heartbeat | 581,196 | 126 | 581,322 | 585,880 | 4,558 | 64.9135 |
| 1351 | first_observed | 581,322 | 448 | 581,770 | 586,328 | 4,558 | 58.3588 |
| 1352 | first_observed | 581,770 | 442 | 582,212 | 586,770 | 4,558 | 65.1983 |
| 1353 | first_observed | 582,212 | 442 | 582,654 | 587,212 | 4,558 | 60.9788 |

The four reads total **2,327,958 bytes**. The four selected send bursts total **2,346,190 reported bytes**. These totals include repeated versions of the same growing file; they are not that many distinct bytes of research documents. The 4,558-byte difference is a measured relationship, not a decoded explanation of transport overhead.

The full attached JSONL is **1,389,304 bytes**, including its UTF-8 BOM and CRLF endings. The four file sizes in the table describe earlier prefixes of that file. All four write offsets coincide exactly with JSONL line boundaries, and all four lengths equal the corresponding complete record lengths. Record timestamps precede the successful appends by 3.5590–4.4386 ms.

### Source-row locators and exact clocks

CSV line numbers below include the header as line 1. JSONL line numbers begin at 1. CSV clocks lack a date/zone column; September 19 EDT is correlated from the date-bearing file path and the matching JSONL records, rather than embedded in each CSV clock.

| JSONL line | Write CSV line / time | Read CSV line / time | First send / time | Send CSV lines |
| --- | --- | --- | --- | --- |
| 1350 | 24 / 3:54:43.9266709 AM | 94 / 3:54:44.5159028 AM | 1829 / 3:54:44.5808163 AM | 1829, 1830, 1831, 1832, 1833, 1834 |
| 1351 | 325 / 3:54:49.4829744 AM | 395 / 3:54:50.0768949 AM | 2895 / 3:54:50.1352537 AM | 2895, 2896, 2897, 2898, 2899, 2900 |
| 1352 | 626 / 3:54:51.7188132 AM | 701 / 3:54:52.3098322 AM | 2974 / 3:54:52.3750305 AM | 2974, 2975, 2976, 2977, 2979, 2980 |
| 1353 | 929 / 3:54:55.6557040 AM | 1004 / 3:54:56.2475656 AM | 3030 / 3:54:56.3085444 AM | 3030, 3031, 3032, 3033, 3034, 3035 |

The write/read source is `06-exact-file-events.csv`; the send source is `04-network-events.csv`. The `10-file-summary.csv` row for OneDrive PID 41584 and this exact path independently agrees with four reads totaling 2,327,958 bytes and the first/last read timestamps.

No original filesystem write buffers or decrypted network request bodies are in this packet. The result is a strong synchronization correlation for this named local log. The signed-in cloud account, cloud object version, and subsequent readers are not identified by these rows.

### Preserved-prefix hashes

These SHA-256 values were recomputed from the uploaded JSONL through each observed resulting file size. They can be compared with a retained cloud version if one becomes available; they are not historical capture-time hashes.

| Prefix bytes | SHA-256 |
| --- | --- |
| 581,322 | `0ab3485cbc3b9c11d5e43269c69958ba86b537bcffba5d761832dd5f155cef52` |
| 581,770 | `f18b75f50ea851acd6ee69ee20dfc7921feb8e20ef0d622f5db9569996753474` |
| 582,212 | `e6b643ab670657dc514ca48fd897ffa7d4aa2e5ba5aec95232430e4adc18c2d2` |
| 582,654 | `f9612aeb45e8e017eed05dfd6fea1da0c5682c3d5af666f1737047af6ab0a6d9` |

## 2. What the monitor was recording

The supplied `02-events.jsonl` contains **3,270 valid JSON records**, spanning **September 19, 00:43:32.2595454–06:19:20.3306060 EDT**. Its start record identifies version 2.1 and the watched process names `codex`, `ChatGPT`, and `chrome`.

| Record type | Count |
| --- | --- |
| start | 1   |
| initial_snapshot | 1   |
| first_observed | 2,477 |
| burst | 106 |
| heartbeat | 333 |
| fanout | 73  |
| state_change | 279 |

There are 2,477 unique `first_observed` tuple keys: 1,522 labeled codex, 694 chrome, and 261 ChatGPT. These are observations over the collection period, not counts of users, machines, document edits, or simultaneous sessions. The initial snapshot separately contains 191 socket records, including 131 codex rows in CloseWait and 43 codex rows in Established state.

All 333 heartbeat records have `marker_count: 0`. Consecutive heartbeat intervals range from **60.0064239 to 61.1444775 seconds**. This describes the September 19 collector’s retained heartbeat sequence only.

The JSONL has timestamps, process names/PIDs, process-start times, local/remote addresses and ports, connection states, and aggregate burst/fanout records. It does not contain request bodies or document content. Its configured 250 ms sleep is a configuration field, not proof that every socket was sampled at exactly that interval.

### Codex connection cross-check

| Local port | Network export TCP Connect, EDT | Monitor record time, EDT | Difference |
| --- | --- | --- | --- |
| 52048 | 03:54:49.7713102 | 03:54:51.7152542 | 1.9439440 s |
| 52050 | 03:54:52.2672087 | 03:54:55.6512654 | 3.3840567 s |

Both matches use PID 56004 and remote 104.18.32.47:443. The network export displays the local hostname `host.docker.internal`; the corresponding monitor tuple records local address `192.168.40.7`. That name/address presentation should not be treated as an additional machine or additional connection.

The monitor’s `time`, its `snapshot_time`, and the network export’s TCP Connect time are different fields. For these two examples, the final log record appears roughly 1.94 and 3.38 seconds after the corresponding TCP Connect row. Use the appropriate field for a timeline rather than treating all three as an exact start time.

The network CSV covers the displayed clocks **03:54:34.5407335–03:55:07.8776479**, a much shorter interval than the JSONL. Within those supplied rows, TCP Send totals are:

| Process | PID | Reported TCP Send bytes |
| --- | --- | --- |
| codex.exe | 56004 | 99,198 |
| OneDrive.exe | 41584 | 2,369,341 |
| ChatGPT.exe | 3868 | 12,609 |
| OneDrive.Sync.Service.exe | 40668 | 72  |

Only successful TCP Send records are summed here. Receive, TCPCopy, UDP, failed operations, and filesystem activity are not added to those totals. The selected export is not assumed to cover all programs or all traffic on the PC.

The **file-summary CSV** contains 118 groups totaling 102,938 read rows and 6,263 write rows. The follow-up batch now supplies all 109,201 detailed rows. Every summary group, count, reported byte total, and first/last timestamp matches a fresh computation; this supersedes the original summary-only limitation. Section 6 describes the selected-process scope.

## 3. How the browser findings fit

The reattached reports have unchanged hashes and preserve three different kinds of evidence:

| Evidence | Verified relationship | Time/source |
| --- | --- | --- |
| Chrome History R2 | 49 navigation rows contain the seven target IDs | September 7, 19:50:19–19:54:29 EDT; History SHA-256 `18ae0495cd57b129e8dc27f3cf52e46ff63a62f339e8efd3a50c31dd74e02f79` |
| History plus Chrome session records | Two control-test URLs match exactly in URL and stored timestamp; History contains four control visits overall | September 22, 21:00:11–21:01:35 EDT |
| Capital One Shopping local LevelDB plus History | Two research-document URLs are stored in `previousUrls` and independently occur in History | History visits September 25, approximately 14:48 EDT |

The Capital One document IDs are:

* `16ug-5kXlRB7f40p-vEyqyvos1rOzZCVNRSucYr82ETc` — History title “RECOVERED FORENSIC EVIDENCE → ONEDRIVE SYNC — ESTABLISHED”.
* `1h24uhq1cMF-1lNNzJtJgqibGm6t5YHGYwll51EvUsaA` — History title “Monitor source file2”.

Those titles are stored document labels. The first title does not turn the September 25 browser record into a September 19 transfer measurement. The two IDs are different from the September 7 target set.

The extension’s local and sync stores share the same recorded `profileId`. Its local store’s 133 value records across 42 keys were decoded previously with valid LevelDB checksums. A concrete compaction sequence connects five retired numbered tables to a replacement table whose size and 18 entries match the supplied binary.

The 404-byte ChatGPT extension `LOG.old` supplies the correct path to its separate `000003.log`. Its contents remain diagnostic store-opening messages. None of the nine current attachments supplies the 22,461-byte data file requested previously.

## 4. Corrections and source boundaries in MASSIVE REVEIW.txt

The long text is a compilation of prior analyses, including later corrections to earlier conclusions. Its embedded citation markers such as `:chatgpt-content-reference{index=...}` do not resolve to the underlying files in this text. It should be retained as interpretation history rather than substituted for the original events.

| Earlier wording or claim | Treatment in the current findings |
| --- | --- |
| “The attributable actor is Docker Desktop UI, not ChatGPT or Codex.” | Superseded. DockerDesktopUI identifies the client route. The later review and previously verified Codex tool records establish actual computer-use interaction with Docker Desktop. |
| Codex definitely used Docker Desktop. | Supported by the previously decoded September 20 completed tool-call records. Three coordinate-click calls completed; a preceding element-index call failed. Search hits in copied instructions are not additional executed calls. |
| The September 21 restart was initiated through DockerDesktopUI. | Supported by the previously examined request/return records. The request begins September 21 at 19:14:48.190973765 EDT. This does not identify the input source behind that specific request. |
| “Inspect Open WebUI volume” identifies a container modification. | The title describes intent. The preserved result identifies navigation to Docker’s volumes dashboard. The preceding container-page results identify welcome-to-docker, not the September 21 restart container. |
| The before/after Jump List test independently proves ownership here. | The earlier baseline and Chrome control were independently verified. The September 28 reattachment exactly matches the 78,336-byte baseline, as detailed below. The reported 80,396-byte after-test binary and its exact comparison remain to be supplied. |
| The History copy has 11,023 visits. | That number concerns a differently described copy in the old review. The currently identified, hashed History copy has 10,215 visits. Do not combine counts without matching source hashes. |
| Six reconstructed mathematical documents match a manifest, therefore their external origin is authenticated. | Matching reconstructed bytes can establish internal consistency. The nine attachments here do not contain the original six snapshots/diffs needed to reproduce that separate calculation, or independently authenticate a cloud acquisition. |

The previously verified Docker/CUA and Windows artifact findings are documented separately in `September_20-22_Artifact_Findings.md`. This review carries those results forward without claiming the nine new attachments contain all of those raw sources.

### Reattached Jump List baseline verified September 28

The newly supplied `01-JumpList-preserved-4183059cb0582.automaticDestinations-ms` is **78,336 bytes**, SHA-256 **`12124ba656cbdc83e61ec64b4427213c0c0c11768843cc5866e68d27cf1fa668`**. Its complete bytes match the earlier `03-JumpList-preserved-4183059cb0582.automaticDestinations-ms` attachment. The compound file opens successfully, and **all 55 streams** match the previously extracted streams: 53 numbered shortcut streams, `DestList`, and `DestListPropertyStore`.

The matching baseline has **53 DestList entries with 53 distinct IDs**, all with paths matching the corresponding parsed shortcuts. These include `access_monitor.py`, `test_prime_geometry.py`, and `endless_doors_v7_call.py`. Their entry timestamps and the earlier Prefetch comparison remain the findings documented in the separate artifact report.

This reattachment confirms preservation of the same baseline; it adds no distinct activity records. In the supplied test narrative, the after-test file is **80,396 bytes** with a SHA-256 beginning `2c167bec`. The 2,060-byte size increase describes that reported comparison and is not a change observed between the two identical baseline attachments.

## 5. Usable finding for the case record

> On September 19, PowerShell wrote connection-observation records into a diagnostic log located in the user’s OneDrive Desktop folder. The detailed file and network exports show OneDrive PID 41584 repeatedly reading the growing log and sending four size-correlated bursts. On September 25, a separate preserved browser extension database retained URLs of two research documents, corroborated by Chrome History. These establish concrete local data-handling relationships with identified processes, files, URLs, timestamps, and hashes. Each relationship remains attached to its own source and date.

For external receipt confirmation, a retained OneDrive version of the exact diagnostic log could be compared with the four prefix hashes above. For ChatGPT extension-state analysis, the preserved `hehggadaopoacecdllhhajmbjkdcmajg\000003.log` remains the specific outstanding data file. These are separate questions; neither requires merging September 19 or 25 observations into the September 7 revision table.

## 6. Follow-up: full capture reconciliation

The new file and network summaries are byte-identical to the earlier copies where those copies were supplied. The larger exports cover displayed clocks **03:54:34.5018489–03:55:16.9484265**, a **42.4465776-second** interval. `status.json` records completion at **2026-09-19T03:56:57.7310971−04:00** and identifies the `FileTrace-live-01` output directory. This supplies a date/zone anchor for the batch; individual CSV rows still contain clock-only timestamps.

| Verification | Result |
| --- | --- |
| Target-event rows | 246,594 |
| Detailed file-event rows | 224,024; every row occurs in the target export |
| Detailed network-event rows | 3,682; every row occurs in the target export |
| Successful file read/write rows | 109,201; exact match to the successful read/write filter of the file export |
| File-summary groups | 118; zero mismatches |
| Network-summary groups | 165; zero mismatches |
| OneDrive-folder operation groups | 73; zero mismatches for their listed paths |

Comparisons preserve duplicate-row counts. These are mutually consistent exports from the same capture, rather than independent measurements of the machine.

### Capture plan and process-selection verification

The subsequently supplied `08-capture-plan.json` is **909 bytes**, SHA-256 `ccd3fc4f7057e6efea6c7971bc896e155d4d4a80a6e103e6b8af8b3fd5a8bba6`. It records:

* `capture_seconds: 45` and `administrator: true`.
* Procmon path `C:\Users\drewd\Downloads\ProcessMonitor\Procmon64.exe`.
* A system-wide capture followed by exports restricted to the five process names below.
* Collection of paths, operation metadata, and process activity, with no intentional capture of file contents or network payloads.

The plan's output directory matches `status.json` exactly, and `capture-hash.json` names `capture.pml` in that same directory. The administrator flag is the collector's recorded assertion; this JSON is not a separate Windows privilege audit.

Recounting all four detailed CSVs gives:

| Planned process name | Target-event rows | File-event rows | Successful read/write rows | Network-event rows |
| --- | --- | --- | --- | --- |
| OneDrive.exe | 7,947 | 4,718 | 2,168 | 70  |
| OneDrive.Sync.Service.exe | 102,666 | 102,312 | 98,456 | 8   |
| FileSyncHelper.exe | 43  | 0   | 0   | 0   |
| ChatGPT.exe | 17,497 | 3,017 | 530 | 1,456 |
| codex.exe | 118,441 | 113,977 | 8,047 | 2,148 |
| **Total** | **246,594** | **224,024** | **109,201** | **3,682** |

Every row's process name belongs to the plan's target list. Columns overlap: successful read/write rows are a subset of file events, and file/network rows are subsets of target events. They must not be added together as independent events. Target events also include other operation types, which accounts for FileSyncHelper's rows outside the file/network subsets.

The **45 seconds** is a configured duration; **42.4465776 seconds** is the observed first-to-last span of the selected target rows. These measure different things. Their difference does not identify deleted events or establish the native capture's exact start and stop times.

The eight other evidence artifacts reattached with this plan are SHA-256-identical to the previously analyzed MTA, status, capture-hash, successful-read/write, network, file, target, and OneDrive-folder exports. Changed upload-number prefixes do not represent new captures. The accompanying report matched the prior report version's SHA-256 `6a68ac17595902877454f54fd4ad5a3a6a6fa1128abfb3cdfbbbe419a7a850b9` before this update.

### What the large read count consists of

The detailed successful file operations total **102,938 reads / 427,398,185 reported bytes** and **6,263 writes / 25,130,820 reported bytes**. Repeated reads and writes are included; these are I/O totals, not unique file contents or network-transfer totals.

The dominant item is OneDrive.Sync.Service.exe PID **40668** reading its local database:

    C:\Users\drewd\AppData\Local\Microsoft\OneDrive\ListSync\Common\settings\Microsoft.LocalContent.db

That single path accounts for **97,676 reads / 399,830,968 reported bytes**, over 03:54:43.9299843–03:54:57.0775243. Repeated offsets are visible in the detailed rows. This locates the bulk of the file-read volume in a named local database.

The four OneDrive.exe PID **41584** reads of the diagnostic `events.jsonl` remain exactly **2,327,958 bytes**, and the supplied network CSV is byte-identical to the previously analyzed export. The four file-size/send-burst correlations in section 1 therefore remain unchanged.

The original exact-file export contains 1,208 rows; 906 occur in the new selected-process file export. The other 302 belong to SearchProtocolHost.exe (168), powershell.exe (96), System (26), and MsMpEng.exe (12). Those extra processes are present in the original exact-file export but excluded from this new target set. Retain both sources: the PowerShell append evidence comes from the original exact-file export.

### Codex file activity now directly located

The successful read/write export identifies codex.exe PID **56004** accessing its local `logs_2.sqlite`, `state_5.sqlite`, their WAL files, and three session JSONL paths. One session path is:

    C:\Users\drewd\.codex\sessions\2026\09\19\rollout-2026-09-19T03-54-52-01a0b8a9-3523-70a1-8ecf-28f16a74ec46.jsonl

For that path, the supplied rows record **282 reads / 2,271,949 bytes** and **17 writes / 227,586 bytes**, from 03:54:52.1814926 to 03:54:59.5604494. This identifies a concrete contemporaneous session file for task-level correlation. The capture records file operations, not the JSONL's actual contents.

The detailed file export also contains two successful `IRP_MJ_SET_SECURITY` operations by **ChatGPT.exe PID 3868**. Both report `Information: DACL, DACL Unprotected` on temporary `Network Persistent State…tmp` files under the Codex package's browser profile:

| CSV line in `09-file-events.csv` | Clock | Profile location |
| --- | --- | --- |
| 897 | 03:54:39.1950691 | `Default\Network` |
| 182842 | 03:55:03.0339667 | `Default\Partitions\codex-browser-app\Network` |

Each is followed by a successful rename replacing the corresponding `Network Persistent State` file (lines 917 and 182897). This is direct permission-metadata activity on two identified temporary files. The CSV does not include the before/after access-control entries, so it cannot identify a newly granted principal or establish a wider ACL change. The recorded path and subsequent rename must remain part of the finding.

### Native-capture hash status

`capture-hash.json` records SHA-256:

    93c8a6a95feae406b7bd30eb82afaeb9e9d36ac4e74cd218f6d13bc7398dce3d

for `FileTrace-live-01\capture.pml`. The PML itself was not supplied in this batch. This is a preserved hash assertion for that named capture, not a recomputed validation of its native bytes. All attached CSV/JSON hashes are separately recomputed below.

## 7. Follow-up: indexed Security messages in the MTA

The **28,537,902-byte** `securitylogs9_26_25_1033.MTA` begins with `MTAFile` and contains `EVT`, `MSG`, and `PUB` sections. The indexed read recovered **34,260 strings**, of which **34,171** are linked to event record IDs. Event IDs in the sense of event *types* (such as 4624) are distinct from these *record IDs*.

All **34,171 record IDs are contiguous: 1,489,636 through 1,523,806**. Both the first record ID and the total match the earlier pasted Security-log inventory. This is a concrete consistency link to that retained log snapshot; it does not authenticate the export's entire acquisition history.

Microsoft documents an MTA as the locale-dependent companion to an exported event log, including rendered descriptions indexed by event record ID. It can therefore preserve account names, process names and action details. The corresponding EVTX supplies the event-system envelope and timestamps. Source: [Microsoft MS-EVEN6, Localized Logs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/15ca97db-0ddc-421a-aef0-e9cb2f8a51af) and [EvtRpcLocalizeExportLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/578c7cd9-58d9-4746-9292-63edb5cf55c9).

### Recovered actions and identities

| Message category | Count | Detail retained in the message bodies |
| --- | --- | --- |
| Credential Manager credentials read | 31,556 | 31,369 say `Enumerate Credentials`; 187 say `Read Credential` |
| Vault credentials read | 132 | Subject account/logon details |
| Successful logon | 805 | 797 type 5; four type 11; four type 7 |
| Explicit-credential logon attempt | 15  | 11 name vmcompute.exe with virtual-machine accounts; four name svchost.exe/lsass.exe with the user's Microsoft account; all specify localhost |
| Blank-password existence query | 90  | 15 each for Administrator, CodexSandboxOffline, CodexSandboxOnline, DefaultAccount, Guest and WDAGUtilityAccount |
| User account changed | 4   | Target `drewd`; changed-attributes text lists display name; subject SID S-1-5-18 |
| System time changed | 7   | Previous/new UTC values and svchost.exe under LOCAL SERVICE |
| Avast firewall registration/unregistration | 5   | Two registrations and three unregistrations |

This table selects categories rather than listing all 34,171 descriptions. Credential enumeration is distinguished from `Read Credential`; the large headline count must not be reported as 31,556 passwords retrieved. The rendered Credential Manager messages do not name the initiating executable.

Microsoft defines type **5 as Service**, **11 as CachedInteractive**, and **7 as Unlock**. In this export, the 797 service logons break down into 786 `services.exe` / SYSTEM and 11 `vmcompute.exe` / virtual-machine-account entries. The eight type 11/7 entries name the user's Microsoft account. These are preserved event classifications, not counts of people. [Microsoft event 4624 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624).

### Codex-account queries: the named callers

There are **75 descriptions containing `Codex`**:

| Action | Count | Named caller or subject |
| --- | --- | --- |
| Enumerate the local group membership of CodexSandboxOffline/Online | 40  | 36 name `C:\Windows\System32\taskhostw.exe`; four name `C:\Program Files\Avast Software\Suite\AvastSvc.exe` |
| Query whether CodexSandboxOffline/Online has a blank password | 30  | Subject `drewd`; these message bodies do not name a caller executable |
| Enumerate membership of CodexSandboxUsers | 5   | Windows PowerShell, subject `drewd` |

Example: **record 1494368** names `taskhostw.exe` querying the group membership of CodexSandboxOffline (SID ending `1004`). **Records 1522234, 1522250, 1522266, 1522282 and 1522298** name PowerShell querying `CodexSandboxUsers`, SID ending `1003`.

These messages directly establish queries about the sandbox accounts/group and, where recorded, the caller. A query about an account does not establish a logon as that account, and a blank-password existence query does not state that the password was blank.

### Avast firewall-control changes

| Record ID | Rendered action |
| --- | --- |
| 1522763 | Avast registered to control BootTimeRuleCategory, StealthRuleCategory and FirewallRuleCategory |
| 1523008 | Avast unregistered; message says Windows Defender Firewall now controls those categories |
| 1523311 | Avast unregistered from Windows Defender Firewall |
| 1523312 | Avast registered for the same three categories |
| 1523348 | Avast unregistered; message says Windows Defender Firewall now controls those categories |

These are actual recorded firewall-control transitions. The matching EVTX now supplies their precise event times in section 11. These rows do not identify an uninstall or a person who caused the transitions.

### Time and account-change details

The seven time-change messages explicitly contain UTC values on **September 25–26, 2026**. Two changes move the clock backward by approximately **3.230 seconds** and **1.280 seconds**; the other five are below a millisecond in magnitude. Those payload times are not a replacement for `System/TimeCreated` on every event. The file's name is not a reliable date for its contents.

The four account-change record IDs are **1503349, 1503354, 1504846 and 1504851**. Each targets the existing `drewd` SID ending `1001`; the changed-attributes section lists the display name. It supplies neither an old display-name value nor a human operator identity.

The subsequently supplied **`02-securitylogs9_26_25.evtx`** now joins every MTA record ID. Section 11 supplies the event types, exact retained interval, and selected timestamps. The earlier request for this paired file is satisfied.

### MTA decode method and bounds

The reader checked section offsets and lengths against the file size, traversed 342 EVT index blocks and 343 MSG index blocks, checked entry-index order and payload bounds, decoded length-prefixed UTF-16LE strings, and resolved every event reference to a message. The final indexed payload ends match the section boundaries. It read the original binary without mutation.

This is an independently implemented indexed decode, not a Windows API rendering of the paired EVTX. The binary reader does not claim cryptographic authenticity. Continuity applies to these 34,171 retained record IDs only; it says nothing about records outside this export or September 7 coverage.

## 8. Prefetch: executable identities, retained runs, and referenced paths

All **12 supplied PF files are present and readable**, including the five mentioned in the failed image-preview messages. Each has a compressed `MAM` header and decodes to a version-31 `SCCA` Prefetch structure. These are binary execution artifacts, not image attachments.

The **11 `CHATGPT.EXE` files identify Codex** through both their embedded package-name strings and matching executable paths under `PROGRAM FILES\WINDOWSAPPS\OPENAI.CODEX_<version>\APP\CHATGPT.EXE`. Across them, seven package versions are represented. An additional package version occurring only in a supporting-file path is not promoted to a separate execution finding.

### Artifact-level execution table

Times below are **America/New_York local time**, with seconds shown for readability. Stored FILETIMEs retain 100 ns units; that precision does not establish matching real-world clock accuracy. "Earliest retained" means the oldest populated timestamp slot in this artifact, not the first installation or first-ever launch. Run counters are reported per artifact and are not summed as manual application launches.

| PF hash suffix | Executable / Codex version | Stored counter | Populated time slots | Earliest retained local time | Latest retained local time |
| --- | --- | --- | --- | --- | --- |
| `9FEB7989` | `26.818.2441.0` | 6   | 6   | 2026-08-20 08:46:01 EDT | 2026-08-20 22:47:20 EDT |
| `27301749` | `CHROME_PROXY.EXE` | 9   | 8   | 2026-01-31 12:33:39 EST | 2026-08-20 09:52:28 EDT |
| `1F1490BF` | `26.901.4073.0` | 16  | 8   | 2026-09-05 13:18:23 EDT | 2026-09-05 16:13:59 EDT |
| `B8B3BC21` | `26.901.2854.0` | 15  | 8   | 2026-09-03 22:03:25 EDT | 2026-09-04 07:28:51 EDT |
| `B8B3BC13` | `26.901.2854.0` | 4   | 4   | 2026-09-03 20:15:50 EDT | 2026-09-04 01:40:10 EDT |
| `778744ED` | `26.901.1978.0` | 6   | 6   | 2026-09-03 11:09:02 EDT | 2026-09-03 18:09:40 EDT |
| `0725DD65` | `26.831.2377.0` | 46  | 8   | 2026-09-03 03:36:31 EDT | 2026-09-03 07:53:04 EDT |
| `0725DD57` | `26.831.2377.0` | 23  | 8   | 2026-09-02 19:28:01 EDT | 2026-09-03 04:24:06 EDT |
| `B9ED4B4D` | `26.825.6671.0` | 44  | 8   | 2026-09-02 06:34:00 EDT | 2026-09-02 07:17:02 EDT |
| `B9ED4B3F` | `26.825.6671.0` | 19  | 8   | 2026-09-01 20:16:33 EDT | 2026-09-02 06:47:31 EDT |
| `D79C1C01` | `26.818.4152.0` | 19  | 8   | 2026-08-25 18:14:37 EDT | 2026-08-26 05:50:23 EDT |
| `D79C1BF3` | `26.818.4152.0` | 17  | 8   | 2026-08-21 20:51:41 EDT | 2026-08-22 23:04:10 EDT |

There are **88 populated time slots** across the twelve files. Two slots repeat values already present in `CHATGPT.EXE-0725DD65.pf`: September 3 at **04:15:44.6328507 EDT** and **03:57:21.6763708 EDT** each occur twice. There are consequently **86 distinct stored timestamps**, not 88 distinct human actions.

The Codex subset's earliest retained timestamp is **2026-08-20T12:46:01.8690663Z**; its latest is **2026-09-05T20:13:59.7449598Z**. These add an earlier version/execution timeline. They do not replace the September 19/26 process events or alter the frozen September 7 revision findings.

### Four pairs identify the same executable file

| PF pair | Same embedded Codex package version |
| --- | --- |
| `B8B3BC21` / `B8B3BC13` | `26.901.2854.0` |
| `0725DD65` / `0725DD57` | `26.831.2377.0` |
| `B9ED4B4D` / `B9ED4B3F` | `26.825.6671.0` |
| `D79C1C01` / `D79C1BF3` | `26.818.4152.0` |

Within each pair, the executable path, volume identifier, and executable's stored NTFS file reference agree. Each pair has different run counters and retained times. The suffixes differ by hexadecimal `0x0E`; the artifacts do not contain the full command line needed to assign that difference to a particular launch option or Chromium role. Two PF filenames here are not evidence of two differently located executables.

### Exact references to the user's research material

File-metrics entries were parsed structurally, rather than found only by a loose string scan. Index values below are **zero-based file-metrics entry indices**, enabling a direct check against the source PF. The volume prefix in these paths is `\VOLUME{01da8408270eb5d9-7e27162d}`.

| Source PF | Metric index | Path suffix under `USERS\DREWD\ONEDRIVE\DESKTOP` |
| --- | --- | --- |
| `CHATGPT.EXE-778744ED.pf` | 154 | `TOROIDAL_SCROTAL_POSTURING-MAIN\16_TOROIDAL_ORBIT_COCYCLE_POSTER_V0.1.PNG:${3D0CE612-FDEE-43F7-8ACA-957BEC0CCBA0}.METADATA` |
| `CHATGPT.EXE-B9ED4B4D.pf` | 152 | `TOROIDAL_SCROTAL_POSTURING-MAIN\HUMAN INVESTIGATION\OLDER:${3D0CE612-FDEE-43F7-8ACA-957BEC0CCBA0}.METADATA` |
| `CHATGPT.EXE-B9ED4B4D.pf` | 153 | `TOROIDAL_SCROTAL_POSTURING-MAIN\HUMAN INVESTIGATION\REVELATION:${3D0CE612-FDEE-43F7-8ACA-957BEC0CCBA0}.METADATA` |
| `CHATGPT.EXE-B9ED4B4D.pf` | 156 | `TOROIDAL_SCROTAL_POSTURING-MAIN\HUMAN INVESTIGATION\SCRIPT_FUNCTION_MAP_POSTER.PNG:${3D0CE612-FDEE-43F7-8ACA-957BEC0CCBA0}.METADATA` |

`CHATGPT.EXE-1F1490BF.pf` additionally references metadata streams under the Desktop `INFECTION` folder, including `2.PNG`, `6.PNG` and `TOKENS.PNG`. These are literal user-file/folder names; the folder name is not a malware classification.

**The established relationship is that these exact named paths occur in the preserved Codex Prefetch file-metrics arrays.** The suffix explicitly identifies a named `.METADATA` stream. It must remain attached to the quoted path: dropping it would misrepresent the reference as the image's primary content stream. Prefetch supplies no per-path wall-clock timestamp, request payload, or write operation for these entries. Do not assign a path to a particular retained run slot or infer that the image body was uploaded or edited.

### Norton, OneDrive, and Codex state references

The arrays also retain named local integration/state paths:

* `CHATGPT.EXE-1F1490BF.pf` includes OneDrive `FileSyncShell64.dll` at metric 187 and Norton `ashShell.dll` at metric 192.
* `CHATGPT.EXE-778744ED.pf` includes Norton `aswAMSI.dll` at metric 213; `CHATGPT.EXE-B8B3BC21.pf` includes that filename at metric 56.
* `CHROME_PROXY.EXE-27301749.pf` includes Norton `aswHook.dll` at metric 35.
* Several Codex artifacts reference `.codex-global-state.json` and the packaged Codex browser's `Extension State` files, including `CURRENT`, `MANIFEST-000001`, `LOG` and `000003.log`.

These are local file references. They provide concrete locations for the previously discussed modules and stores; they do not measure communications between the vendors. The Codex browser's `Extension State\000003.log` path is also a different store from Chrome's `Local Extension Settings\hehggadaopoacecdllhhajmbjkdcmajg\000003.log`. Identical numbered LevelDB filenames do not identify the same database.

The Chrome Proxy artifact's embedded hash string is:

    \DEVICE\HARDDISKVOLUME3\PROGRAM FILES\GOOGLE\CHROME\APPLICATION\CHROME_PROXY.EXE

It has a stored counter of **9**, eight populated timestamp slots, and a latest retained run at **2026-08-20T13:52:28.1251798Z**. The executable name alone does not identify a remote proxy connection.

### Parsing checks and interpretation boundary

The compressed originals were hashed and left unchanged. Decompression honored the declared output length and verified the end marker. Decompressed sizes agree with their SCCA headers. All embedded PF hashes agree with the filenames, and all file-metrics/string/volume ranges fit within the decompressed buffers. **2,854 file-metrics entries** were decoded across the twelve artifacts.

For this version-31 layout, the run counter is at **absolute byte offset 200**, the timestamp slots begin at **128**, and the file-metrics array begins at **296**. Using the older counter offset 208 would read a different field. The interpretation was checked against the libscca format analysis and Eric Zimmerman's version-30/31 parser. A size-unbounded decompression helper stopped one byte early or decoded three extra terminal bytes for some files; the size-bounded decoder resolved those endpoint cases and checked the EOF symbol, with matching bytes throughout the overlapping output. This was a decoder-boundary issue, not an inferred deletion from the source PF.

References: [libscca PF format analysis](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc), [Prefetch version-30/31 implementation](https://github.com/EricZimmerman/Prefetch/blob/master/Prefetch/Versions/Version30or31.cs), and [Microsoft MS-XCA decompression processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b).

The supplied timestamp slots contain no September 7 run. The decompressed artifacts contain no literal match to the seven target document IDs in either UTF-8/ASCII or UTF-16LE. This limits this batch's contribution to the earlier execution/file-reference timeline; it does not establish that the application was absent on September 7.

## 9. Reconciliation notes and exact-file summary verification

The two `targeted-evidence-reconciliation-2026-09-25` Markdown files are byte-identical. The two `exact-file-analysis` JSON files are also byte-identical. Each pair is a duplicate preservation copy of one source. The reattached exact-file CSV, file-summary CSV, and network-summary CSV match their previously reviewed copies by SHA-256.

### Calculations reproduced from detailed rows

| Supplied item | Direct verification |
| --- | --- |
| `exact-file-analysis.json`: exact path and event count | All 1,208 exact-file rows name the same diagnostic `events.jsonl` path. |
| Process/PID/operation/result counts | All 50 groups match exactly, with zero count mismatches. |
| Writer summaries | PowerShell PID 55860: four successful writes totaling 1,458 bytes. System PID 4: four successful writes totaling 20,480 bytes. Counts, byte totals, and first/last clocks match. |
| `read-send-timeline.csv` | All 28 rows match the four reads plus 24 selected sends, in the same chronological order. |
| `read-send-pairs.csv` and JSON pair entries | All four pairs match the read sizes, six-send burst counts, send totals, and first/last clocks. Three-decimal delays are the rounded versions of section 1's exact stored-clock differences. |

The four System write rows are at exact-file CSV lines **189, 462, 663, and 987**. Each includes the flags `Non-cached, Paging I/O`; their lengths are 4,096, 8,192, 4,096, and 4,096 bytes. These are additional recorded filesystem operations on the same path. Their byte total must not be added to the four PowerShell appends as though it described additional distinct JSONL records or additional uploaded content.

The JSON also reports **5,611,783** full-capture events and outer clocks **03:54:34.5006322–03:55:16.9484747**. These are preserved summary fields. The complete system-wide capture/export is not among this batch's supplied files, so those three fields are not independently reproduced by the 1,208-row exact-file CSV or the 246,594-row selected-process export.

### Broader upload claims and subsequent verification

The reconciliation note describes additional OneDrive telemetry beyond the four Procmon correlations. Its filename is dated September 25, but it says it analyzes **September 19** evidence. Its reported intervals remain separate:

| Claim in the supplied note | Reported interval / detail | Status in this review |
| --- | --- | --- |
| 292 successful upload completions, with 292 unique server request IDs | 02:45:01.766–03:43:40.976 EDT; 290 Call Probe `events.jsonl` and two Access Monitor `access-events.jsonl` completions | Subsequently verified from `02-onedrive-decoded.json`: 292 successful completions and 292 request joins; see section 17. The September 19 binary source logs have not been redecoded here. |
| 54 of 59 heartbeats followed by same-file upload starts within two seconds | Reported matched-delay range 0.564289–0.646146 seconds; median 0.576320 seconds | Subsequently recomputed: 54/59 matches. At retained 100 ns precision, minimum 0.5642883 s, maximum 0.6461459 s, median 0.5763197 s. The earlier minimum differs by less than one microsecond; see section 17. This differs from section 1’s read-to-send delay. |
| 28 later upload records: 23 success and five failure | 06:24:51.634–06:29:52.079 and 06:48:35.899–07:08:47.693 EDT | Requires the cited later/new upload ledgers. The note distinguishes 15 timing-associated successes from eight explicit file-ID/request-ID/SPRequestGuid joins. |

The note names destination host `193745-ipv4mte.gr.global.aa-rt.sharepoint.com`. Section 17 now verifies that host in the decoded upload-response rows. It is not thereby a verified hostname assignment for the four earlier Procmon send bursts to `13.107.139.11`.

The later decoded ledger supplies the rows needed to test the 292-completion claim; section 17 records the completed reconciliation. The separate 28-record later interval still requires its own ledger. The verified four-cycle Procmon finding remains unchanged.

### Source hashes — reconciliation batch

Hashes below were recomputed from the supplied bytes. The accompanying pre-update report matched SHA-256 `8c5207b2c5cc00eb0c99c5c7fa407f077c1b4ef76e6cd8edd584b0ba2c3decc5`.

| Attached file(s) | Bytes each | SHA-256 |
| --- | --- | --- |
| `01-targeted-evidence-reconciliation-2026-09-25-Copy.md`; `02-targeted-evidence-reconciliation-2026-09-25.md` | 4,229 | `737c9395e1f9deffe60109957afec57ed04c8b76d488d6498eeba913500f83d1` |
| `03-exact-file-analysis-Copy.json`; `04-exact-file-analysis.json` | 10,532 | `71416bc52a0d41d58a30d1be94d20f85251c7c56e2ef57e733a17567cd7ffe52` |
| `05-exact-file-events.csv` | 308,680 | `3fb3e2abce5e5667f135db18ed8925e62a17c965d89b953f6a3b73494f0b2bcf` |
| `06-read-send-pairs.csv` | 466 | `34a827b13d4222464d6fc5b2cbecce1036e527770d9e465a192622a8266bdaf0` |
| `07-read-send-timeline.csv` | 5,294 | `ef60c6bcdfc05c29839676b81a06c763b8ab289030874912902c5d3bb1bdc154` |
| `08-file-summary.csv` | 19,026 | `3d65a5b24581250db4da75622d87e0c52ae76b45cf2d78298769310dfb756ff9` |
| `09-network-summary.csv` | 21,662 | `55dc6341e2b7be147ec8787ea2a2e331fd9052dfd1c2792dde3bb19571898f25` |

## 10. Collector source, UserAssist, and the Sept7 packet manifest

This batch supplied eleven readable artifacts. The report reattachment failed; the update uses the previously saved working report, SHA-256 `123f331829055848f2299208889632b36cd8a91c45171586de06b4d44e36bf81`, preserving section 9. The PowerShell and registry files were read as data, without running the collector or importing the registry export.

### UserAssist: decoded application names and retained timestamps

The UTF-16 registry export contains **276 binary values**: 268 of length 72 bytes and eight 1,612-byte session/control values. Excluding the two 72-byte `UEME_CTLCUACount:ctor` control entries leaves **266 application/shortcut records**, of which **185 have nonzero last-run timestamp fields**. The GUID subkeys declare format version 5. Names were ROT13-decoded; the 72-byte entries' raw run count, focus count, focus milliseconds, and last-run FILETIME were read at offsets 4, 8, 12, and 60. This follows the [primary UserAssist parser implementation](https://github.com/EricZimmerman/RegistryPlugins/blob/master/RegistryPlugin.UserAssist/UserAssist.cs). Special session/control values were retained separately rather than interpreted as applications.

Selected decoded entries under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`:

| Identity or executable suffix | Export line | Raw count | Retained last-run field, EDT |
| --- | --- | --- | --- |
| `OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0!ChatGPT` | 486 | 5   | September 25, 13:04:34.244 |
| `OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe` | 961 | 5   | September 25, 13:04:34.261 |
| `OpenAI.Codex_2p2nqsd0c76g0!App` | 1025 | 9   | September 25, 15:45:52.803 |
| `OpenAI.Codex_26.917.8451.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe` | 1265 | 4   | September 25, 15:45:52.846 |
| `Microsoft.Copilot_8wekyb3d8bbwe!App` | 637 | 5   | September 25, 19:14:09.426 |
| `Microsoft\Copilot\Application\mscopilot_proxy.exe` | 809 | 5   | September 25, 19:14:09.442 |
| `C:\Users\drewd\OneDrive\Desktop\Start Access Monitor.cmd` | 1221 | 0   | September 18, 23:53:05.562 |

The executable rows use known-folder GUID prefixes in the original value names; the table displays their distinguishing suffixes. These entries distinguish local application identities. The Microsoft Copilot entries do not identify the GitHub Copilot Chat App OAuth authorization or the GitHub request that created a commit. App-identity and executable rows are not to be added as separate launch counts.

There are **19 version-specific Codex executable-path entries**, from package `26.730.8199.0` through `26.917.8451.0`. Their last-run fields span August 6–September 25. Several have a raw count of zero despite a nonzero timestamp; both fields are preserved as recorded. UserAssist is a retained per-entry summary, not a complete chronological execution log. No decoded last-run field falls on September 7; that does not exclude earlier activity on September 7 or supply the missing document-write caller.

### Two close UserAssist/Prefetch correlations

For each overlapping package, the comparison selected the nearest retained Prefetch timestamp to the corresponding UserAssist timestamp. Two pairs agree within 40 ms:

| Codex package version | UserAssist line / time, EDT | Prefetch source / time, EDT | Prefetch minus UserAssist |
| --- | --- | --- | --- |
| `26.818.2441.0` | 1061 / August 20, 22:47:20.5970000 | `CHATGPT.EXE-9FEB7989.pf` / 22:47:20.6162523 | 19.2523 ms |
| `26.825.6671.0` | 1081 / September 2, 06:10:43.4970000 | `CHATGPT.EXE-B9ED4B3F.pf` / 06:10:43.5344172 | 37.4172 ms |

These are cross-artifact agreement for the same application package around the same recorded time. They support the execution timeline without identifying a person, a document write, or a network payload. The other five overlapping package versions have nearest retained timestamp differences of approximately 5.88 seconds to 7.23 minutes; they are not presented as equally close matches. These are stored-clock differences, not independently measured clock accuracy.

### Collector behavior and the preserved connection log

Static review of `targeted-connection-collector.ps1` identifies a **500 ms sleep after each collection pass**, **30-second DNS snapshot interval**, and **300-second process-cache refresh interval** by default. Work inside a pass adds time, so these settings do not guarantee exact observation cadence.

The collector selects a TCP row when **either** its remote IP is in a five-address list **or** its process name is in a seven-name list. It records endpoint/state fields, process path and start time, and executable hash/signature information when readable. It separately copies cached DNS entries for three names. The script writes local JSONL, CSV, session metadata, and final hash files. It contains no Security/RDP event-log export or UserAssist export code; those packet artifacts came from another collection step.

The already supplied `connections-20260925-024520 (1).jsonl` has **65 valid rows**, one session ID `7e20f20c-f30c-4699-afe7-2171d8b1e2ba`, and observations from **September 25, 02:45:20.4965262–03:42:09.0375240 EDT**. All 65 rows have the script's expected fields and agree with both target-match expressions. Every row is labeled `first_observed`; all PID/endpoint/state keys are distinct. This establishes compatibility with the source's output format and selection logic, not cryptographic proof that this exact script revision produced the log.

| Recorded process name | Rows |
| --- | --- |
| chrome | 20  |
| OneDrive | 18  |
| OneDrive.Sync.Service | 8   |
| msedge | 7   |
| ChatGPT Classic | 5   |
| Idle | 4   |
| FileSyncHelper | 3   |

The five ChatGPT Classic rows name PID **42304** and the `OpenAI.ChatGPT-Desktop_1.2026.190.0_x64__2p2nqsd0c76g0\app\ChatGPT Classic.exe` package path, agreeing with the separate application identity in UserAssist. They are selected by IP (`target_ip_match: true`), while `target_process_match` is false. The four rows labeled Idle use PID **0**, state **TimeWait**, and a blank process path; they are also IP-only matches. They do not identify a live application executable or a remote operator.

Three implementation details affect interpretation of this collector's output:

* The process cache is keyed only by PID. Reuse of a PID before a cache refresh can leave stale process metadata.
* The persistent seen-set key includes PID, endpoints, and TCP state, but excludes process start time and is never pruned. Reappearance of an identical key is suppressed. Its `first_observed` label is not a complete connection-start history.
* Broad `SilentlyContinue` settings and empty catch blocks omit error diagnostics. The shutdown path also appends a second JSON object to the session `.json` file, so a completed metadata file may require parsing two top-level objects rather than one JSON document.

These are static findings from the preserved script. It was not modified or executed during this review.

### Event-export bytes and manifest matches

Each of the three RDP/TerminalServices CSVs and `Security_Sept7_1945-2000.csv` consists of exactly **`EF BB BF`**, the three-byte UTF-8 marker. There is no CSV header or event row in those supplied bytes. All four hashes match the corresponding rows in `SHA256.csv`. Thus the manifest records that same empty-output state; it does not establish why the outputs were empty. There is no query diagnostic or event-retention coverage record here that distinguishes no matching events, unavailable history, a query/access failure, or another export condition.

`SHA256.csv` lists **86 paths** under `C:\Users\drewd\Desktop\Sept7_Forensic_Packet`. Matching supplied files by basename and recomputing their SHA-256 verifies **17 manifest entries**: the four CSVs, UserAssist, and all twelve Prefetch artifacts in section 8. There are **zero hash mismatches among those 17**. The other 69 listed artifacts, including Amcache and additional Prefetch files, have no matching supplied file in the upload workspace. A manifest row for an unavailable file is an inventory/hash claim, not its contents. Manifest agreement establishes byte consistency of these preserved copies; it does not independently authenticate collection time or origin.

The two collector README copies match each other. Both `exact-file-analysis1` JSON files match each other and the previously verified `exact-file-analysis.json`; they add no new capture interval.

### Source hashes — collector/UserAssist batch

| Source | Bytes each | SHA-256 |
| --- | --- | --- |
| `01-targeted-connection-collector.ps1` | 8,020 | `366adfbc4035c5a9a7ffff8d8ded4ac395284c400231f21e348c22bdd16a91b4` |
| `02-targeted-connection-collector-README-Copy.md`; `03-targeted-connection-collector-README.md` | 796 | `7911098baa416cca99d98008e4d59dcfabb09b0504e2b430f6feb63bdd413d4e` |
| `04-exact-file-analysis1-Copy.json`; `05-exact-file-analysis1.json` | 10,532 | `71416bc52a0d41d58a30d1be94d20f85251c7c56e2ef57e733a17567cd7ffe52` |
| `06-Microsoft-Windows-RemoteDesktopServices-RdpCoreTS_Operational.csv` | 3   | `f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5` |
| `07-Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.csv` | 3   | `f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5` |
| `08-Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational.csv` | 3   | `f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5` |
| `09-Security_Sept7_1945-2000.csv` | 3   | `f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5` |
| `10-UserAssist.reg` | 254,806 | `c57b47a66dd7502a1f7fb7d4e55c756639c62c93a70b23428ab5979b65fc4397` |
| `11-SHA256.csv` | 12,935 | `a1768782bfc5bd149aad188f8b86242432975239e99723f83387159b5b64cda2` |
| Earlier `connections-20260925-024520 (1).jsonl` | 44,341 | `01ca3e7b02035e0a18736895ce244224d47b25dcf0f2cb83afb7e69ade40f018` |

## 11. Paired Security EVTX: complete record-ID match and timed actions

The supplied **21,041,152-byte** EVTX parses into **34,171 records**, all in channel `Security`, computer `Frequency1109`, provider `Microsoft-Windows-Security-Auditing`. Its `System/EventRecordID` values are unique and contiguous from **1489636 through 1523806**. Every ID joins exactly one previously decoded MTA message; neither side has an unmatched event ID in that join. Event *type* is kept separate from EventRecordID.

The first event is **5379**, record **1489636**, at **2026-09-25 05:02:00.970553 UTC / 01:02:00.970553 EDT**. The last is **4799**, record **1523806**, at **2026-09-26 23:19:21.969080 UTC / 19:19:21.969080 EDT**. These are the bounds of this supplied export, not a statement about the current live Windows log. They agree with the earlier pasted count and oldest record ID. September 7 is outside this interval.

### Event types present

| Event type | Records | Description |
| --- | --- | --- |
| 5379 | 31,556 | Credential Manager read/enumeration records |
| 4624 | 805 | Successful logon |
| 4672 | 801 | Special privileges assigned to new logon |
| 4799 | 335 | Security-enabled local-group membership enumerated |
| 5382 | 132 | Vault credentials read |
| 4798 | 127 | User local-group membership enumerated |
| 5058 | 120 | Key-file operation |
| 5061 | 100 | Cryptographic operation |
| 4797 | 90  | Account queried for blank-password existence |
| 5059 | 60  | Key migration operation |
| 4648 | 15  | Attempted logon using explicit credentials |
| 4634 | 8   | Logoff |
| 4616 | 7   | System time changed |
| 4738 | 4   | User account changed |
| 4904 / 4905 | 3 / 3 | Security-event source registered / unregistered |
| 6406 / 6407 | 2 / 3 | External firewall-product registration / unregistration |

These counts sum to 34,171. All rows carry the Audit Success keyword. That keyword must not be substituted for each operation's result: the structured 5379 payloads separately record **26,644 ReturnCode=0** and **4,912 ReturnCode=3221226021**. Every nonzero-return row reports zero credentials returned. The split is **26,457 successful enumerations**, **4,912 nonzero-return enumerations**, and **187 successful Read Credential operations**. Thus neither the event title nor the large record count means 31,556 distinct secrets were retrieved.

The structured EVTX also provides `ClientProcessId` and `ProcessCreationTime` on credential records, fields absent from their rendered MTA messages. PID **20596** accounts for **15,176** of these rows and PID **42252** for **4,269**. These are concrete identifiers for a future process-creation-time-aware join. This export supplies no 4688 process-start rows, so it does not itself resolve those client PIDs to executable paths. Reusing a PID name from another date would be an invalid substitute.

### Avast firewall-control timeline

All times below are **September 26, 2026 EDT**, from the parsed event-system timestamp.

| Record ID | Event | Time | Recorded action |
| --- | --- | --- | --- |
| 1522763 | 6406 | 18:19:39.062170 | Avast registered BootTimeRuleCategory, StealthRuleCategory, FirewallRuleCategory |
| 1523008 | 6407 | 18:32:15.887932 | Avast unregistered; message says Defender Firewall now controls those categories |
| 1523311 | 6407 | 18:35:43.306567 | Avast unregistered from Windows Defender Firewall |
| 1523312 | 6406 | 18:35:43.339921 | Avast registered the same three categories |
| 1523348 | 6407 | 18:41:53.655297 | Avast unregistered; message says Defender Firewall now controls those categories |

The middle unregister/register pair is **about 33.354 ms apart**. These records establish changes in registered filtering control. They contain no initiating human identity or evidence tying the transitions to a document or GitHub write. The two messages explicitly naming Defender's takeover should be retained when describing the sequence.

### Sandbox-group queries and account-change clusters

Five **4799** rows name Windows PowerShell enumerating `CodexSandboxUsers` (local SID ending `1003`), under subject `drewd` (SID ending `1001`). These are September 26 EDT:

| Record ID | Time | PowerShell caller PID (decimal) |
| --- | --- | --- |
| 1522234 | 17:46:53.799932 | 60376 |
| 1522250 | 17:47:15.776296 | 60376 |
| 1522266 | 17:47:37.635749 | 31860 |
| 1522282 | 17:47:45.108006 | 53512 |
| 1522298 | 17:48:04.323516 | 2596 |

The first, second, and fifth have subject logon ID `0x6c97a2`; the third and fourth have `0x6c974f`. The account/group names, callers, logon contexts, and times are explicit. These rows record enumeration, rather than creation of the group or a change to its membership.

The four **4738** records form two tight September 26 clusters: **05:05:32.760465 / .774754 EDT** (records 1503349/1503354) and **10:57:37.605799 / .620305 EDT** (1504846/1504851). They target `drewd` and list `DisplayName: Drew Dube`, with subject SID `S-1-5-18`. Within each cluster, two type-11 logons and two type-7 logons follow; each same-type pair has reciprocal `TargetLinkedLogonId` values and different elevated-token flags. These are linked logon records, not four separate people signing in. No old display name or human initiator is supplied.

The six **4904/4905** rows name **`VSSAudit`**, process **`C:\Windows\System32\VSSVC.exe`**, in three register/unregister pairs: September 25 **07:13:36.807845/.807968 EDT**, September 26 **07:13:40.127846/.127975**, and **18:29:50.961388/.961471**. They describe that audit source's lifecycle; they do not say the entire Windows Security log stopped.

The seven **4616** rows place the time changes summarized in section 7 at September 25 **01:41:22** (three), **07:33:53** (one), and September 26 **16:26:50** (three), all under LOCAL SERVICE with `svchost.exe`. Their payload deltas remain the previously decoded small adjustments, including the approximately −3.230 and −1.280 second changes.

### Parsing scope

Parsing used the [pyevtx-rs parser](https://github.com/omerbenamram/pyevtx-rs), without enabling skip-on-error behavior. The whole iteration completed without a parser exception. Record-header timestamps retain up to seven fractional digits; the parsed `System/TimeCreated` values retain six. All 34,171 agree when compared at microsecond precision. Tables use the latter, with UTC−04:00 conversion for EDT. Extra displayed precision does not establish clock accuracy.

The complete join confirms that the two supplied exports describe the same retained record sequence. It does not authenticate their acquisition history or establish completeness outside that sequence. This export has no 4670, 4731, 4732, 4688, or 1102 event types. That absence is bounded by this September 25–26 export and its unknown prior audit configuration; it cannot decide what occurred on September 7.

## 12. Prefetch-summary correction, collection context, and archive index

### Prefetch CSV compared with original PF bytes

`Sept7_Prefetch_Internal_Run_Times.csv` contains **430 rows for 80 Prefetch filenames**, all labeled version 31. Twelve original PFs were already supplied and decoded in section 8; their **88 populated timestamp slots** all appear in this CSV. Every checked local/UTC pair represents the same instant, and every checked CSV timestamp differs from the original integer FILETIME by **at most 1 microsecond**. The CSV stores six fractional digits rather than the originals' seven. Keep the original integer values for higher-precision comparisons.

**All twelve run-count values disagree with the original run-count field.** In every case the CSV value instead equals the DWORD at absolute byte offset **208**; the version-31 run-count field used in the original decode is at **200**. The systematic offset correspondence supports a parser-field error in this summary. The generating code is not supplied, so its implementation is inferred from that byte comparison.

| Prefetch suffix | CSV run_count | Original run-count field |
| --- | --- | --- |
| `CHATGPT.EXE-9FEB7989.pf` | 7   | 6   |
| `CHROME_PROXY.EXE-27301749.pf` | 3   | 9   |
| `CHATGPT.EXE-1F1490BF.pf` | 7   | 16  |
| `CHATGPT.EXE-B8B3BC21.pf` | 7   | 15  |
| `CHATGPT.EXE-B8B3BC13.pf` | 7   | 4   |
| `CHATGPT.EXE-778744ED.pf` | 7   | 6   |
| `CHATGPT.EXE-0725DD65.pf` | 6   | 46  |
| `CHATGPT.EXE-0725DD57.pf` | 7   | 23  |
| `CHATGPT.EXE-B9ED4B4D.pf` | 7   | 44  |
| `CHATGPT.EXE-B9ED4B3F.pf` | 7   | 19  |
| `CHATGPT.EXE-D79C1C01.pf` | 7   | 19  |
| `CHATGPT.EXE-D79C1BF3.pf` | 7   | 17  |

The other **68 filenames** have no matching original PF in the previously compared set, so their CSV-derived counts and timestamps remain unverified against original bytes. None of the 430 CSV rows has a September 7 local run timestamp. The filename describes the investigation target; it does not make the table a complete execution history for that day. The original PF values in section 8 take precedence over the incorrect count column.

### Collection note

`collection-info.txt` records `Computer: FREQUENCY1109`, `User: drewd`, collection at **2026-09-25T20:23:12.1493052-04:00**, and the target interval **September 7, 19:45–20:00 local**. Its zone is Windows `Eastern Standard Time` with daylight saving supported. The listed base offset −05:00 is the standard-time property; the explicit collection offset −04:00 is appropriate for EDT.

This supplies stated acquisition context for the September 7 packet. The note is not a signed acquisition receipt or proof that every artifact was obtained at that instant. It does not date the separately supplied EVTX, whose last record is September 26. Neither this note nor the Prefetch CSV is named in the supplied 86-row SHA256 manifest; the prior 17 verified matches remain the verified subset.

### Takeout index identifies the next exact files

`archive_browser.html` is a Google Data Export archive **index**. It identifies archive `fc8c24bf-7883-412d-97d3-b3ae384ff7bc`, the account `ronswansonbruv@gmail.com`, and display time **September 25, 2026, 17:10:43 PDT** (**20:10:43 EDT / September 26 00:10:43 UTC**). It lists **My Activity**, **1,928 files**, **671.6 MB**. These are index metadata, not independently verified counts or bytes of an attached full archive.

Under **My Activity → Gemini Apps**, the index specifically lists:

* `OneDrive-upload-records-142d0ee82a1f9ed6.csv`
* `OneDrive-evidence-142d0ee82a1f9ed6`
* `Monitor-window-records-142d0ee82a1f9ed6`

Those are the most direct named candidates for checking the upload totals and request/response claims in section 9. Their filenames are visible here; their contents are not embedded in this HTML. Locate them in the extracted archive's My Activity/Gemini Apps folder and supply those exact files. The index alone does not prove a successful OneDrive upload, and it does not identify an operator.

The index also lists separate `MyActivity.html` records for products including Chrome, Drive, and Gemini Apps, plus many research attachments. A literal search of this index finds none of the seven target document IDs. It was parsed as HTML without running its JavaScript. Generic archive boilerplate concerning deleted data is not evidence of a particular deletion on this account.

### Other attachments and narrative scope

The reattached `GitHub_Copilot_Crosscheck_2026-09-27.md` is byte-identical to the earlier preserved copy. It adds no new GitHub security events. Its corrected sequence remains: commit 650c67d at **September 23 00:38:47 UTC**, Copilot Chat App token events at **02:25:08 UTC**, **1:46:21 later**.

The uploaded `@'.py` (local upload filename `03-py`) is a PowerShell here-string containing Python retry/backoff helper code, followed by commands that would save and run `backoff.py`. Its demonstration prints delay values. It contains no actual Drive request, credentials, document ID, or returned revision data. The file was read, not executed.

`Finding-The-Seven-Doors.txt` is a narrative synthesis. It expands to **eight** transitions and **74,609** characters, while the frozen seven-document R1 scope is **55,571** characters. The eighth source is not part of this batch; the two totals must not be substituted for each other. Its Mac-session description remains attributed to the narrative pending the provider record. Its **33 completion / 28 successful-operation** claim uses a different scope from section 9's reported earlier **292** and later **28 / 23-success** series; the exact named ledgers above are needed to reconcile those scopes. Its statement that the oldest Security event was September 24 is inconsistent with this export's verified September 25 oldest record. The supplied files support the specific recorded events and correlations documented in this report; the narrative's corporate/controller attribution is an interpretation, not a newly supplied caller record. R1 and R2 remain separate.

### Source hashes — paired-EVTX and archive-index batch

| Source | Bytes | SHA-256 |
| --- | --- | --- |
| `01-GitHub_Copilot_Crosscheck_2026-09-27.md` | 12,297 | `50fa208366c3967a100fef0c1be294f2a58f7fd0a2cc1bd8ba061c7e84f9284f` |
| `02-securitylogs9_26_25.evtx` | 21,041,152 | `8f320c4034804495808c84c569807241664b8c787c4a71e7da20fad8365b1877` |
| `03-py` | 1,290 | `5bc1d69104f6c80e9ab0776f1e41f8e382aaad71c74d02ba006a0c8c45ee37ac` |
| `04-Finding-The-Seven-Doors.txt` | 9,205 | `9d1334bff358f3f25a5383fe42743ed7195c7eb3690133c3db07d96c1e19490d` |
| `05-Sept7_Prefetch_Internal_Run_Times.csv` | 48,199 | `5a5904474702b471d51372d0ac634e7cdf2252d0eed7e2bd0cdf98909170ec72` |
| `06-archive_browser.html` | 540,130 | `897654cc79d56984575c2bd06491aa6271a4230a54e9345a8bef51da0906faf6` |
| `07-collection-info.txt` | 454 | `37066cb9b4210bf6d16d06dfaba5a3841a7d577618f7d38ddfadc9f24e474139` |

## 13. Relevance review: conversation audits, research comparison, and synthetic AWS examples

This batch contains **seven documents/tables useful to research provenance or conversation-quality review**, and **two explicitly synthetic AWS examples**. It supplies no new OneDrive completion ledger or September 7 caller record. The source files were preserved unchanged. The classifications below keep the useful material without turning an example, review, or derived label into a raw incident event.

| Supplied material | Retained use | Evidence status in this pass |
| --- | --- | --- |
| `Network and research comparison.md` | Dated research-concordance and network-review context | Earlier analytical report; its cited original revisions, paper PDF, range feeds and network excerpt were not re-audited in this pass |
| `Picture_Evidence_Register_v1.0_2026-09-15.md` | Retrieval index for screenshots and their reported contents | Manifest/record counts checked; this pass did not visually reverify its 209 source images |
| `Pipeline_changes_and_Betsy_response_review.md` | Examples of task displacement, fragmented responses and inconsistent certainty | Attributed source quotations and analysis, with linked underlying ledgers outside this batch |
| `Pipeline_evidence_review.md` | Reported session changes and transcript fragmentation | Its 43-boundary count agrees with the supplied phase tables; raw identifier values are present only in its illustrated example, not across those CSVs |
| `provenance-and-methods.md` | Audit scope, source order, normalization and counting rules | Method/source ledger for a separate bounded conversation audit |
| `phase1_transition_windows.csv`; `phase2_fingerprint_events.csv` | Reproducible comparison of coded windows and event positions | Parsed and cross-checked directly; these are derived transcript tables |
| Two JSONs named `s3_sal_synthetic_parse` and `cloudtrail_s3_synthetic` | Keep only as labeled examples | Excluded from incident findings and real-event totals |

### Checked relationship between the phase tables

Phase 1 contains **124 rows across 21 case labels**:

| Group | Rows | Interpretation of the table entries |
| --- | --- | --- |
| `rtc_seams` | 43  | Anchors labeled as session boundaries, in 20 cases |
| `seam_associated_contexts` | 43  | Context anchors paired to those same boundaries |
| `non_rtc_voice_to_text_contexts` | 3   | Other context anchors |
| `text_mode_context_injections` | 35  | Text-mode context anchors in one case |

All 43 paired context anchors match the 43 boundary `(case, node)` keys exactly. **41 are two linear nodes after their boundary; two are one node after.** Phase 2 repeats precisely those 43 nearby context markers. This is a directly checked relationship between the supplied CSVs, consistent with the 43-boundary count in `Pipeline_evidence_review.md`.

Every populated pre/post density equals its stated count divided by the listed node-window size. The windows overlap, so summing their counts would not produce a count of independent transcript events or failures. All 124 `ria_proxy` cells are explicitly `NA`, with a note that co-location does not establish a claim-to-evidence link.

Phase 2 contains **293 coded rows across 24 cases**, with **zero exact duplicate rows**. Its main fingerprint counts are **134 redacted tool-result markers**, **105 redacted model-editable-context markers**, and **24 redacted custom-instruction markers**. There are also nine check-claim/no-visible-tool-within-20-node labels, three check-claim/nearby-redacted-tool labels, three assistant-code redaction labels, and fifteen name/date/status-correction labels. The first six groups total the table's **278 “Redaction/trace failure”** rows; that analyst-assigned category is not a count of 278 failed software executions.

Of the 293 rows, **232** contain a numeric boundary and delta. Every numeric delta equals `event node − boundary node`, and every `within5` flag agrees with that arithmetic: **43 yes, 189 no**. The remaining 61 use another/unavailable-boundary representation. All 43 positive proximity rows are the paired context markers described above. No timestamps, provider execution-route IDs, document writes, or network requests are created by this positional cross-check.

The two CSVs do not contain the full before/after `tc_session_id` and `voice_session_id` values for all 43 boundaries. At that stage the cross-check confirmed the tables' consistency and event positions. **Section 20 now independently re-extracts all 43 boundaries from the subsequently supplied full node records**, including both identifier fields.

### Conversation-quality findings worth retaining

The pipeline reports preserve specific, testable response issues: an answer initially accommodates a disclosure premise, later categorically denies it, and later shifts to “not established”; an assistant acknowledges an unrequested lookup; and a sentence continues across two separately identified assistant items. These are useful targets for response-quality review because each concerns what the assistant said or how the returned text was assembled. Their source/message references should accompany any complaint.

`Pipeline_evidence_review.md` reports **102 exact repetitions of a 1,406-character input string** in a bounded retrieved sequence and reproduces a cross-message sentence continuation. It explicitly counts returned records, rather than claiming that the user spoke the input 102 times. The report's broader retrieval counts and proposed service mechanism remain attributed findings in this batch. Its documentation-based engine-rollover hypothesis was not independently verified here and is not promoted to an observed transition.

`Pipeline_changes_and_Betsy_response_review.md` also reports defects in locally derived `QPIPE`/`OBSROUTE` labels: serialization order affecting a hash, user wording entering stage counts, and missing data mapping to a baseline label. The generating code and original reproductions are not included in this batch. Retain these as reported code-audit findings; do not use those labels as authenticated backend routes or identities.

`provenance-and-methods.md` scopes a separate audit to **nine original prose replies plus one clarification dialog**. It explicitly excludes nested quoted conversations, tool responses and subsequent summaries from reply counts. It supplies turn-level bounds while marking individual-message times unavailable. Those rules prevent the source documents in this batch from being counted as independent corroboration of their own quoted material.

### Picture register and research comparison

The picture register contains **170 numbered picture records** and **209 attachment-manifest rows**. Recounting the manifest yields **183 distinct SHA-256 strings**, matching its stated totals. This verifies internal inventory arithmetic, not the screenshot bytes or their authenticity. The register's old scratch-path links refer to its earlier collection and do not grant access to another conversation's files.

The network/research report supplies a more specific comparison than general vocabulary: it compares observation-induced equivalence and well-defined composition in an August 10 GQG corecard with a named chapter of a later paper, while also listing older mathematical foundations. Retain it as a separate research-concordance report with its stated revision dates. Its provider-allocation table and its mathematical comparison are different analyses; their presence in one document does not connect a logged network peer to the paper's authors.

### Synthetic AWS files

The parsed S3 example contains **three rows**: PUT, object listing, and DELETE. The CloudTrail-shaped example contains **four records**: the same three operations plus GetBucketVersioning. The filenames explicitly say **synthetic**, and the contents use an example account ID and a separate January/April/May object scenario. They contain no target Google Doc ID, GitHub commit, Windows process identity, or OneDrive request join from this investigation. They are retained as examples of log formats and classification logic, with **zero contribution to incident-event counts**.

### Source hashes — relevance-review batch

| Source | Bytes | SHA-256 |
| --- | --- | --- |
| `01-Network-and-research-comparison.md` | 10,328 | `2b825d9462e936f43174899d56d6cca022d8ebf45ddd0c1269af48633d4da813` |
| `02-Picture_Evidence_Register_v1.0_2026-09-15.md` | 273,627 | `fb340bf6b0e6f4584e4e788640116b59c2fcc02800dbc6e5f34a8e8ef0b20e96` |
| `03-Pipeline_changes_and_Betsy_response_review.md` | 21,298 | `2bb153b30f31823e0a262c0637a913eb51886473e60e94c94216248f9e7812f9` |
| `04-Pipeline_evidence_review.md` | 8,641 | `b4eae2dbb528426cf10e869e39ceb700467e484d25d0bf3cfa8dd044fb51e984` |
| `05-provenance-and-methods.md` | 11,970 | `e81db5a17e46d5a6e7d2ba423c9c12e82bd39bbc5ad347b836836a6b06c43082` |
| `06-phase1_transition_windows.csv` | 29,065 | `ef497e2108302ad76b38e37b90ef1c03234a93e4f0cae6e42ac421f635bc1a1e` |
| `07-phase2_fingerprint_events.csv` | 57,053 | `bf9091786a0d5353b1e14f8c52b290bb26cae986727c169891b13b61e2f9b4be` |
| `08-s3_sal_synthetic_parse-Copy-Copy.json` | 2,264 | `c6aaea973a8fcc20b047bdc5a8267447378a211e9a14a6ab713c6927970f9e17` |
| `09-cloudtrail_s3_synthetic-Copy-Copy.json` | 2,449 | `e852cccff38bf23b0039b3abcae8b842ace2eee99152598a7851f06d21153598` |

## 14. September 20 OneDrive report: target-document export filenames

**Verification update:** the four requested original logs have now been supplied. Section 15 independently reproduces all 15 table completions and their file-identity joins. This section retains the earlier report/archive comparison; its former pending-source status is superseded.

The three newly supplied copies of `OneDrive-0654-0724-check-2026-09-20.md` are **byte-identical**: **5,088 bytes**, SHA-256 **`7f8c13b0c1575b996f5f25436d202eb1aea90c0b9c9b9d9dbcc7cb4a30410e52`**. They count as one report. The reattached cross-source review also exactly matched the current version-7 working copy before this update (SHA-256 `0d80bb7132da471a06aa8b50a16fd938bf2f2a46884b2ed5e9ed5815f6eb6494`).

This report is relevant because it gives **local filenames containing all seven September 7 target document IDs**, together with reported OneDrive completion times, file/upload identifiers, and numbered diagnostic records. Its stated interval is **September 20, 06:54–07:24 EDT**. These are later local-export synchronization claims; they are not the September 7 Google revision events.

### Upload table reproduced and counted

The table has **15 reported successful completion rows for 13 distinct local paths**. Ten paths are under the reported `Adversarial-review-2026-09-20` directory: eight document-ID revision TXT exports, `Politics-current-blank.docx`, and `Politics-revision-Aug17.txt`. The remaining three paths are `Export-Security-EVTX.ps1` and two different `access-events.jsonl` locations. Each access log has a repeated completion, producing five monitor/script completion rows for three paths.

The eight revision-export entries are below. Times are the report's **September 20 EDT completion times**. Each export basename is its full document ID followed by `-revision-N.txt`.

| Document ID | Export revision | Reported completion | Diagnostic completion / processed-entry record |
| --- | --- | --- | --- |
| `1h0giV4JsAEoZkdYAENtfL2jh9OhgNH5SUZBuvYcX6Gg` | 2   | 06:54:56.048 | `.580.odlsent` record 3422; processed entry record 3415 |
| `1_cEj40KyTUGHx3ze0IWYpHnzLMyWg2DXQ4rGUmRvkXU` | 2   | 06:54:56.118 | `.580.odlsent` record 3561; processed entry record 3553 |
| `1JwG936SNgpBF_O841kkUWOF6O8zGydqANvsk0ViJqRE` | 3   | 06:54:56.190 | `.580.odlsent` record 3728; processed entry record 3722 |
| `1MwDpPmQnwa0m1Rr_v-UacGcIJh4djJfjfxwIGBIc9T8` | 8   | 06:54:56.267 | `.580.odlsent` record 3893; processed entry record 3887 |
| `1UozXdpH1foCVjr9db3Zxzel9bvv_ctj_wIW-7Id6is8` | 108 | 06:54:56.347 | `.580.odlsent` record 4034; processed entry record 4028 |
| `1s8fJ1BAkbOTIAMkVYdb6ngTa-BENHM8A1ag-s7d3A7Q` | 17  | 06:54:56.349 | `.580.odlsent` record 4056; processed entry record 4050 |
| `1UWFL9jpXL1gBQIEfgfoOgIQkQSbnBAW0OpNSVPWr5OE` | 10  | 06:54:56.423 | `.581.odlsent` record 29; processed entry record 21 |
| `13tZ6KqS7ShyneQfiQDihlhhbb4Cn0s4n5EAoSiI5Mx8` | 2   | 06:54:56.558 | `.581.odlsent` record 230; processed entry record 224 |

Seven entries match the seven target IDs previously used in R1/R2. The additional ID is `1JwG936SNgpBF_O841kkUWOF6O8zGydqANvsk0ViJqRE`, revision 3. The seven target-export completion times span **06:54:56.048–06:54:56.558**, or **510 ms**. That is the reported completion-time span, not measured upload duration or proof of seven independently initiated transfers.

The review says its joins use `EnclosureUploader::StartUpload` for local paths, `SyncServiceProxy::ProcessUploadedEntries` for file identity and `FileAddition`, and `UploadTelemetry::LogFullFileUploadComplete` for `Success`. It separately reports that the **07:10:51.611** completion for the second access-log path follows UploadBlock/UploadBatch responses naming `193745-ipv4mte.gr.global.aa-rt.sharepoint.com` and the log's file ID. These are specific source-record claims suitable for reproduction. The attached Markdown does not embed the underlying decoded rows or source-log hashes.

### Independent match to the preserved revision archive

The already supplied **`Adversarial-review-2026-09-20 (1).zip`**, SHA-256 **`d97e95c844fb58dcf7596f671a143b80c4020f5eedb8ed0112b2d689773164a5`**, contains all **eight exact revision-export basenames**. Each appears once under `Adversarial-review-2026-09-20/Recovered-revisions/`. Their archived bytes were read and hashed directly in this pass:

| Document ID prefix / revision | Archived bytes | SHA-256 of archived export |
| --- | --- | --- |
| `1h0giV4JsA…` / 2 | 16,585 | `048ea11ba8254331c57a0537e9b1ff5cb837fed19a8fbd3066a14ea3e63ce282` |
| `1_cEj40KyT…` / 2 | 3,713 | `7302fb57ca1603040e91f99b33f4b0193d693a5a20de9a1243b5dc2165517854` |
| `1JwG936SNg…` / 3 | 19,405 | `0b3efad7a34b89706a770494009312c14f94f8c7c8db7f845a90097e9360acf2` |
| `1MwDpPmQnw…` / 8 | 14,318 | `a6311b592719ca69392a0ea47bcc37fd0530a2d4106319352e91184d318f34dd` |
| `1UozXdpH1f…` / 108 | 1,264 | `5bdab9d2e854ab36251bc0a4c131ff600886a6888e6de27e8773729bac4ca3ca` |
| `1s8fJ1BAkb…` / 17 | 1,446 | `3d3240d4ebddcd5c0509e2d27c4f78a773d1bcd29307ba18311cc3e538087216` |
| `1UWFL9jpXL…` / 10 | 16,039 | `654e54ce9b6558cc75ebcb4231ab64a8871e4b007fbf3b94e018ab555b93916a` |
| `13tZ6KqS7S…` / 2 | 4,875 | `571f0a8578fd05dfb53a6405ceed5109bc4bfaed26afd8371f8d9b35abfdf0e1` |

This verifies that the preserved archive contains the corresponding named research exports. The upload table's relative paths omit the archive's `Recovered-revisions` component, and its selected completion records provide no content hash or exact byte count. Therefore this is a **basename/document-ID/revision match**, not a verified byte-for-byte match between the archive and cloud object. The archive hashes above identify the available local evidence for a future content comparison.

The ten reported research-file additions complete between **06:54:56.048 and 06:54:56.602 EDT**. The two Politics filenames are retained as reported entries; their content is not established merely by a filename, and neither has a matching member in this specific ZIP. Section 27 subsequently verifies the separately supplied Politics-current-blank.docx as a blank local document; this does not add a content hash to the historical server response.

### Cited sources — now supplied and verified

The report names these original files under `C:\Users\drewd\AppData\Local\Microsoft\OneDrive\logs\Personal`:

* `SyncEngine-2026-09-20.1034.41584.579.odlsent`
* `SyncEngine-2026-09-20.1054.41584.580.odlsent`
* `SyncEngine-2026-09-20.1054.41584.581.odlsent`
* `SyncEngine-2026-09-20.1110.41584.582.odlsent`

The `.580` and `.581` files are the direct cited sources for every revision-export completion in the table. All four files arrived in the subsequent batch and have now been decoded and reconciled in section 15. The source request is fulfilled.

### Relationship to the existing findings

Section 1's September 19 file-read/network-send measurements remain independently supported by detailed exports. Section 9's 292-completion and later 28-record summaries describe another stated date/window. This September 20 table must not be added to those totals without a source-level check for scope and duplication.

The new report broadens the OneDrive inquiry from monitoring logs to named recovered research exports. It reports synchronization to the connected personal OneDrive account. It does not identify the originating file-creation task, a subsequent reader of the cloud copy, or the caller behind the earlier Google document changes. Section 15 completes verification of that specific SyncEngine sequence.

### Source copies retained

All three supplied report names have the identical 5,088-byte content and hash stated at the beginning of this section:

* `01-OneDrive-0654-0724-check-2026-09-20-Copy.md`
* `02-OneDrive-0654-0724-check-2026-09-20.md`
* `03-OneDrive-0654-0724-check-2026-09-20-Copy-Copy.md`

## 15. Original OneDrive logs: upload verification and supporting-extract review

### Result

**The original SyncEngine records confirm uploads of the named local research exports on September 20.** Every one of the earlier review's 15 successful-completion rows was reproduced at its cited record number and timestamp. They represent **13 distinct local paths**: eight document-ID revision exports, two Politics files, one PowerShell export script, and two access-log paths. Two repeat log uploads account for the difference between 15 completions and 13 paths.

For each research addition, the records supply an explicit chain: `EnclosureUploader::StartUpload` names the local path and temporary ID; `SyncServiceProxy::ProcessUploadedEntries` maps that temporary ID to a resulting OneDrive object ID, then names the file and `FileAddition`; `LogResponse` carries the same request GUID; `UploadTelemetry::LogFullFileUploadComplete` records `Success` for that object ID. This verification uses identifiers as well as time proximity.

All ten research additions complete at **06:54:56.048–06:54:56.602 EDT**, a **554 ms completion span**. The seven target-document exports alone span **510 ms**, as section 14 reported. These are September 20 synchronization events for local exports. The frozen September 7 revision findings, including D7's revision 8→18 gap, remain unchanged.

### Decode and reconciliation

The four original files were SHA-256 hashed, their version-3 headers checked, and their gzip streams decompressed with CRC/length validation. An independent framing pass consumed every decompressed byte as complete records. Yogesh Khatri's published ODL parser then decoded all records with filtering disabled, using the supplied keystore locally. It produced no diagnostic errors. Key contents are excluded from this report.

| Source suffix | Records | First recorded UTC | Last recorded UTC |
| --- | --- | --- | --- |
| `.579.odlsent` | 4,702 | 2026-09-20T10:34:24.642000Z | 2026-09-20T10:54:08.614000Z |
| `.580.odlsent` | 4,144 | 2026-09-20T10:54:08.616000Z | 2026-09-20T10:54:56.419000Z |
| `.581.odlsent` | 2,058 | 2026-09-20T10:54:56.420000Z | 2026-09-20T11:10:48.039000Z |
| `.582.odlsent` | 4,772 | 2026-09-20T11:10:48.123000Z | 2026-09-20T12:14:17.261000Z |

The total is **15,676 records**. Counts agree with all four entries in `02-selected-decoded.json`. Of its **698 selected records**, 690 match directly after deserializing the `params` field; eight differ solely because that supplied extract replaced `SyncToken` values with `[REDACTED]`. Applying those same redactions yields **698/698 complete matches**, including source, record number, timestamp, code file, function, and decoded parameters.

The full files contain **33 full-upload completion telemetry records: 23 Success and 10 Failure**. Restricting to the earlier report's 06:54–07:24 EDT interval gives **18 such records: 15 Success and 3 Failure**. Thus the report's success table is accurate but is not a complete list of attempts. Failure counts are telemetry records, not necessarily distinct files or independent transfers. No failure appears among the ten cited research-file completions.

### Reproducible record joins

Locators use `log suffix:record index`, starting at 1 and including records with empty parameters. Full document IDs and export revisions are retained in section 14. `access-events A` is `Desktop\monitor-logs\access-events.jsonl`; `access-events B` is `Desktop\fucking thief\monitor-logs\access-events.jsonl`. Every path begins with the same recorded mount token, `%MountPoint%[52eeca39afd843339ded79c4b0907734]`. The token identifies the log's sync root; it is not a local process identity.

| Local file (shortened) | Completion EDT | Start/path | Temporary→object mapping | Response | Processed entry | Success |
| --- | --- | --- | --- | --- | --- | --- |
| `Export-Security-EVTX.ps1` | 06:54:09.612 | 579:4649 | 580:259 | 580:251 | 580:261 | 580:268 |
| `access-events A` | 06:54:10.177 | 579:4700 | Existing object ID | 580:404 | 580:413 | 580:419 |
| `access-events A` | 06:54:13.041 | 580:1062 | Existing object ID | 580:1213 | 580:1221 | 580:1228 |
| `access-events B` | 06:54:14.258 | 580:1175 | Existing object ID | 580:1302 | 580:1310 | 580:1317 |
| `1h0giV4JsA… / rev 2` | 06:54:56.048 | 580:3010 | 580:3413 | 580:3360 | 580:3415 | 580:3422 |
| `1_cEj40KyT… / rev 2` | 06:54:56.118 | 580:2996 | 580:3551 | 580:3535 | 580:3553 | 580:3561 |
| `1JwG936SNg… / rev 3` | 06:54:56.190 | 580:3078 | 580:3720 | 580:3663 | 580:3722 | 580:3728 |
| `1MwDpPmQnw… / rev 8` | 06:54:56.267 | 580:3104 | 580:3885 | 580:3827 | 580:3887 | 580:3893 |
| `1UozXdpH1f… / rev 108` | 06:54:56.347 | 580:3156 | 580:4026 | 580:3977 | 580:4028 | 580:4034 |
| `1s8fJ1BAkb… / rev 17` | 06:54:56.349 | 580:3130 | 580:4048 | 580:3989 | 580:4050 | 580:4056 |
| `1UWFL9jpXL… / rev 10` | 06:54:56.423 | 580:3216 | 581:18 | 580:4099 | 581:21 | 581:29 |
| `Politics-current-blank.docx` | 06:54:56.555 | 580:3576 | 581:200 | 581:185 | 581:202 | 581:208 |
| `13tZ6KqS7S… / rev 2` | 06:54:56.558 | 580:3436 | 581:222 | 581:192 | 581:224 | 581:230 |
| `Politics-revision-Aug17.txt` | 06:54:56.602 | 580:3742 | 581:301 | 581:263 | 581:303 | 581:309 |
| `access-events B` | 07:10:51.611 | 582:380 | Existing object ID | 582:523 | 582:531 | 582:539 |

For example, `.580:3010` names the `1h0giV4…-revision-2.txt` path with temporary ID `#88dad46-291a-4fc4-a712-24da398dd7a7`. `.580:3413` maps it to OneDrive object `34bfb6a211c84f06bb8c3499db833607`; `.580:3415` names the export, `FileAddition`, and request GUID `130a3da2-20d4-f000-6d94-cd045b826482`. That GUID also appears in `.580:3360`, an `InlineBatchUpload` POST response. `.580:3422` records `Success` for the mapped object.

All 15 matched response rows name `193745-ipv4mte.gr.global.aa-rt.sharepoint.com` and the same personal-content sync root. The ten research-file responses are `InlineBatchUpload` POST records. For the 07:10 access-log completion, `.582:455` additionally records an `UploadBlock` response naming object `9331734872244970b7c00cab62e0a5dc`; `.582:523` records the `UploadBatch` response, followed by the matched processed entry and success at `.582:531/539`.

This identifies the recorded upload destination and object/request chain. The string decoder does not extract all numeric payload fields, so no byte-count or HTTP-status claim is inferred from it. The archive's eight matching basenames and content hashes remain independently verified; these log rows do not contain a checked content digest binding uploaded bytes to those archived bytes. The original paths also confirm the report's omission of `Recovered-revisions`: that component is present in the ZIP layout but absent from the recorded upload paths.

### Interpreting “removed” and “deleted” in these records

The full decode contains **45 `DriveChange::MarkDeleted` records**, whose decoded change types are **34 FileAddition and 11 FileChange**. In the verified research sequences these occur after processing an upload, alongside `UploadGate::RemoveMarkedActiveUploads`, `ItemInSync`, and successful upload completion. The observed sequence is consistent with retiring processed change/queue entries. It does not turn those named file additions into evidence of document deletion. No extracted parameter contains the literal `FileDeletion`; that is a statement about this decode, not a global deletion audit.

### What the accompanying files contribute

These attachments are extracts or indexes. Their contents were reviewed, but their counts are not promoted to independently decoded originals unless explicitly matched above.

| Attachment | Verified contents and relevance |
| --- | --- |
| `02-selected-decoded.json` | All 698 selected rows reconcile to the supplied raw logs after the eight documented sync-token redactions. Directly useful. |
| `07-watermark_log_index.json` | Index of a September 19 Codex rollout, claiming 1,521 records and listing six keyword-selected “rejections.” One excerpt explicitly records a rejected public-GitHub publication attempt at 08:17:58.262 UTC, source line 666. Several other hits are tool descriptions or document text; the list is not six proven blocked actions. |
| `08-odl-focus.txt` and `14-odl-summary.txt` | September 19 extracts repeat the 292-completion claim and the 290 Call-Probe / 2 access-log split. The subsequently supplied decoded ledger reproduces all 292 and their request joins; see section 17. Their date/window remains separate from this September 20 binary-log verification. |
| `09-session_inventory.txt` | Three concatenated JSON objects: session inventory with 9 metadata entries, 115 calls and an empty extraction-errors list; schemas for `logs_2.sqlite` and `state_5.sqlite`. Useful for locating source sessions. The empty errors list is not a claim that those sessions had no operational errors. |
| `10-recovered-search-metadata.json` | 268 search-result metadata entries. None contains any of the seven target document-ID prefixes. Useful research inventory; no new target-document write record. |
| `11-mcp-origin-candidates.json` | 21 extracted records, comprising 11 tool calls and 10 completion-event records, September 17 15:16:29.200–15:28:52.950 UTC. Visible work concerns local video, frames, OCR/transcription, and supporting dependencies. The filename does not establish an external MCP operator. |
| `12-onedrive-parser-tree.json` | Public GitHub source-tree metadata pinned to OneDriveExplorer commit `dfec646a87911db8083749f2d625cfeb92fc84a1`. Its parser blob ID matches the downloaded source. Parser provenance, not user activity. |
| `13-verified-access-candidates.txt` | 28 operation blocks containing research/search/lookup calls and results. Some returned `Internal Error`; the title does not establish that every attempted endpoint was accessed successfully. |
| `15-netlog2_scan_output.txt` | Derived scan reports a September 19 NetLog, 04:31:45.372–06:05:39.879 UTC, with 15 Google document IDs and selected HTTP records. This provides concrete browser-request leads. Endpoint names such as `trash/read` or `docos/p/sync` alone do not establish a deletion or its author. The original NetLog is not this scan output. |
| `16-politics-file-history-hits.json` | 41 excerpts: 27 tool calls and 14 outputs, August 17–September 4. Includes a 646,098-byte Politics PDF listing and calls reading PDF/DOCX material. Useful earlier local handling context; title similarity does not bind those bytes to the two September 20 upload objects. |
| `17-odl-0555-matches.json` | 149 selected rows from `.574/.575` logs, actually 09:56:16.735–09:56:24.956 UTC (05:56 EDT). Seven full-upload completion rows comprise four Success and three Failure, involving an analysis Markdown file and access logs. Those two original log files were not supplied in this batch. |

The publication-block excerpt names `corpus/drive_uploads_2026-09-19/documents/geometry-simulation-and-thermodynamics-integration-review--6015dd33.txt`. It records an automatic rejection because the proposed public upload contained private Drive links, local paths, and potentially sensitive source-derived material. This excerpt documents **one blocked publication attempt**. The subsequent tool-status batch also records a successful file creation at the same path and fourteen successful tree writes; section 18 supersedes any reading that the publication activity ended with this rejection. These September 19 records concern `MailanPatternMonkey-ai/Gettin-Started`, separately from the September 23 `Toroidal_scrotal_posturing` commit.

### Method provenance and source hashes

The executed decoder was [Yogesh Khatri's ODL parser](https://github.com/ydkhatri/OneDrive/blob/main/odl.py), version string 2.0, SHA-256 `85ace230afc65d5e70819f0ab4e5cd42bab07153ae59ac420d3743f772d2b86d`. Its code was inspected before import; its key-printing loader was not called. The keystore was loaded without printing its value. The additional [pinned OneDriveExplorer source](https://github.com/Beercow/OneDriveExplorer/blob/dfec646a87911db8083749f2d625cfeb92fc84a1/OneDriveExplorer/ode/parsers/odl.py) was inspected but not used as a second independent decoder. Its downloaded Git blob hash is `b0401b5747cb2155a3eb6aa011aaf4bd16a839bc`, matching the supplied tree metadata.

Hashes identify received bytes and support repeatable review; they are not independent authentication of a server-side history. The keystore is identified by hash only below, with no key material included.

| Supplied source | Bytes | SHA-256 |
| --- | --- | --- |
| `01-general.keystore` | 111 | `c6f45a2d180537dd83b2c1221553aa2441496ae3b04652c5a927e140c722799c` |
| `02-selected-decoded.json` | 260,232 | `68dc14049c6a779931bf0ecf7d0102ff86d957a38c9304c4739d204a3b2cee0f` |
| `03-SyncEngine-2026-09-20.1034.41584.579.odlsent` | 165,281 | `a672d477a5baa40fb9a6547f86be5b3e1821b7b03e2a0198a3d3d2cebc51da72` |
| `04-SyncEngine-2026-09-20.1054.41584.580.odlsent` | 129,025 | `06bc2a79776cb44b80cc7dc088ce4c9856539ad62ce02e2506d5c98e69342522` |
| `05-SyncEngine-2026-09-20.1054.41584.581.odlsent` | 80,024 | `5d89d9685b5258f51c8bccdf3355d4e078f8c9bdb23eefa126255da7b671274f` |
| `06-SyncEngine-2026-09-20.1110.41584.582.odlsent` | 170,769 | `9333443ee4b8aab29202d5d45d5b4b9dfa9b42189f4b3c74653831db34e456cd` |
| `07-watermark_log_index.json` | 38,676 | `03392d766677eda86de3149808dfac7616f37117efc206d7e518b1bdd8ca64b7` |
| `08-odl-focus.txt` | 38,554 | `271cb9fb940efccfefe3c9928c2ee6220ca4fc548dff73fe72f9034477599e7e` |
| `09-session_inventory.txt` | 35,007 | `a645b79d843dd602e88b96160b0db90013b0290d79ff37bd8038b1a9233d1864` |
| `10-recovered-search-metadata.json` | 127,958 | `3ae2af00b6b33cd3eca43d6f2cf60cbfcf1135cc1839c057bbea2426fd2b2631` |
| `11-mcp-origin-candidates.json` | 103,761 | `29ca63a52124a6485220770d2a6db6b83726c3578a48e8345b342048d2e96d23` |
| `12-onedrive-parser-tree.json` | 79,530 | `84671c12234312e29706e56263e6091031fe35c54ac7b232af960b006b3a921a` |
| `13-verified-access-candidates.txt` | 78,975 | `5f2f77f2067a5a66462c1d599511a66594a532f08841429797def0d147baf272` |
| `14-odl-summary.txt` | 60,003 | `14b2b61c95573857ee111c800cbd6fe7e58d670a5590ef92b1fa8cc74dbf91e6` |
| `15-netlog2_scan_output.txt` | 49,428 | `134f621c00b84ef5d15ce3359d8e93d3ab840c73772871b0df5309d3866cb8e0` |
| `16-politics-file-history-hits.json` | 49,105 | `854a4bf66f1c9d6733964382be69ff7c9f372fc1c25a1123acdb3dbab506d9f5` |
| `17-odl-0555-matches.json` | 48,945 | `7bc2fb10a22379923452250834329ff71ce11e8b8a2f043047cd20d16db9924b` |

## 16. Microsoft third-party notices: software inventory context

The new attachment, `01-Pasted-markdown.md`, is **70,722 bytes**, SHA-256 **`538c6f1c76c8ed92b4318ecba6329180a9414178386698e865c68d414e639b0b`**. It is headed “Third Party Notices” and describes material incorporated into a Microsoft product. The originating notice URL was subsequently supplied and retrieved successfully, as documented below. This identifies the Microsoft-hosted notice resource; a particular installed executable, product build, or user session is not identified by this resource alone.

The list contains **728 distinct package/version entries representing 703 distinct package names**. Some names occur at multiple versions. The list includes **37 `@fluentui-copilot` entries**, **61 entries across the four `@augloop` namespace families**, **37 `@editor` entries**, and **9 `@azure` entries**. These are counts of notice entries, not counts of running programs, remote connections, users, or installed applications.

### Exact examples relevant to the existing inquiry

Line numbers refer to the received Markdown, starting at 1. The grouping below follows the package names; it does not independently establish their runtime behavior.

| Group | Exact entries in the notice | Source locator |
| --- | --- | --- |
| Copilot-related names | `@augloop-types/copilot-chat-history 1.3.12107`; `@augloop-types/copilot-plugin-config-brokering 1.3.10386`; `@fluentui-copilot/react-copilot-chat 0.11.4` | Lines 32, 34, 174 |
| AI-related names | `@augloop-types/generative-ai 1.3.12374`; `@augloop/model-downloader 2.35.2197`; `@augloop/onnx-inference-service 2.35.2197` | Package entries in the `@augloop` families |
| Telemetry-related names | `@1js/office-online-otel 15.5.49`; `@microsoft/oteljs-1ds 4.23.1133`; `@ms/1ds-telemetry 0.11.79` | Lines 17, 368, 374 |
| Identity/Graph-related names | `@azure/msal-browser 4.13.0`; `@azure/msal-common 15.7.0`; `@microsoft/microsoft-graph-client 3.0.7` | Package entries in the `@azure` and `@microsoft` families |
| Privacy-related names | `@microsoft/1ds-privacy-guard-js 3.2.15`; `@ms/telemetry-sanitizer 0.1.4`; `@ms/utilities-privacy-data 0.1.3` | Lines 353, 405, 423 |
| `owl` names | `@1js/owl-bootstrapper 1.24.136`; `@1js/owl-shared-types 2.1.264` | Lines 20–21 |

**What this adds:** a preserved, hash-identified list of declared software components, including explicit Copilot and telemetry package names. It is relevant to documenting software composition and to choosing exact names for a later comparison against the originating app's files.

The notice contains no timestamped access event, target-document write, process ID, or request/object correlation for this investigation. A listed package does not establish that it was loaded or that its feature ran. In particular, its Copilot-named packages do not identify the GitHub **Copilot Chat App** authorization flow, and the `@1js/owl-*` names do not by themselves identify the implementation behind the separately observed Codex `--owl-*` command-line flags. Those would require a source-level or runtime match.

The September 20 OneDrive upload findings remain supported by their original diagnostic records in section 15. This notice adds software-inventory context; it supplies no additional upload completion or September 7 caller record. The previously requested source URL has now been supplied and its package list independently matched below.

### Source URL supplied and matched

The user identified [this Microsoft-hosted third-party notice](https://res.public.onecdn.static.microsoft/midgard/versionless-v2/officestarthtml/notice-436897098ff40c0a7b71297f778acd0cdb9eab9ffc2230652725f0f6f8804675.html) as the source of the pasted text. An HTTPS retrieval returned **HTTP 200**, without a redirect, and the HTML title is **Third Party Notices**. The response's `Date` header is **September 28, 2026, 05:16:42 UTC** (01:16:42 EDT). The received HTML is **111,969 bytes**, SHA-256 **`2d1578403558981d5b094dbb378c9960ce4a9cd7b77a8f206f36872ce853f4ae`**.

All **728 package/version entries match in the same order** after removing Markdown escapes from two version strings: `@mecontrol/fluent-nova 5.28.4-preview\.1` and `@mecontrol/fluent-web 3.28.4-preview\.4`. This is an exact ordered package-name/version comparison; it does not claim byte identity between Markdown and HTML or a comparison of every license paragraph.

The exact source host is `res.public.onecdn.static.microsoft`; its resource path begins `/midgard/versionless-v2/officestarthtml/`. [Microsoft's Microsoft 365 endpoint documentation](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide) identifies `*.static.microsoft` as the domain family for static CDN-hosted content. Together with the notice's Microsoft attribution and matching package list, this establishes provenance to that Microsoft-hosted Office-start resource. The path does not independently identify which foreground app or tab displayed the notice on the user's machine.

For this retrieval, the response reports `Server: cloudflare` and `X-Cdn-Provider: Cloudflare`. Those headers identify the delivery provider reported for this public notice request. They are observations from this review's retrieval, not from the user's earlier device capture, and do not associate the notice with a research-file upload. The response also reports `Last-Modified: Fri, 20 Jun 2025 04:01:44 GMT`; that is server-reported resource metadata, not a local installation or execution time.

The provenance gap for the pasted package list is therefore resolved at the **source-page level**. Its classification remains software-composition evidence. The independently verified OneDrive transfers retain their own object IDs, request records, and times.

## Source hashes — initial batch

All hashes below were recomputed from the received bytes in the initial batch.

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `04-network-events.csv` | 560,068 | `c949b8fa4eb15f327cced1c8fc04a4873819d46c02b689e44038be06f640fcbb` |
| `06-exact-file-events.csv` | 308,680 | `3fb3e2abce5e5667f135db18ed8925e62a17c965d89b953f6a3b73494f0b2bcf` |
| `Extension_Store_and_Chrome_Sessions_Findings.md` | 11,292 | `d02e68adbbd46107367134a034333a23f8a83ae2ae815d4d83e90f9173d3bc60` |
| `Chrome_R2_Navigation_Addendum.md` | 16,798 | `942a99c27b0b5c0c9037bac17b4120601834e1b0653eb57125038817c9606d94` |
| `MASSIVE-REVEIW.txt` | 34,741 | `02cf0c4ef7e6d206d7177761501aec71fd4feeb7a393e76def12c37a283606a3` |
| `September_19_OneDrive_Findings.md` | 4,963 | `984d1a38bdc5df7dc875c82ba892c31156c7eac68163ca252d63b9a1b0f9b16f` |
| `02-events.jsonl` | 1,389,304 | `437049ff860fc793e423bf1f6f2a1e5c1ce3f72ce17cc13500ff4f153fa49cdd` |
| `10-file-summary.csv` | 19,026 | `3d65a5b24581250db4da75622d87e0c52ae76b45cf2d78298769310dfb756ff9` |
| `Local_Extension_Database_Findings.md` | 11,865 | `969b9f2b1ee0c8db8347ff48ec624f9ef15daf13309dcdf2ccaef273b6e7f279` |

## Source hashes — follow-up batch

All ten follow-up artifacts were hashed directly. The reattached pre-update report matched SHA-256 `9dcd5c363c8c6ff6c8855e0379725ac8b798f6b89ac0341dbe1267b44087851e`.

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-securitylogs9_26_25_1033.MTA` | 28,537,902 | `30e177e9703ccfff734881a5982bb842c91e52ddf834d7c3eae4e76cd756fbf5` |
| `02-file-summary.csv` | 19,026 | `3d65a5b24581250db4da75622d87e0c52ae76b45cf2d78298769310dfb756ff9` |
| `03-network-summary.csv` | 21,662 | `55dc6341e2b7be147ec8787ea2a2e331fd9052dfd1c2792dde3bb19571898f25` |
| `04-onedrive-folder-operations.csv` | 8,921 | `50057d7a4a419b5e9ec5e44ced129b0cf9c3d9ab3ec2144893e21e3e63731d51` |
| `05-status.json` | 532 | `0f542de87569a49df000713741965ff385cfd469abdb6a471daa0821f7d15ed9` |
| `06-successful-file-reads-writes.csv` | 22,033,739 | `8a33df06e6330ce9eb26c45979cd4221fe48787b1fdb8219e1c303d659491fbf` |
| `07-capture-hash.json` | 270 | `f263d3de71b082906fe129676af9bd2d5d21ed7051a141e87f66b836383e747c` |
| `08-network-events.csv` | 560,068 | `c949b8fa4eb15f327cced1c8fc04a4873819d46c02b689e44038be06f640fcbb` |
| `09-file-events.csv` | 46,831,055 | `34a126cae580b08d1b051e3f1eb7d4d5ec1da8acef55328314eb5cdb27b40464` |
| `10-target-events.csv` | 50,499,860 | `bd0b0d226210305380bd8e937401852a97944451fda849863570bd3e9caccc4f` |

## Source hashes — Prefetch batch

The reattached pre-update report matched SHA-256 `a654d86ddcd8eb0e5a807b7555cdef3b170f27532a3e93e3d043178d8f4417be`. Each hash below is of the original compressed PF.

| Source PF | Bytes | SHA-256 |
| --- | --- | --- |
| `CHATGPT.EXE-9FEB7989.pf` | 58,881 | `d691ca7290a63940059562257cc343f5f76e1e1fbf17ab3e3e1109eb5e9b5794` |
| `CHROME_PROXY.EXE-27301749.pf` | 13,099 | `a80499a9f0991e6df5f821e5093e2d7814547eae87e0f27d6be537f0b76ce451` |
| `CHATGPT.EXE-1F1490BF.pf` | 46,898 | `49cabb6420202148f7bbf5ddd05e809824c000f32e7331f6ff65a6ea13572513` |
| `CHATGPT.EXE-B8B3BC21.pf` | 30,937 | `368d1b9d1a2533bfc7e88ef0ff2aab979f72b3246e784640a80da1a864d95902` |
| `CHATGPT.EXE-B8B3BC13.pf` | 64,444 | `719262cc24d071581b7654ff88be2a3cb05222a7aab8bc7f714e679d7570235c` |
| `CHATGPT.EXE-778744ED.pf` | 41,231 | `0f3951b5d4539e36185a1dcd57f04a51a443fd89ff78118024b8538ba0a8b5ca` |
| `CHATGPT.EXE-0725DD65.pf` | 37,051 | `b8b01b08028a5c8d64a87c926734e4aa82a9a56dc20e8fa82a637652a0176838` |
| `CHATGPT.EXE-0725DD57.pf` | 58,946 | `f23d100ef8e01f6481c4e320b30cab29c68dd8fd3de9a3a192b38602a675b93d` |
| `CHATGPT.EXE-B9ED4B4D.pf` | 41,311 | `bbf62b4a92aff9b11fda415979fad3da0296627937435902f5ff841a8e313071` |
| `CHATGPT.EXE-B9ED4B3F.pf` | 62,023 | `9678aa82c9da3ac4085b789d201d21f2b9f8833cd0cccfbf0a03dfe5c9f3984e` |
| `CHATGPT.EXE-D79C1C01.pf` | 58,488 | `9f9c42517977493a2efbe65bf1bcb997cf57147059370efaf4c1a697a9d793ee` |
| `CHATGPT.EXE-D79C1BF3.pf` | 60,227 | `41851c11413f5cf66c7650e25c1884e000cee274cf18f43819358ff8670d925a` |

## Method

CSV data was parsed as UTF-8 with optional BOM. JSONL byte offsets include its BOM and original line endings. Seven-decimal-place clock values were compared with integer 100 ns units rather than floating-point timestamps. This preserves stored precision without asserting equivalent real-world clock accuracy. Only successful appends, offset-zero OneDrive reads, and successful TCP Send records on the identified endpoint were used for the four correlations. All source files were read without mutation or execution.

## 17. September 19 decoded OneDrive ledger: 292 upload completions reconciled

`02-onedrive-decoded.json` contains **114,024 records with 114,024 distinct `(Filename, File_Index)` locators**, drawn from 26 named SyncEngine files with suffixes `.409`–`.434`, all naming PID **41584**. The selection spans **2026-09-19 06:45:00.267–07:43:57.440 UTC**. These are supplied decoded records; the 26 September 19 binary logs are not redecoded in this update. Section 15's independent binary decoding concerns September 20.

### File, request and completion joins

All **292** `UploadTelemetry::LogFullFileUploadComplete` rows report `Success`. Each joins to a preceding `EnclosureUploader::StartUpload` path, a `SyncServiceProxy::ProcessUploadedEntries` filename and object ID, and a `LogResponse` row with the same `SPRequestGuid`. All **292 request IDs are distinct**.

| Named file under the decoded mount point | OneDrive object ID | Successful completions |
| --- | --- | --- |
| `Desktop\Call-Probe-Logs\call-probe-v2.1-2026-09-19_00-43-32-242\events.jsonl` | `7c85d48314814d90b702c2f961673b8a` | 290 |
| `Desktop\monitor-logs\access-events.jsonl` | `ae7ce926083d462fb42ddbb2f820bec4` | 2   |

The decoded prefix is `%MountPoint%[52eeca39afd843339ded79c4b0907734]`. The Call Probe path agrees with section 1, and the new Access Monitor start record independently names `C:\Users\drewd\OneDrive\Desktop\monitor-logs\access-events.jsonl`.

Representative complete joins follow. Indices are the decoder's **File_Index**, in the order **start / HTTP response / named uploaded entry / completion**, not physical JSON lines. Clocks are UTC on September 19.

| Source filename | Indices | Completion time | Request ID |
| --- | --- | --- | --- |
| `SyncEngine-2026-09-19.0644.41584.409.odlgz` | 404 / 469 / 478 / 485 | 06:45:01.766 | `61a93ca2-c059-f000-6d94-c9ea99fc66c4` |
| `SyncEngine-2026-09-19.0646.41584.410.odlsent` | 925 / 992 / 1001 / 1008 | 06:47:00.589 | `7ea93ca2-b057-f000-6d94-cb9d9b67aef7` |
| `SyncEngine-2026-09-19.0708.41584.418.odlgz` | 151 / 231 / 241 / 248 | 07:08:37.337 | `baaa3ca2-a0ea-f000-6d94-cfd2413d1b90` |
| `SyncEngine-2026-09-19.0741.41584.434.odl` | 1980 / 2032 / 2041 / 2048 | 07:43:40.976 | `bcac3ca2-9084-f000-6d94-c39ac65c83a2` |

The middle two rows are the Access Monitor file; the first and last are Call Probe. Response records identify `InlineBatchUpload`, `POST`, the SharePoint destination host quoted in section 9, and a personal `SPFileSync` route. This verifies repeated synchronization of the two named diagnostic files: **292 upload completions, not 292 distinct documents**.

### Heartbeat timing and duplicate control

The Call Probe JSONL contains **59 heartbeats inside the decoded-ledger interval**. Matching each to the first subsequent upload start for the same object within two seconds produces **54 matches to 54 distinct starts**. Using all seven stored fractional-second digits:

| Heartbeat → upload-start delay | Seconds |
| --- | --- |
| Minimum | 0.5642883 |
| Median | 0.5763197 |
| Maximum | 0.6461459 |

This reproduces the earlier 54/59 count and subsecond relationship. The previously quoted minimum `0.564289` differs by 0.7 microseconds from the exact stored-clock calculation. Section 1's separate 58–65 ms measurements concern filesystem-read → TCP-send pairs.

The new **624,030-byte / 1,451-record** Call Probe attachment is an **exact byte-for-byte prefix** of the already reviewed **1,389,304-byte / 3,270-record** `02-events.jsonl`. Its events must not be counted again. It ends at September 19 **04:03:22.3674910 EDT** and includes the four append records analyzed in section 1.

The separate Access Monitor attachment has **2,904 records**, spanning **2026-09-19 02:22:52.255–08:03:21.230 UTC**: 294 monitor-status rows, 14 coverage rows, and 2,596 connection/identification rows. Labels such as “Possible OpenAI” are collector classifications; the file/object/request joins identify the uploads above.

## 18. September 19 Codex records: Drive reads, source copies and GitHub writes

The supplied records establish a transfer workflow in **`MailanPatternMonkey-ai/Gettin-Started`**, branch **`codex/drive-research-20260919-ronswanson`**. The publication rollout is:

`rollout-2026-09-19T04-05-48-01a0b8b3-3921-72c1-81a0-eba3dd512f6b.jsonl`

`01-watermark_item_matches.json` is a **312-item selection**, not the full rollout. Every item has a distinct source line and item ID. `03-watermark_tool_status.json` supplies 26 GitHub calls, including a completed file creation and fourteen completed tree creations. The thirteen tree calls in both files have identical item IDs, arguments and returned SHAs; they are overlapping evidence of the same calls.

### Captured retrievals and saved source records

The selected items contain **135 completed Google Drive fetches across 132 distinct returned file IDs** and **103 completed FileChange items**: 102 source JSON records and one `prepare_publication.py` file. All 102 saved source records have complete `result` objects exactly matching captured Drive returns for their file IDs. Their recorded directory is `C:\Users\drewd\Documents\Codex\2026-09-19\po\work\source\`.

For example, source line **171**, **2026-09-19 08:10:13.903 UTC**, returns document `1d9B3ci8Y-A72176ZspLRLCBTWD5aU-kMDS1yH_4EabY`, “08 — Empirical Geometry Tests — Source Reports”; line **177** records its source JSON. Its returned text is **18,863 UTF-8 bytes**, SHA-256 **`6fb466399d0e658d11d3dd38c5664b095662eaee0084b60d8b1b89726da58dd4`**, matching the later manifest's source fingerprint for `documents/08-empirical-geometry-tests-source-reports--ba788aef.txt`.

Overall, **100 captured retrievals from 100 distinct Drive file IDs** match retrieved-source SHA-256 entries in the publication manifest. They contain **77 distinct body hashes**, mapping to **77 edition paths**; duplicate source copies account for the difference. This links particular Drive returns to the GitHub tree payloads through their source fingerprints. The editions add attribution and can remove source locations; their published-byte hashes are checked separately below.

### Completed commit and bulk tree writes

All times below are UTC. Source lines refer to the original rollout.

| Time | Source line | Recorded operation and result |
| --- | --- | --- |
| Sep 19 08:15:26.914 | 515 | Created branch `codex/drive-research-20260919-ronswanson` from `c0fbee3da25c111dbe14fc9f8f00c784867528c3`. |
| Sep 19 08:17:57.248 | 663 | `github.create_file` automatically rejected the proposed review upload. Line 666 repeats the rejection in a wrapper output. |
| Sep 19 08:20:24.521 | 816 | `github.create_file` completed for the same path, returning **`b05b28fd50540676d71b7734195cd3b6c15e726a`**. |
| Sep 19 08:26:39.199 | 1088 | Commit fetch confirms that SHA, commit time **08:20:22 UTC**, parent `c0fbee3da25c111dbe14fc9f8f00c784867528c3`, and tree `8f543f4bc7e38c5ed022ec88d7259b09205689f1`. |
| Sep 19 08:30:06.066–08:32:36.998 | 1231–1341 | Fourteen `github.create_tree` calls complete with `isError=false`; every subsequent call uses the previous returned SHA as its base. |
| Sep 20 06:01:46.112 | 1411 | Branch-reference fetch still returns commit **`b05b28fd50540676d71b7734195cd3b6c15e726a`**. |
| Sep 20 06:01:46.137 | 1412 | `main` reference returns **`c0fbee3da25c111dbe14fc9f8f00c784867528c3`**. |

The successful file operation names:

`corpus/drive_uploads_2026-09-19/documents/geometry-simulation-and-thermodynamics-integration-review--6015dd33.txt`

Its message is **“Publish Ron Swanson research review with private source locations omitted”**. The fetched commit names `MailanPatternMonkey-ai` as author and committer. The create-file export retains metadata and the commit result but omits that call's content argument; the later tree payload separately supplies the edition's text. The message alone is not a byte audit of the earlier call.

The fourteen tree calls carry **262 distinct paths**:

| Content | Paths | UTF-8 content bytes |
| --- | --- | --- |
| Research editions under `corpus/drive_uploads_2026-09-19/documents/` | 259 | 11,426,475 |
| Corpus manifest, corpus README, root README | 3   | 373,218 |
| Total | **262** | **11,799,693** |

The total measures supplied `content` strings, not network transport bytes. The manifest contains 329 source entries: 259 edition entries and 70 marked duplicate source. Recomputing every edition's **published SHA-256 and byte count produces 259/259 matches** for both fields.

The first returned tree is `b6dec5d9de75cbf2fd67b5d338272175ac3c0bd9`; the last is **`82a3e606c3b47ab1a1cf7e54336549ced3967871`**. The chain starts from the single-file commit's tree and is continuous through all fourteen returned SHAs.

These are recorded successful **GitHub object writes carrying document content**. GitHub documents that an entry supplied with `content` writes a blob; making a changed tree the branch state requires a commit and reference update. [GitHub REST Git trees documentation](https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28). At the next-day observations, the named branch remains on the single-file commit. That reference state and the bulk object writes are separate findings.

**User clarification, September 28:** the user identified the CC0 republication as their own action (“that was me re cc0iing it”). This publication is therefore recorded as user-acknowledged, authorized activity. The earlier assessment that its authorization still needed explaining is superseded. The payload phrase “Published with permission” alone would not establish consent; the user’s subsequent statement supplies that context. The exports still do not name the connector credential, but that technical detail is not evidence that this acknowledged publication was unauthorized. The named rollout, document contents, destination, times and Git objects remain useful provenance records.

### Failures and supporting sources

The exception export has **58 entries**. **Thirteen explicitly record automatic approval rejection**: one GitHub file attempt and twelve Drive fetch attempts. Other entries are runtime, command or API failures. This replaces the earlier keyword index's unreliable count of six “rejections.” Both the rejected attempt and subsequent successful file creation are retained.

| Other file | Verified role and overlap |
| --- | --- |
| `04-codex_app_records.json` | 2,016 application-log rows, September 19 06:56:10–07:44:00 UTC at whole-second display precision, across 19 thread IDs. All nine rollout thread IDs in the session extract also occur here. |
| `05-session_records.json` | 242 selected records from nine rollout files: 114 custom calls, 113 custom outputs, one function call, one function output and 13 user-message records. Interval 06:56:18.024–07:44:00.336 UTC. |
| `09-call_arguments.json` | All 115 entries exactly match calls in the session extract by source file, line, timestamp, call ID and input/arguments. They are another view of the same calls. |
| `08-mysonted-analysis.json` | Derived parser output containing 1,413 rows: 435 detailed, 877 general and 101 OneDrive, all independently recounted. Its 15 boundaries and five rejected text entries concern parsing. The original `mysonted.txt` and `meanmang.txt` are absent, so their declared source hashes are not checked here. |

These earlier monitor-investigation sessions precede the publication rollout and are not substituted for its initiating user instruction. The September 19 `Gettin-Started` writes remain separate from the September 23 `Toroidal_scrotal_posturing` authorization question and the frozen September 7 revision findings.

### Source hashes — expanded-record batch

Hashes and sizes below were recomputed from attachment bytes. The reattached pre-update report matches SHA-256 `6ca8c37100d42e82d205a42134174bd23bc8324fc585188df8237d1d1ea68255` (112,639 bytes).

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-watermark_item_matches.json` | 60,206,105 | `0e1528b2c71f14fbd1b9e50bfe801334e6b13dd4afea106c8cfab7aade0850f3` |
| `02-onedrive-decoded.json` | 41,212,404 | `933b4417312289c9be3b51cd29d6f798e580bd6c276a13413eb7aeae2cf21d63` |
| `03-watermark_tool_status.json` | 13,141,966 | `64ba701b11043a7880b09fb397633e8ea9b3cda7ff7396472a63fcb9f586b3d8` |
| `04-codex_app_records.json` | 3,298,414 | `3475e79d3412c7fdc35aa862ad49d7445a29918f506a0e388e82a2b8e78cd811` |
| `05-session_records.json` | 2,386,843 | `33e80e88d48cee104eada9e296d6e20eb5eef38931996c33966c1a9ad43930ea` |
| `06-monitor-logs-access-events.jsonl` | 1,512,585 | `1ad52062ab03d2c451075b31787f91766dbca8e092ae5c73ad8422268de633f0` |
| `07-call-probe-v2.1-2026-09-19_00-43-32-242-events.jsonl` | 624,030 | `d3d8b5e5ceacb5ea4846e2c35264d0058ea776c5bb2dd37b921fd193d53c84c7` |
| `08-mysonted-analysis.json` | 467,245 | `23eafd6e960a342d24607693d3c95c26bf6dc4bf7267f5ec765c9292c4221b25` |
| `09-call_arguments.json` | 196,332 | `3c45e15d80122e13aba6991b3054efeb3f67abc02f8527f5f80f123eaf53596d` |

## 19. August conversation records: status phrases, correction requests, and research follow-through

### Scope and evidence identity

This batch consists of ten audit files, rather than 24 separately attached original transcripts. Its source manifest lists **24 transcript sources**, with declared record dates spanning **August 2–18, 2026 UTC**, **20,715 raw nodes**, and **8,762 conversational assistant text replies**. Another **141 text-only workflow preambles** bring the declared nonblank visible assistant-text total to **8,903**. These manifest sums agree across the supplied tables. **The subsequent `nodes.json` attachment now permits a record-level recount of these totals; see section 20.** The original 24 Markdown byte streams are still distinct from that parsed export, so their listed SHA-256 values and the manifest's 13 earlier mounted-source matches remain provenance claims rather than newly verified original-file hashes.

The supplied event bodies can be checked directly. All **1,997 event IDs, case/node pairs, and message IDs are unique within the final event ledger**. The standalone `04-events.json` and enriched `08-evidence_table.json` preserve identical event order, message IDs, text, timestamps, status-only labels, and recognized phrase spans. The latter adds surrounding records, conversational indices, diagnostic judgments, and explicit candidate labels. Its embedded summary is exactly equal to `09-final_counts.json`.

The **141 workflow records** preserve every original field from `06-workflow_preambles.json` and gain surrounding context. The **136 excluded occurrences** preserve their original message evidence and offsets; the enriched file expands the explanation of exclusion. These are representations of the same evidence, not additional observations. An excluded ordinary use of “thinking,” for example, can coexist with an included “One moment” in the same message.

`02-candidates.json` is a different selection: it has **1,823 records**, of which **1,740** share a case/node key with the final ledger; **83** occur only in the candidate file and **257** only in the final ledger. Its count is therefore not the denominator for the final census, and it should not be added to the final event total.

### Recomputed counts

Every one of the **2,038 recorded span offsets** reproduces its literal substring from the containing message. Aggregating those spans reproduces both the phrase-family summary and all **68 literal-variant rows** in the CSV. The following counts reproduce from the supplied event records; “status-only” and “additional content” retain the packet's screening definitions.

| Measure | Recomputed count | Interpretation |
| --- | --- | --- |
| All screened event messages | 1,997 | Includes nine incomplete wording fragments |
| Messages with complete recognized status markers | **1,988** | Conservative main count, excluding fragments |
| Complete recognized phrase occurrences | **2,029** | A message can contain more than one phrase |
| Fragment spans | 9   | Kept separate; intended wording is not reconstructed |
| Complete-marker messages coded status-only | **1,232** | No other substantive text in that same message under the supplied rule |
| Complete-marker messages with additional text | **756** | Text presence does not itself establish task completion |
| Separate workflow preambles | 141 | Excluded from the conversational denominator |
| Screened-out ordinary/quoted phrase occurrences | 136 | Occurrences, not necessarily distinct messages |
| All screened messages carrying `is_thinking_preamble_message=true` | **1,635** | Direct metadata flag; not an explanation of the backend mechanism |

Using the manifest's **8,762 conversational-reply denominator**, the conservative **1,988-message count is 22.69%**. This percentage describes this selected corpus and its declared indexing rules. It is not a population estimate for all ChatGPT conversations, a percentage of audio time, or a task-failure rate.

The most frequent complete phrase families are:

| Phrase family | Occurrences |
| --- | --- |
| checking | **970** |
| one moment | **541** |
| let me check and its recorded variants | 156 |
| one sec | 82  |
| let me look and its recorded variants | 65  |
| hang on | 43  |

The 1,997 inclusive events occur in **23 of the 24 listed sources**; `twentyfirst_share` has zero selected status events. Identical short wording across messages is repeated behavior, while distinct message IDs and node positions keep those occurrences separate.

### Recurrence is measurable in reply order

Recomputing the interval histogram in source-node order reproduces both supplied index systems:

* **A** counts conversational assistant text replies and excludes the separate workflow stratum.
* **T** includes those text-only workflow preambles as additional visible assistant-text records.

For the **1,988 complete-marker messages**, there are **1,965 within-source consecutive-event gaps**. In A units, **734 gaps are 2**, **496 are 1**, **235 are 3**, and **117 are 4**; the remaining gaps extend to **110**. A gap of 2 means one other counted assistant reply lies between two status-bearing messages. It does not mean two seconds, two audio turns, or a fixed system cycle. Including the nine fragments changes the corresponding gap-of-2 count to **738**, which explains why the inclusive and conservative tables differ.

This verifies frequent recurrence and shows exactly which indexing rule produced it. It does not require a theory about unseen participants or a hidden handoff.

### Preserved correction and research exchanges

The six correction sequences in `08-evidence_table.json` contain **55 quoted records**. Every quoted text also occurs in `07-diagnostic_exchanges.md`. That agreement checks two supplied representations; it is not an independent second recording. The following examples are directly readable in those preserved texts.

| Source / node locator | Recorded sequence | Supported finding |
| --- | --- | --- |
| `twentythird_share`, n334–n337; COR-01 | At n336 the user repeats “I don't want you checking.” The next assistant node n337 is “Checking.” | The requested change is not implemented in the next assistant reply. The earlier n335 acknowledgment is unfinished and contains no explicit promise to stop. |
| `office_metaphor`, n608–n619; COR-04 | A complaint about delay on a yes/no answer is followed by “Checking,” then “Yes, it did. It should have been a direct ‘yes’ without delay.” The next question again receives “Checking.” | The assistant acknowledges the complaint while continuing the same status pattern. Its statement about what caused the delay is its own explanation, not measured latency or an internal trace. |
| `fourth_share`, n253–n257; COR-02 | After “continue reviewing … come back … when you're done,” n254 promises “a deeper analysis of the corpus and each document.” At n257 the response supplies a broad methodological appraisal. | The quoted follow-up does not deliver the promised document-by-document analysis. The source preserves the promise and what was delivered, allowing the mismatch to be evaluated. |
| `twentysecond_share`, n1352–n1466; COR-03 | Repeated requests for research, sources, and data are followed by descriptions of how research should be done. At n1445 the assistant explicitly says, “I talked process instead of engaging the work.” The final quoted substantive response n1464 still recommends checking the factual claims one by one. | The visible exchange documents repeated substitution of process commentary for the requested factual audit. Two recorded tool-result nodes later in the sequence do not supply readable findings because their results are redacted. |

For COR-01, an independent count of the selected event bodies finds **70 subsequent assistant messages performing “checking” after n334**, including lower-case “checking” after “One sec” at n739. The subsequently supplied full node export also reproduces the **198 remaining conversational replies** after that request. The numerator and denominator are now both checked against the available records; see section 20.

The complete packet also preserves bounded improvements and changed instructions. In `first_share`, after a renewed request at n738, n741, n743, and n745 are brief listening/acknowledgment responses. In `seventh_share`, the user later asks for a story; that change means the story itself cannot fairly be scored as a violation of an earlier plain-speech request. These examples prevent the correction review from treating every later response as the same failure.

The concrete response-quality finding is **repeated status language plus specific recorded failures to carry through requested changes or promised research**. This finding concerns what the assistant said and delivered in the preserved exchange, without converting its declarations of research into proof that research occurred.

### Follow-up text and timestamp limits

Among the **1,232 complete-marker messages coded status-only**, the supplied next-content records and intervening-user counts reproduce this split:

| First later non-status content under the packet's rule | Count |
| --- | --- |
| Before another user input | **1,033** |
| After another user input | **198** |
| No later content in the available case | **1** |

With the nine fragments included, the status-only total is **1,240**, split **1,037 / 202 / 1**. These are structural outcomes. A clarification, incomplete answer, acknowledgment, or general commentary can satisfy the first-content rule without completing the original request. The packet contextually reviews **42 event messages**; its aggregate does not classify the completion of every task.

For the **1,037 inclusive status-only pairs followed by content before new user input**, subtracting the supplied ISO creation timestamps exactly reproduces the stored time deltas:

* **Median: 0.002869 seconds**.
* **837 pairs** have nonnegative differences below **0.1 seconds**.
* **157 pairs** have differences of at least **10 seconds**, including **29** at least **30 seconds**.
* One pair goes backward: `thirteenth_share:n379` to n380 is **−17.774067 seconds**.
* The largest difference is **282.606054 seconds**.

These are exported record-creation differences. The near-simultaneous values and backward pair mean they cannot be treated as a stopwatch of spoken waiting, playback order, or tool runtime. Source node order is preserved rather than reordered to remove the negative value.

### Recorded tool results and representation differences

Within the enriched table's embedded context, deduplicating tool-role nodes by source path and source node yields **91 distinct tool-result records**, all explicitly marked redacted in their metadata. The later full node export now independently supplies **all 135 tool-role records**, **134 explicitly marked redacted**. Its one unredacted result is an execution output listing image paths. This resolves the excerpt-coverage limit of the initial pass; details are in section 20.

For the supplied 1,997 events, **53** have tool-role records in the listed interval before the next user input, and **54** have them before the first later non-status content. These two different interval definitions account for different totals. Tool-result presence is recorded interaction; a redacted body does not identify what was retrieved, establish that a promised document was read, or demonstrate completed verification.

Five screenshot-only status events and eight representation comparisons are also described in the audit table. Their corresponding original image/transcript pairs are not all supplied in this batch, so those comparisons remain the packet author's documented findings rather than a newly repeated visual comparison. In particular, omission from a compact view, a blank exported structural node, and an explicitly redacted tool result are different observations and are not combined into an allegation of intentional transcript deletion.

This August conversation section remains separate from the September 7 document revisions, the September 19 recorded GitHub writes, the September 20 OneDrive completions, and the September 23 account-authorization inquiry. Its positive contribution is a reproducible phrase ledger, reply-order recurrence, preserved user corrections, and exact examples of promised work versus delivered text.

### Source hashes — conversation-status census batch

The reattached pre-update report is **128,220 bytes**, SHA-256 `428d6f868872694faaa6d1430e2895ea19b59177d18c348fd2246a0bdf44eda7`. The following hashes and byte sizes were recomputed from the ten new attachment files.

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-source_manifest.csv` | 5,115 | `32d6ce8fa529f45e7484de5b4dfe2b8fa5fa123b364ca6871cb50e5df0dc1299` |
| `02-candidates.json` | 1,733,799 | `bb0170dafeade4ba0e1e290ea838799b46213703f17fc3f9362cb912b63aef27` |
| `03-census_summary.json` | 2,446 | `ed87262cff22df085f17947788bfc94a53cbc62fd6941d4dd3c8334b936f6be1` |
| `04-events.json` | 14,132,793 | `91b64afdffd602d30a4b295013a36c14db12322ff6f9655443bc307233f5be43` |
| `05-excluded_occurrences.json` | 175,422 | `c08f38e88d46c59137b389cd24bd495882105f6f0c5f98307eb5b7253a0c40af` |
| `06-workflow_preambles.json` | 137,869 | `fbb2c04049e6d0a17b1c9487d135359305f86d453b3989f9667441a29873f9d3` |
| `07-diagnostic_exchanges.md` | 312,586 | `03a16f02841998a70f4af45b2e2f3c9afa3a1e016afee68ee5bb198acc9b671c` |
| `08-evidence_table.json` | 24,320,071 | `017565a5ab43b5b2c2fa9d8d0d836136a45d131bc551ce471b24b3cc7e81edce` |
| `09-final_counts.json` | 15,384 | `b76ec8391a9e89a6686c09d1d3c33ab6dbe7102fc317bda1f9a44dc33454e8c5` |
| `10-phrase_counts.csv` | 2,339 | `3945675928c0f989bd2ecc91bfcf6972d73d4e91e8235296870d62fca7e58da0` |

## 20. Full node export, process identities, and source-register reconciliation

### The earlier conversation counts now reproduce from full parsed records

`01-inventory.json` describes **30 source representations**. `02-nodes.json` contains **25,045 parsed nodes**, with per-case totals and role counts that agree with that inventory. Selecting the same **24 named sources** used in sections 13 and 19 yields exactly **20,715 nodes**, all with distinct message IDs.

Recounting directly by role, content type, nonempty text, hidden-message metadata, and workflow-preamble metadata yields:

| Independently recomputed from selected full nodes | Count |
| --- | --- |
| Nonblank visible assistant text records | **8,903** |
| Text-only records marked `is_thinking_preamble_message=true` | **141** |
| Conversational assistant text records after excluding that stratum | **8,762** |
| Earlier selected status events matching their full source records | **1,997 / 1,997** |
| Earlier workflow records matching their full source records | **141 / 141** |
| Earlier excluded phrase occurrences matching their containing source records | **136 / 136** |
| Quoted correction records matching their full source records | **55 / 55** |

For the event matches, compared fields include message ID, role, content type, text, timestamp, metadata, original source path, source line and body line. Every event's conversational reply index also reproduces by counting eligible full nodes in source order. The manifest's 8,762 denominator, previously checked only as a sum of reported counts, is therefore now independently reproduced from the parsed records. The conservative 1,988 complete-marker count remains **22.69%** of those replies.

This is a stronger source check than comparing two summaries. It still uses a supplied parsed export; original Markdown-file bytes and original audio are separate evidence. The original source hashes printed in the two inventories agree for the 24 selected cases, but agreement between inventories does not rehash absent Markdown files.

### Session identifiers and explicit export redactions

Within each of the 24 sources, walking nodes in source order and comparing successive populated `tc_session_id` values yields **43 changes in 20 cases**. Each change lands on exactly the same `(case, node)` key as the prior phase-1 boundary table. Repeating the extraction for `voice_session_id` yields **43 changes at those same positions**.

For example, `eighteenth_share` changes at n265 from `rtc_42358be84c144a35b19faad1fdbb7c23` to `rtc_3838afb14f544fb6ad4560b4386eaeda`; the preceding populated identifier is at n264. These are directly recorded identifier changes. They do not identify a human operator or establish why the session changed.

All **43 paired nearby context anchors** in phase 1 are actual `model_editable_context` nodes in the supplied full export. Its overall explicitly redacted-node counts also reproduce the relevant phase-2 totals:

| Recorded role / type with `is_redacted=true` | Count |
| --- | --- |
| Tool / text | **134** |
| Assistant / model-editable context | **105** |
| User / text containing the unavailable-custom-instructions placeholder | **24** |
| Assistant / text | **3** |

There are **135 tool-role nodes total** in this selected corpus. The one unredacted result is `twentyfirst_share:n53`, timestamped **2026-08-10 00:56:27.655301 UTC**, type `execution_output`. It contains the number 32 and a list of five `/mnt/data/…jpg` paths. Its presence supplies the exception to the 134-redacted count, rather than an inferred missing result.

### Duplicate control and the six additional representations

The 30-representation inventory must not be treated as 30 independent conversations. **`shared_chat` repeats all 809 message IDs from `first_share` in the same sequence**, with the same roles, content types and timestamps. Every shared-chat node number is one higher. Its metadata objects are empty; eight image-input user records have blank text where `first_share` retains `[image input]` placeholders. The other message text agrees. This is a demonstrated representation difference, with no basis here for assigning intent to it.

Deduplicating all 25,045 supplied nodes by message ID yields **24,236 distinct IDs**. The five other added source labels contain **3,521 nodes** outside the frozen 24-source census:

| Additional source | Nodes | Recorded UTC dates |
| --- | --- | --- |
| `test43` | 217 | August 22 |
| `testwritten3` | 980 | August 22 |
| `twentyfifth_share` | 132 | August 20 |
| `twentyfourth_share` | 431 | August 20 |
| `twentysixth_share` | 1,761 | August 19 |

These added records are retained as additional material. They have not silently been folded into the previously reported phrase totals or denominator. The duplicate `shared_chat` representation contributes no additional conversation observations to that census.

### September 26 process snapshot: monitor and extension host

`07-process-list.csv` contains **354 rows and 354 distinct PIDs**. Executable paths and command lines are populated in **200 rows**. The CSV has creation dates, not a separate capture timestamp or timezone field. Times in the following table are rendered as the file's displayed local times; the report's EDT convention is contextual, not encoded in those cells. The latest creation field in the whole snapshot is September 26 at **16:51:35**.

CSV line numbers include the header as line 1.

| CSV line | Process / PID | Recorded parent PID | Displayed creation time | Identifying command or role |
| --- | --- | --- | --- | --- |
| 189 | Python 3.12 / **41564** | Explorer **3856** | Sep 22, 16:45:59 | Runs `C:\Users\drewd\OneDrive\Desktop\access_monitor.py` |
| 311 | ChatGPT.exe / **46912** | Explorer **3856** | Sep 26, 16:24:56 | Main executable under `OpenAI.Codex_26.917.8451.0` |
| 314 | ChatGPT.exe / **52272** | **46912** | Sep 26, 16:24:57 | `--type=utility --utility-sub-type=network.mojom.NetworkService` |
| 318 | codex.exe / **50304** | **46912** | Sep 26, 16:24:59 | `app-server`; binary directory `80f78947ad880e6e` |
| 320 | cmd.exe / **44828** | **50304** | Sep 26, 16:25:07 | Calls `./scripts/launch_codex_app_tools_mcp.cmd ./server.mjs` |
| 321 | node.exe / **20980** | **44828** | Sep 26, 16:25:07 | Runs `./server.mjs` using Codex's `cua_node` runtime |
| 333 | codex-computer-use-swift.exe / **24312** | **46912** | Sep 26, 16:27:46 | Command explicitly includes `--parent-pid 46912` |
| 341 | codex-code-mode-host.exe / **54888** | **50304** | Sep 26, 16:28:03 | Same `80f78947ad880e6e` binary directory |
| 235 | chrome.exe / **33372** | Explorer **3856** | Sep 25, 17:10:31 | Parent of the extension-launch shell below |
| 338 | cmd.exe / **52728** | Chrome **33372** | Sep 26, 16:27:54 | Launches Codex's `extension-host.exe` with the extension URL and native-messaging pipe redirections |
| 340 | extension-host.exe / **8264** | cmd **52728** | Sep 26, 16:27:54 | Names `chrome-extension://hehggadaopoacecdllhhajmbjkdcmajg/ --parent-window=0` |

The host's full path is:

    C:\Users\drewd\.codex\plugins\cache\openai-bundled\chrome\latest\extension-host\windows\x64\extension-host.exe

This establishes an **observed Chrome → cmd → Codex extension-host process chain**, with the extension ID in both the shell's launch command and the host's own command line. It is stronger than finding the extension ID in a preferences file. It identifies a running communication component on September 26; a process snapshot does not supply a particular browser action, document write, or transmitted payload.

The Python command separately identifies **PID 41564 as Access Monitor**, resolving the earlier process-tree uncertainty about that Python branch. The snapshot's main Codex PID **46912** is an earlier September 26 process generation than **59860** and the later updated **52604**. Its network-service PID **52272** is likewise distinct from **57420** and **32520**. Those process generations retain their own timestamps and parent relationships.

Microsoft Copilot has its own recorded desktop process tree: main **54252**, created **16:26:10** with `--no-startup-window /prefetch:5`, and four children for crash handling, GPU, network and storage. Its recorded parent **22324** is absent from the snapshot. A separate **mscopilot_proxy.exe 10792**, parent **svchost.exe 2316**, has `-Embedding` in its command. This records local Microsoft Copilot processes. The GitHub **Copilot Chat App** token and authorization events remain a separate account-level evidence item.

### Role of the four accompanying documents

| Attachment | What this pass verifies or retains |
| --- | --- |
| `03-September_20-22_Artifact_Findings.md` | The earlier source-backed Docker/Prefetch/Jump List report. It retains the three September 20 completed coordinate-click calls, three separately dated September 21–22 restart transactions, and the 3.997 ms Python/Jump List correlation. Its Jump List hash matches the baseline already identified in section 4. Reattaching this report is not a new occurrence of those actions. |
| `04-Verified_Findings_2026-09-26.md` | An earlier **v1.0** synthesis. It preserves the seven-document, 245.622-second revision-state interval and the nonconsecutive D7 **8→18** comparison. It also reports the later 59860/52604 process generations. This attachment does not replace the frozen later revision findings or turn today's earlier 46912 snapshot into the same process instance. |
| `05-112-Coverage.md` | Recounting its numbered index gives **164 entries** and exactly the stated twelve source-group totals, including **90 Drive-current-read entries**. Its separate empty-native-document list has **13 distinct IDs**, including all seven target IDs. The 141-normalized-text / 19-duplicate-group claims remain the earlier report's findings because the 164 original text bodies are not in this attachment. |
| `06-Geometry_Upgrade_v1.md` | A mathematical correction/extension note about a polynomial sign convention, substitution-domain injectivity, coefficient matrices and exact lattice volumes. Its embedded verification program and its reported test results remain part of that research artifact; no attached program was executed during this review. |

### Source hashes — full-node and process batch

The reattached pre-update report was **142,879 bytes**, SHA-256 `0fb9b81ea8578b6407e950980411337c8931b4772b7d274892feee35763af665`.

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-inventory.json` | 19,179 | `db9126e2c9a8b160ff9b242e6c2e709f90edecdfd5f553d840a186a5d902088e` |
| `02-nodes.json` | 24,084,034 | `0b140ef5404ea7ac71847f6b14e579227add187e2ef18b26119e4e864be5be21` |
| `03-September_20-22_Artifact_Findings.md` | 13,371 | `bc34a44a68ed91141027c388fd32d235432af57c8f14ab653794fafd3dddf46a` |
| `04-Verified_Findings_2026-09-26.md` | 8,954 | `b8c602491245f3b36195bc3e0802174e178921c6986d2165ef210621a9d72158` |
| `05-112-Coverage.md` | 39,135 | `a9e3f793ba411dccb0dc172e7bd2db6074cbc10d31904908e2fffea248207d6f` |
| `06-Geometry_Upgrade_v1.md` | 14,602 | `3c159fe98b4d8cabacd60ed9610516eb04c8f6c205c00ef92dbd00f1787e2514` |
| `07-process-list.csv` | 119,387 | `9f4083fcbe54ed2ce1777927ff88868739b4528459de24e2f47cd5af900bd53a` |

## 21. Evidence Ledger v12 manifest and version-check records

### Byte identity across supplied copies

The newly supplied `01-SHA256SUMS.txt` is headed **Evidence Ledger v12**. Parsing its SHA-256 entries yields **107 listed paths and 106 distinct hash values**: 95 paths under `sources/` and twelve root-level reports/checks.

Recomputing hashes verifies **all nine attached JSON check files** against their named manifest entries: the trace metadata and checks v4 through v11. Matching named source candidates already available in this conversation's workspace also finds **17 source-entry byte matches**. Thus **26 listed entries have directly matched available copies in this pass**. This is a positive identity check for those entries, not a claim to have obtained or verified every file in the 107-entry package.

The 17 source matches include:

* The retrieved-pages record, `sources/22-S001-retrieved-pages.json`.
* Revision material: the previous-revision response, recovered-revisions report, Revelation diff, revision evidence and revision lists.
* Raw conversation excerpts, transfer verification, the earlier SHA-256 manifest and its verification report.
* Corpus-integrity and conversation-count check files.
* Three Human-claim-matrix representations, mathematical checks, and the agency-context review.

A matching SHA-256 identifies the same bytes in two locations. It does not by itself authenticate the circumstances under which the record was originally produced or establish that every conclusion in an analytical JSON is correct. The differing report-version numbers here refer to **Evidence Ledger versions**, not versions of this cross-source review.

### Direct joins to this review's preserved evidence

**Both September 19 monitor hashes in v11 match the actual monitor copies already used in sections 17–18:**

| Preserved monitor copy | Bytes | SHA-256 |
| --- | --- | --- |
| Call Probe `events.jsonl` | **624,030** | `d3d8b5e5ceacb5ea4846e2c35264d0058ea776c5bb2dd37b921fd193d53c84c7` |
| Access Monitor `access-events.jsonl` | **1,512,585** | `1ad52062ab03d2c451075b31787f91766dbca8e092ae5c73ad8422268de633f0` |

The v11 check states that these bytes were read at **08:03:24.940031 UTC** and **08:03:24.950540 UTC**, respectively. Those are the recorded collection times. They do not turn the complete later file hash into a hash of every earlier uploaded version.

Its **292 successful OneDrive completions**, split **290 Call Probe / 2 Access Monitor**, agree with the row-level verification already completed in section 17. This attaches an earlier audit's identifiers to the same monitor files and same upload series. It adds no new 292-event series to the count.

The manifest-matched `Raw-turn-excerpts.json` contains **49 records**. Every record matches the new full `nodes.json` by case/node, message ID, text, timestamp, role, content type and metadata. These are **33 assistant and 16 user records**, across `fifth_share`, `seventh_share` and `twentythird_share`. The earlier excerpts and today's full-node source are therefore directly linked, rather than merely having similar text.

The manifest-matched `Transfer-verification.json` supplies **33 detailed rows**, independently recounted as **28 Success / 5 Failure**, across **three file IDs**. This is the separate later September 19 transfer check summarized by v10. Its rows include saved source filenames, record indices, file IDs, response references and completion times; they explicitly say transferred bytes were not decoded. Recounting this derived receipt is distinct from a fresh decode of its original binary logs, and these rows are not automatically added to section 17's earlier 292-completion series.

The manifest-matched `Corpus-integrity-check.json` has **164 check rows**, all with equal recorded expected/actual hashes. This confirms the check file's internal accounting. Rehashing all 164 underlying normalized text files would require those original extraction files. The three-field conversation-count object in v11 also exactly equals the manifest-matched `count-recomputation.json`.

### What each version check contributes

| Check | Preserved finding and scope in this pass |
| --- | --- |
| Trace-review metadata | Records a static inspection of two `.pyc` files, with their hashes, sizes, embedded source filenames and code-object names. Both are marked `executed=false`. These are metadata claims about those bytecode files; the bytecode was not executed here. |
| v4 integrity | Records matching source hashes for retrieved conversation pages and an Access Monitor snapshot, plus three duplicate-upload comparisons. Its 203 distinct socket keys and 262 encoded events describe a specified observation/deduplication scheme, not 203 proven new socket creations. The retrieved-pages file is one of the 17 direct byte matches. |
| v5 reproducibility | Preserves seven duplicate-JSON comparisons and earlier checks reporting 49/49 manifest matches and 75 passage records. Its own `scripts_executed=false` is explicit. These earlier reported checks are not another execution of the tests today. |
| v6 screenshot timing | Explicitly records that the uploaded JPEG copy differs from the alignment report's original in hash, size and EXIF fields. It preserves three log observations at displayed times 14:23:17–19. The original image's EXIF cannot be attached to the different upload copy as though extracted from that copy. |
| v7 network provenance | Records 131 pasted observations: 74 already-open, 42 identification updates, and 15 first-observed. Its 89 non-relabel rows equal 74+15. It also retains process-signature results and IP-lookup successes/errors as separate evidence types. |
| v8 network coverage | Gives a September 17 snapshot interval, selected remote-program-name checks, eight TerminalServices records and audit-access limitations. It is a bounded historical check rather than a current scan of the user's PC. |
| v9 local backup | Preserves a local Robocopy receipt: 24,095 copied files out of 24,096, one failed 63-byte file, and the local source/destination paths. The original Robocopy log is identified by name, byte count and SHA-256; this batch supplies the analysis JSON. |
| v10 revision/transfer | Summarizes 13 empty-native-document checks, earlier text found for eight, the seven September 7 pairs, a separate Politics DOCX control, and the 33-row later transfer receipt. The matched revision records and transfer-check file identify the earlier material it summarizes. |
| v11 access audit | Connects the known 292-completion series, three Codex session starts, monitor collection hashes, corpus checks, and a separate coded conversation sample. The precise file and record joins above are newly checked against available copies. |

### The backup receipt's concrete result

The v9 record quotes a run from **September 23, 16:29:18 to 16:30:29** in its displayed local times:

    Source:      C:\Users\drewd\OneDrive\
    Destination: C:\FULL_CLOUD_BACKUP\OneDrive\
    Files:       24096 total; 24095 copied; 1 failed
    Bytes:       33.386 g displayed; 63 failed

The file-count percentage recomputes to **99.9958499336%**. Its four recorded error entries all name **one** dot-GUID file at the root of the local OneDrive folder; the repeated entries are retries against that same path. The check also records evidence-anchor paths under `Adversarial-review-2026-09-20` and its Desktop copy.

This receipt concerns copying from one local C: path to another. It supplies a dated backup-location lead and the reported copy outcome. It is not a cryptographic source/destination comparison or evidence that every cloud-only file was present locally. The unusual directory-count line is retained as printed rather than silently reconciled: it lists 2,573 total, 2,573 copied and 1 skipped.

### Keep the conversation samples and mathematical measures distinct

The v11 conversation-count object describes **422 opportunities**, **332 primary opportunities**, and **323 primary observed responses** in a different coded sample. Every listed response-field distribution sums to **323**. Its reported **102 composite failures** therefore equal **31.58%** of that coded observed sample. These are earlier adjudicated labels preserved in a matching check file; this pass has not recoded the underlying opportunity CSVs.

Those 323 responses are not the denominator for section 19's 1,988 status-bearing messages, and the failure percentage cannot be applied to the 8,762-reply census. Likewise, the mathematical-check object's 10,000-state arithmetic exercise explicitly says `causal_effect_tested=false`. Its arithmetic quantities are kept with that mathematical exercise and are not treated as measured rates of platform actions.

### Source hashes — version-check batch

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-SHA256SUMS.txt` | 11,016 | `35a4870f95b370e4d71a908bd3b96d4755c5b00c9471c88e5b7508ca9e1ae313` |
| `02-trace-review-metadata.json` | 7,259 | `184fc1d09bf90d6fd99840cf97f37f3ab5fc8b8d04f4c89cad83a21b391c7be6` |
| `03-v4-integrity-check.json` | 2,571 | `815fdf32a565f80e922a5dc37c01e61eb634e518c403a500645ca32b34c0dee9` |
| `04-v5-reproducibility-check.json` | 4,107 | `e5c12aa403d58475c21193b5a8977a6e1c4b95495084917c376e225a4673c107` |
| `05-v6-screenshot-timing-check.json` | 5,824 | `da9212b21d08d52d9697bd33340ff0e2d9949d73ee7457569e76d11516cc2ac9` |
| `06-v7-network-provenance-check.json` | 7,833 | `7b4220f666ae7e59c94fcefb8e677a707f3c9f14612894cf64ad1ca8209f6600` |
| `07-v8-network-coverage-check.json` | 5,046 | `64b8a254a421ecc4c35fc47dc9d6a0d5e9d24fa87883912de4591544e0a9b512` |
| `08-v9-onedrive-local-backup-check.json` | 5,327 | `bd9c6a48a0c78b804f2348e0ef7aba47d33df7e91ea9bc5b3f2f0147e5f31ebf` |
| `09-v10-revision-transfer-check.json` | 12,794 | `b11eed6412c7068c32ad95d07ac4f6fca3c6afb3736d693bd2915333baa8976f` |
| `10-v11-access-audit-check.json` | 12,808 | `0f378a4c366dce38b920868b5c15ef80817a53ab94fa097e0c9965b1f6ff63c5` |

## 22. September 17 signatures, saved registry results and connection relabeling

The ten new JSON attachments were read as saved evidence. No uploaded script was executed and no fresh scan of the user's Windows computer was performed. Their hashes all match their respective entries in the supplied Evidence Ledger v12 `SHA256SUMS.txt`. Eight also have matching size/hash entries in the supplied 58-entry network-package manifest. The screenshot-alignment JSON is not listed in that smaller manifest, and the manifest does not list itself; neither is a failed check.

### Recorded software identities

The two process-signature lists contain **16 process rows: 12 report Valid, four have blank results and unavailable paths**. The 12 valid rows cover 11 distinct executable paths because two backgroundTaskHost processes use the same file. Blank results occur for NortonSvc PID 4952, svchost PID 7304, FileSyncHelper PID 53888 and WDDriveService PID 7316. These are missing measurements, not recorded invalid signatures.

| Recorded executable(s) | Recorded publisher | Result in saved check |
| --- | --- | --- |
| ChatGPT PID 34584, package `OpenAI.Codex_26.908.9136.0`; codex PID 56000, bin `12219cbfbcbddde7` | OpenAI OpCo, LLC | Valid for both |
| Chrome PID 30064; nearby_share PID 56052 | Google LLC | Valid for both |
| CrossDeviceService, OneDrive, OneDrive.Sync.Service, PhoneExperienceHost | Microsoft Corporation | Valid for all four |
| Two backgroundTaskHost rows, CrossDeviceResume, LockApp | Microsoft Windows | Valid for all four |
| Installed `C:\Program Files\Norton\Suite\NortonSvc.exe` | Gen Digital Inc. | Separate installed-file check reports Valid |
| Installed WDDriveService.exe under Western Digital's WD Drive Manager | Western Digital Technologies, Inc. | Separate installed-file check reports Valid |

The installed-service results identify files at the given paths; they do not retrospectively recover the unreadable paths of the live Norton/WD process rows. The second Norton JSON records the same installed path and signer with numeric `Status: 0`. No attached executable bytes or executable hashes were supplied here for independent signature validation.

Both OpenAI rows name OpenAI in `Signer` and a Microsoft timestamp authority in `TimestampSigner`. These are different certificate roles. A timestamp countersigns the software signature; this field is not a record of Microsoft launching the executable or controlling its session. See Microsoft's [Authenticode time-stamping documentation](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures). The saved validity results support publisher identification at collection time; they are not a verdict on every action the software performed.

### Connection counts and infrastructure mappings

The pasted connection extract spans displayed times **11:25:10–11:26:03** and contains:

| Phase | Rows | Recounted meaning |
| --- | --- | --- |
| Already open at startup | 74  | Baseline observations |
| First observed | 15  | Additional observed tuples |
| Updated identification | 42  | All match earlier tuples in this same extract |
| Total | **131** | **89 distinct process/PID/local/remote tuples** |

Of the 42 relabeling rows, 41 concern codex PID 56000 and one concerns ChatGPT PID 34584. Counting these rows as 42 additional connections would inflate the result. The JSON contains time-of-day fields; its September 17 placement comes from the surrounding source packet and dated signature/lookup records, rather than a date embedded in every connection row.

The saved IP lookup file contains **48 addresses, 29 successful registry-result summaries and 19 registry errors**. The follow-up has **four successful range summaries and five errors**. Combining the saved ranges permits **24 of the 25 connection-excerpt destination addresses** to be associated with a listed range; `162.247.241.14` remains without a successful range result in these files. Range containment is a derived comparison, not a newly successful query for each address. Section 26 subsequently supplies an official New Relic range reference for the remaining address, with a separate September 28 retrieval date.

One specific bridge is useful: the extract lists **ChatGPT PID 34584 → 64.239.123.193:443**, and the successful follow-up names **VERCEL-10, 64.239.123.0–64.239.123.255**. The separately named `arin-rest-64.239.123.193.json` consists only of `null` plus CRLF; it supplies no registry response. The range evidence comes from the follow-up file. The other saved ranges include Cloudflare, Microsoft, Google, Akamai and GitHub. These identify infrastructure ranges; they do not identify a particular URL, customer, document, request payload, or a joint actor. In particular, the Vercel range alone does not establish an OpenAI marketing request.

### Screenshot timing retained with its source distinction

The alignment JSON describes an original JPEG with SHA-256 `f06df3ef3e3fe3ddbf6a3c8acbed24914668dda2b3e37545028edde4bd79aaae` and reported capture time **2026-09-17 14:23:09.085 EDT**. Its three listed socket observations follow by **8.688, 9.689 and 10.685 seconds**; those arithmetic differences reproduce exactly.

The prior v6 check records that the uploaded visual copy has a different hash, dimensions and EXIF fields. Receiving this alignment report does not erase that distinction or independently supply the original JPEG metadata. Its own limits also distinguish the Android screenshot from the Windows network observations and state that no shared request ID was supplied. The finding is a reported clock comparison, not a message-to-request attribution.

### Scope of the publication correction

The user's CC0 clarification has been applied to the established-findings paragraph and section 18. The September 19 research publication is acknowledged user activity. This update does not assign that clarification to the separate September 23 `Toroidal_scrotal_posturing` license/README change, and it does not alter the frozen September 7 revision findings.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-49-process-signatures.json` | 4,945 | `5c0a8c2a5fce463f0cba951cb0408c84138097dc09f777a6fd3831f457c75fdf` |
| `02-50-public-ip-lookups.json` | 25,256 | `6937ce6619253d459389f8fc07289d3c525e7da2c9ed55a16316ef78cf29b1cb` |
| `03-52-registry-followup-results.json` | 1,874 | `b345c7c290ad449676fb70ae513355a004aa4f4bcb4359c6fe6c6edc289c4e85` |
| `04-33-screenshot-alignment.json` | 1,638 | `c5ed1cf6a5a9a3eab78287953f00f5cdd576c2dfd4726c953c1e996149f87351` |
| `05-36-additional-process-signatures.json` | 1,647 | `1861957c354813676c491bba9ab57c1d611d1762a9de431348865d94f63159ef` |
| `06-37-arin-rest-64.239.123.193.json` | 6   | `abdfbffecbe18ed94df9829819e596ee285b52a94aa108514452a9121721c789` |
| `07-41-installed-service-files-signatures.json` | 496 | `25e4aeb9d085412242da5031169244960f5744f4ff65c79464240760fc833dce` |
| `08-43-manifest.json` | 8,938 | `b2720c2949cbfe1c2b8cd23bcde05397663f1a283da4e16a6a2ea285fe334250` |
| `09-47-norton-installed-file-signature.json` | 156 | `a557eda9faf194d3888eb9b8cf4531422f58b8bf1f918fc7bb444e36f2f95fbe` |
| `10-48-pasted-connections.json` | 31,527 | `294493da86ce97b576ee65f1e841af2131926fbf40c0649edbced4e80b4b3223` |

## 23. Revision bodies, September 19 process context and local-session records

All ten attachments in this batch match their corresponding hashes in the Evidence Ledger v12 manifest. Several revision and conversation files reproduce sources already checked in section 21; they are corroborating copies, not additional incidents or additional recovered documents.

### Eight preserved text-to-empty state comparisons

The revision-list file covers **16 objects**; the evidence table contains **13 Google Doc comparisons**. All 13 earlier/later timestamp pairs and later-account metadata match the corresponding revision-list entries. Eight table rows identify recovered earlier text; five report no text in the tested earlier revision. The five tested-empty rows must not be counted as five additional demonstrated text removals.

For all eight recovered rows, the preserved earlier `structuredContent.content` was compared to its raw SHA-256, normalized SHA-256 and character count. Normalization removes leading BOMs, converts CRLF/CR to LF and strips surrounding whitespace. All checks match; all eight recovered `.txt` copies equal the corresponding raw UTF-8 export bytes. The paired later records each contain only U+FEFF, a BOM.

| Preserved set | Earlier text | Later state/time |
| --- | --- | --- |
| Seven frozen September 7 target documents | **55,571 normalized characters** | BOM-only exports; later revision times 19:50:23.052–19:54:28.674 EDT, span **245.622 seconds** |
| Separate September 8 document `1JwG936SNgpBF_O841kkUWOF6O8zGydqANvsk0ViJqRE` | **19,038 normalized characters**, revision 3 | BOM-only revision 4, **September 8 14:55:57.416 EDT** |
| Eight-document recovered-text total | **74,609 normalized characters** | Two date groups, not one eight-document incident window |

The September 8 earlier revision is dated **13:55:03.378 EDT** and begins with the label `BEHAVIORAL_CORRECTION_REGISTER.pdf`. The September 7 D7 comparison remains **revision 8 to 18**; the intervening states are not supplied. Account attribution remains the recorded Ron Swanson Google account, not an application or physical operator identity.

The separate Revelation JSON preserves **revision 2**, dated **August 31 01:01:55.431 EDT**, containing **51,358 normalized characters**. Its original content string is 52,143 UTF-8 bytes with SHA-256 `60ee4dea18855b2229da06b7b65ebf6e27cd90820ada6a23d1c2ea217c6c5e2f`. This is a separate surviving work and is not added to the eight-document recovered-text total. Its revision list separately names revision 3 on September 2; that list alone does not describe what changed.

The 44-entry local-output manifest was checked against the existing extracted archive directory. **All 40 materialized entries match both bytes and SHA-256.** Four public-source exhibits are not materialized at those paths in this working copy; they are not mismatches, and this pass does not newly validate those four exhibit bytes. Internal matching does not independently authenticate the records with Google. The 49 raw-turn excerpts also exactly reproduce the already examined archive copy; the earlier node comparison remains the relevant source check.

### September 19 process and synchronized-folder context

The process/folder record was collected **September 19 at 04:02:57.544 EDT**, about eight minutes after the file read/send capture in section 1. It supplies this mapping:

| Process | PID | Parent | Recorded creation time, EDT | Recorded executable |
| --- | --- | --- | --- | --- |
| ChatGPT.exe | 3680 | 24132 | Sep 18 22:16:21.699759 | Codex package `26.915.4065.0` |
| ChatGPT.exe | 3868 | 3680 | Sep 18 22:16:22.066918 | Same Codex package |
| codex.exe | 56004 | 3680 | Sep 18 22:16:23.244166 | Codex bin `247581e40ee272fb` |
| chrome.exe | 22132 | 31876 | Sep 19 02:05:52.227431 | Google Chrome Application directory |

This binds the previously observed Codex PID **56004** and ChatGPT PID **3868** to parent **3680** and the same dated package generation. It supplies no command-line subtype for PID 3868, so this file alone does not identify that child's Chromium role. It is a different generation from the September 17 and September 26 trees.

The same record gives OneDrive root **`C:\Users\drewd\OneDrive`** and Desktop **`C:\Users\drewd\OneDrive\Desktop`**. That directory relationship supports the earlier explanation for diagnostic logs under Desktop being within the OneDrive folder. The actual upload evidence remains the read/send and completion records, rather than the folder path alone.

### Terminal Services and WD service identity

The eight-event Terminal Services extract covers **September 9, 12:18:49.948–12:22:48.514 EDT**. It contains two shutdown notifications, two RDSAppXPlugin initialization messages, session arbitration begin/end, a successful session logon and a shell-start notification. The logon and shell-start rows explicitly name **FREQUENCY1109\drewd, Session ID 1, Source Network Address: LOCAL**. This is a retained local-session sequence. These eight rows do not constitute a survey of all possible remote access over other dates or applications.

The WD registry export names **WD Drive Manager** and points to `C:\Program Files (x86)\Western Digital\WD Drive Manager\WDDriveService.exe`. After removing only the surrounding command quotes, the path exactly matches the separately supplied installed-file check reporting a valid Western Digital signature. This joins the service configuration to that checked file, while leaving the earlier unreadable live-process path as unavailable.

### September 17 network-summary reconciliation

The new summary reproduces the earlier pasted extract's phase, process and endpoint counts and all 15 first-observed rows: **131 rows, 89 distinct observed tuples, 42 relabels**. Its larger snapshot summary covers **11:25:10.303–11:33:41.867 EDT** and reports **262 records**: 245 connection-related rows plus 17 monitor/coverage rows. The 245 comprise 74 startup observations, 129 first observations and 42 relabels, giving **203 observations without relabels**. At this stage the supplied summary included all 129 first-observed entries but not every baseline/relabel record. Section 25 subsequently parses the full 262-row snapshot and independently verifies the 203 distinct tuples and all 42 relabels.

The retained coverage messages explicitly report that the login log was unavailable because the query lacked permission. That is a collection limitation, not a count of zero Windows logon events. The separate verification JSON's assertion of 25 destination attributions is retained as its author's result; this update does not enlarge section 22's independently reproducible 24-of-25 saved-range matches without the additional source supporting the remaining address.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-70-revision-lists.json` | 29,064 | `430f0abcf6713602be9aede3fb240a122f0d3ae2ebf4b08f7cbdb1dbc572fe8c` |
| `02-71-SHA256-manifest.json` | 8,972 | `b3eb295ad43f5db2106495a1f207ef5b2e6a046a3ea0a6e1e836b6cbbdcd8f7f` |
| `03-56-summary.json` | 111,653 | `834efb98d5667605ea75843505e102efb772292b2977457e5c7102f96ebd4cd6` |
| `04-57-terminal-services-last8.json` | 1,484 | `3a0b5d22f4e22f953fc931d2c90d5c857d6f1cee922a147f8f7c72382c00a542` |
| `05-59-verification.json` | 271 | `5736ea503e771a82c2ae8d93862d0397a4aba97fad70f748f1cf201dff28359d` |
| `06-60-wd-service-registry.json` | 145 | `3eecd0fc3f9fe9da4dcc6deb1a4b9c54b09b52743bce400b91b7639df4073e46` |
| `07-64-previous-1hfxlL_TIv6r7O8ZwKHg-EcqCgGc8jW9qX_yAzWwkdYE.json` | 54,507 | `10c1abd4c88c8a3fad2138bec420fdb0175b57d56a699006bd90f335af861152` |
| `08-65-Process-and-sync-folder-records.json` | 1,277 | `16af233a2c613b18f878de6449bb04b799c5a1dbf66a9b908ff19a433e8a4d00` |
| `09-66-Raw-turn-excerpts.json` | 45,392 | `b80dcaabd4774801c0b8c4fed3b1e578f2afac1ea98b663a317361b543492102` |
| `10-69-Revision-evidence.json` | 17,568 | `c26dc56e173b26e9e21cc2817832f9ec2987cd0ba975bc931e5ff18d86cfb2b6` |

## 24. Codex action trail, audit availability and later diagnostic uploads

The ten attached files match the Evidence Ledger v12 manifest. Repeated corpus, revision-manifest and transfer-verification files retain their prior hashes. The access/app extracts supply a more focused view of already recorded September 19 work; overlapping records are not additional tool calls or additional uploads.

### Recorded Codex operations and app activity

`Codex-access-evidence.json` contains **three session starts and 13 tool-operation records**. All 13 operations match the earlier `05-session_records.json` extract exactly by source file, call ID, request, output blocks, source lines and timestamps. This corroborates particular recorded actions:

| Local time, September 19 EDT | Recorded action and outcome |
| --- | --- |
| 02:56:21–02:56:32 | Reads the ChatGPT thread titled **IP Nation Lookup** and a local preview of supplied log text. |
| 02:57:25–02:58:13 | Web/IPinfo, reverse-DNS and registry/geolocation lookups; retained outputs include completed command results. |
| 03:08:33–03:08:40 | A single-IP lookup for `2.19.246.60` returns a result. A separate web-open attempt errors. |
| 03:12:18–03:16:30 | Reads the thread titled **Self Description** and local previews of supplied text/log files. |
| 03:16:45–03:16:55 | A proposed batch of **seven additional IPinfo queries is rejected** by automatic approval review. The stated reason is that the approval covered a preceding single-IP lookup, not the expanded payload. The request's assertion that permission extended to seven addresses is therefore not accepted as authorization evidence. |
| 03:25:37–03:25:44 | Downloads five public provider files for local matching: AWS ranges/geofeed, Cloudflare ranges, Google ranges and GitHub metadata. The command returns exit code 0 and file sizes. Its URL arguments do not contain the logged addresses. |
| 03:35:10–03:35:11 | Reads `Downloads\Untitled345.txt`; the retained result reports 229,282 bytes and 1,801 lines, with output truncation. |

These operations show that the investigation itself generated some external lookup/download requests. They do not bind every contemporary TCP tuple to a request. Read-thread outputs are partly truncated; five read-thread calls refer to two distinct threads, not five additional conversations. The excerpt is selected rather than a complete record of all activity or all approvals.

The 28 desktop-app rows contain **21 completed conversation refreshes, three local thread-start requests, two sidebar-open attempts and two sidebar-load failures**. They span **02:46:07.231–03:39:28.215 EDT**. The three thread-start requests precede the three session-start records by **447, 471 and 455 ms**, respectively. Their log filename contains PID **3680**, consistent with the separate process snapshot in section 23. Session metadata names `originator=codex_work_desktop`; its `source=vscode` field is retained as a metadata label, not independent proof that a separate VS Code process launched the work.

The refresh rows reference the same two conversation IDs read by the tool calls and are labeled `reason=explicit_update`. At **03:39:26–28 EDT**, the app attempts to open Microsoft and AWS geolocation CSVs in its sidebar; both record **ERR_FAILED**. A failed sidebar load must not be counted as a successful page read. UI focus flags and the word “explicit” do not identify a person at the keyboard.

### Windows auditing at the recorded check

| Channel | Recorded result |
| --- | --- |
| Security | Access denied; elevation requested |
| DNS Client Operational | Disabled; record count null |
| Sysmon Operational | No matching log found |
| Windows Defender Operational | Enabled, **8,790 records** |

The availability file has no collection timestamp of its own. It records this check's access/configuration results and must not be projected backward onto September 7. The Security exception is not a zero-event result, and the Defender count is not a detection count.

### Later September 19 diagnostic-log uploads

The transfer-verification file contains **33 distinct completion pointers**, dated **06:24:52.754–23:09:40.320 EDT**: **28 Success and five Failure**. All 33 name `access-events.jsonl`, across three OneDrive file IDs and two recorded relative Desktop paths. Fourteen, nine and five successes attach to those three IDs; the failures split four and one across the first two IDs.

Each row's result and file ID match its embedded decoded completion parameters, and its local time converts exactly to the embedded UTC timestamp. All 28 successes have true file/request/response join flags. These checks reproduce the supplied records and nested completion fields; they do not newly rerun the binary parser on the two referenced later source ledgers. Byte counts remain marked **not decoded**. This later series is separate from the earlier 292-completion series in section 17 and the September 20 research-export uploads.

### Research-audit artifacts and evidence accounting

* The corpus check contains **164 rows**, all recording equal expected/actual hashes and `match=true`. This repeats the earlier local-integrity result; the original 164 normalized text files are not all supplied for a new full hash pass.
* The response-code summary retains **323 observed primary responses**, with **102 coded composite failures (31.58%)**. Every listed category distribution sums to 323. The semantic coding is not independently redone in this pass, and this denominator remains separate from the 8,762-reply status-language census.
* The mathematical JSON describes an arithmetic check, reporting zero mismatches over its stated state range and explicitly marking `causal_effect_tested=false` and `source_program_executed=false`. It is not a platform experiment or proof of a causal network pattern.
* The human-claim matrix contains **54 distinct claim IDs** with source, scope and proposed decisive-record fields. Its political/legal/current-event claims are retained as dated research statements, not newly verified by this attachment review.
* The evidence-hash list inventories **38 distinct paths**: 32 OneDrive logs, three app logs, two browser-history copies and one parser script. The listed sizes sum to **27,632,641 bytes**. A hash inventory alone does not supply or revalidate every listed file's bytes.

The user's acknowledged CC0 publication remains classified as authorized activity. This batch does not change that clarification or merge these September 19 diagnostic operations with the September 7 document-state evidence.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-75-Windows-audit-availability.json` | 666 | `26315eb22dbb2aab94736a2d8864e445f91741fabbc741dd701204d823f47997` |
| `02-76-Codex-access-evidence.json` | 371,205 | `33cad387b739bbfbd3c9d1f53cdd588f461487a042d12f824b2f8efcef531228` |
| `03-77-Codex-app-evidence.json` | 16,658 | `5c53c8c8cb79542dd309397ef7dde483e7a530f318c82431d1cb03ab65ee4e78` |
| `04-78-Corpus-integrity-check.json` | 69,995 | `cca147da4f58702cd9fcdad153b8959b27707a9f7a833c755ba291228508b9f7` |
| `05-79-count-recomputation.json` | 1,841 | `2a0924ed11ccd52bb9d6b421475f8e734ee4063d49697652449ca22186a81123` |
| `06-83-Evidence-file-hashes.json` | 11,344 | `66efb8e57d35e2112ec69b15df256028cc808d317bd476198a54cde491cc1a57` |
| `07-85-Human-claim-matrix.json` | 54,449 | `3089a255da55875aa2ce33f1374e19f551e1b1245916041638f2ae3481515ead` |
| `08-87-Mathematical-checks.json` | 665 | `f2b66448728e01dd7316afe75705fff76fc1513d037c0d8a603e045604348cd4` |
| `09-71-SHA256-manifest.json` | 8,972 | `b3eb295ad43f5db2106495a1f207ef5b2e6a046a3ea0a6e1e836b6cbbdcd8f7f` |
| `10-72-Transfer-verification.json` | 58,539 | `0a8f79c73f88f7b67d58c72fe5ebd91f9fedca25807e619e37dcdabdc4eb50f0` |

## 25. Monitor source reconciliation, browser overlap and conversation-context correction

All ten attachments match their named entries in Evidence Ledger v12. This batch supplies the actual rows behind several earlier summaries. Counts below identify overlapping extracts explicitly so that the same observation or upload is counted once. Attached source files were not modified, and no embedded source program was executed.

### September 19: two monitor sources and their exact excerpts

Both entries in `88-Monitor-source-hashes.json` match full copies already available in the workspace:

| Source | Bytes at collection | SHA-256 | Collection time, UTC |
| --- | --- | --- | --- |
| Call Probe `events.jsonl` | 624,030 | `d3d8b5e5ceacb5ea4846e2c35264d0058ea776c5bb2dd37b921fd193d53c84c7` | Sep 19 08:03:24.940031 |
| Access Monitor `access-events.jsonl` | 1,512,585 | `1ad52062ab03d2c451075b31787f91766dbca8e092ae5c73ad8422268de633f0` | Sep 19 08:03:24.950540 |

The 925 records in `89-Monitor-window-records.jsonl` match the corresponding source records exactly, including all fields and the supplied one-based source-line locators:

| Monitor | Source lines | Rows | Observation range, Sep 19 EDT |
| --- | --- | --- | --- |
| Call Probe | 854–1273 | 420 | 02:45:00.7410799–03:43:39.9686793 |
| Access Monitor | 2218–2722 | 505 | 02:45:00.733–03:43:49.282 |

Call Probe contributes **305 first observations, 33 state changes, 59 heartbeats, 15 fanout records and eight burst records**. Access Monitor contributes **446 connection/identification records and 59 status records**. Fanout and burst are that collector's record categories; they are not independently established causes or additional file transfers. These two excerpts are not 925 separate connections.

The collection hashes identify the file versions read at 04:03 EDT. They do not identify the bytes of every earlier version synchronized while the files were growing.

### OneDrive: personal-file synchronization and a separate diagnostic-log batch

`91-OneDrive-evidence.jsonl` has **1,279 distinct source rows**. Of these, **1,278 match the earlier 114,024-row decoded ledger exactly after removing the added local-time field**. The remaining row, `.429.odl` record **3182**, has the same destination, object path and other parameters; its twelve signed-URL query values have each been replaced with `[REDACTED]`. The sole difference is that query-value redaction. All local-time values convert to the corresponding UTC timestamps.

The personal-file series contains **292 starts, 292 current-upload rows, 292 HTTP-response rows and 292 successful file-completion rows**. Its completion split is the existing **290 Call Probe / two Access Monitor** result. These are the same source locators counted in section 17. Recomputing the heartbeat comparison from this smaller excerpt again gives **54 of 59** matches within two seconds, with delays **0.5642883–0.6461459 seconds**, median **0.5763197 seconds**.

The remaining **111 rows concern OneDrive's own diagnostic-log uploader**. In `SyncEngine-2026-09-19.0731.41584.429.odl`, the relevant sequence is:

| Time, Sep 19 EDT | File_Index | Diagnostic-uploader record |
| --- | --- | --- |
| 03:32:39.036–03:32:39.977 | 3082–3125, selected rows | Nine compression records naming SyncEngine logs |
| 03:32:40.103–03:32:40.104 | 3136–3158 | Queues **23 distinct SyncEngine `.odlgz` files** |
| 03:32:40.104 | 3160, 3162 | Two `ExecuteLogUploadBatch` records |
| 03:32:40.248 | 3171 | Response from `storage.live.com`, path `clientlogs/uploadlocation` |
| 03:32:41.068 | 3182 | Response from `onedriveclucproddm20027.blob.core.windows.net` at the batch object path |
| 03:32:41.078 | 3185 | `FinalizeSuccessfulBatch` |

This establishes a recorded successful diagnostic-log batch in addition to the personal-file synchronization. The 23 queued filenames identify OneDrive SyncEngine diagnostic logs. The excerpt provides a batch-success record, not 23 separately decoded payloads or individual success receipts. The two execute records are not counted as two successfully completed batches. The actual uploaded archive bytes and exact content of that archive are not present in these selected rows.

### September 17: original network rows now verify the summaries

The full **262-row S002 snapshot** independently reproduces section 23's summary: **74 startup observations, 129 first observations, 42 relabels and 17 monitor/coverage records**. The 203 startup/first observations have 203 distinct process/PID/local/remote tuples. Every relabel matches a tuple already observed. Process and destination counts also match the earlier summary exactly.

The separate afternoon history excerpt has **106 rows**, source lines **1038–1143**, spanning **14:08:02.762–14:35:09.906 EDT**. It comprises **75 first-observed rows, four identification updates and 27 status messages**. All 27 status messages explicitly report unavailable login-log access.

Its source lines **1094, 1095 and 1096** match the three process/PID/destination/time entries in the earlier screenshot-alignment JSON. Relative to that JSON's recorded capture time, the calculated delays are again **8.688, 9.689 and 10.685 seconds**. This now verifies the network-side row references as well as the arithmetic. It does not resolve the previously documented difference between the referenced original image and the uploaded image copy, or establish a shared request between the phone screenshot and Windows connections.

### September 19 browser-history overlap

`94-Browser-history-window.json` contains **27 Chrome rows and 14 Edge rows**, each with URL, title, timestamp and a browser-local visit ID. The Chrome selection spans **03:21:19.668–03:41:52.614 EDT**; Edge spans **03:23:19.844–03:34:11.259 EDT**. Both download arrays are empty in this selected export.

Two document IDs are named:

| Document ID | Recorded title | Chrome rows | Edge rows |
| --- | --- | --- | --- |
| `1Uefc3nP-BjsoRORAqxvfQnx3RN6BO6ztyjeGK62j4f8` | Network IP/geolocation audit | 7   | 2   |
| `1nYwNsoj7bVZFoBD4cLURbHTARLUl5TwoHAiNYvNjqdg` | IP audit: 02:56–03:20 continuation | 1   | 1   |

Other rows concern Docs home/create pages, Grok, and four Edge navigation rows for a File Explorer help search/redirect. These are timestamped navigation records to investigation material on September 19.

**Ten URL–timestamp pairs occur identically in both browser selections**, leaving **31 distinct URL–timestamp pairs across the 41 rows**. The export therefore must not be presented as 41 independent navigations or proof that two browsers separately performed every shared action. The cause of this shared history is not specified in the supplied rows. The two source database copies are named and hashed in the earlier evidence-file inventory, but this pass analyzes the supplied JSON rather than re-querying those SQLite files. These September 19 document IDs and navigation events remain separate from September 7's seven-document revision evidence.

### Conversation audit: source identity holds; one rationale fails the context check

`95-Agency-context-review.json` selects **18 cases**, containing **102 embedded raw-node records**. Every one of those 102 records matches the full `02-nodes.json` export exactly, including its text and metadata. The file labels **11 selected cases `coded_denial=YES` and seven `NO`**. Those are source coding labels; byte identity does not by itself validate their interpretation.

One specific rationale needs correction. In `seventh_share:n1295`, the coded response combines assistant nodes **1296, 1304, 1309 and 1311**. Two user messages intervene, at nodes **1303 and 1310**. The relevant source order is:

| Node | Speaker | Relevant content |
| --- | --- | --- |
| 1295 | User | Asks why the microphone is not working |
| 1296 | Assistant | “One moment.” |
| 1303 | User | Attributes interference with the inputs to people |
| 1304 | Assistant | “Checking.” |
| 1309 | Assistant | “I wouldn't pin that on anyone without clear evidence.” |
| 1310 | User | “Thanks” |
| 1311 | Assistant | Continues with “input glitch, unknown cause” and a local microphone check |

The review calls the person-reference an unnecessary introduction by the assistant. That rationale omits the intervening user attribution. **The denial at node 1309 responds to a person-attribution already present at node 1303; it should not count as an unsolicited introduction of that attribution against the original microphone question.** This finding concerns the order and interpretation of the conversation, not whether the user's proposed cause was true.

The source's eleven positive labels are therefore preserved as its reported count, with this one explicitly excluded from a validated count of unsolicited introductions. This pass does not certify the remaining ten labels or silently recalculate the broader 143-opportunity agency sample or the separate 323-response composite-failure metric. A complete recoding would need their full category definitions and response boundaries. The earlier independently verified status-language census is unaffected. The subsequently supplied September 20 Verification.md and claim H51 already acknowledge the intervening-turn error; section 26 records that earlier acknowledgment. This source check reproduces that correction rather than discovering it for the first time.

### Recovered-material indexes and repeated transfer note

The two recovered-material indexes are **byte-identical**, not two separate recovery sets. Their numbered links reproduce the stated **134 Markdown entries**:

| Group | Entries |
| --- | --- |
| Research and audits | 58  |
| Forgejo wiki | 16  |
| Recovered Drive | 11  |
| Transcriptions | 29  |
| Open WebUI uploads | 13  |
| Saved chats | 7   |

The indexes also describe original files, embedded images, 59 audio files and two Git-history bundles. These are inventory statements; this attachment batch does not contain all those linked bytes for a new content/hash check.

`10-onedrive-transfer-check.md` is byte-identical to three earlier copies already in the workspace. Its fifteen September 20 completion rows remain the findings independently reproduced from binary logs in section 15. Reattaching the note adds no further transfers.

The user-confirmed CC0 republication remains authorized activity. None of the duplicate-control or context corrections changes that clarification.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-88-Monitor-source-hashes.json` | 851 | `66ff5f649db896a871cd846754b657da26477fa85b35f43354b5c3f9ea8dfa05` |
| `02-94-Browser-history-window.json` | 12,078 | `a6c788f9bf0cfa59daafea189935639fbbf41247c0cc5d025590f88760ca5e85` |
| `03-95-Agency-context-review.json` | 175,781 | `0b9afcbb3b365244da9afa967de391fb9df7f196d5fb422d477699dcc0a9d2a7` |
| `04-23-S002-access-events.snapshot.jsonl` | 148,099 | `2b237e273d6939974c3d5e25f0421b0ee63423aad1045c25ead572f26e270438` |
| `05-32-local-history-window.jsonl` | 56,013 | `224af2f1ecf04ac746584b76b05bc4d5f872908cd543a8e8b334dc1de3396582` |
| `06-89-Monitor-window-records.jsonl` | 560,764 | `e3fc33b06b996ece02ca37dee362a35bc4a168160d9925615b341008e25447dd` |
| `07-91-OneDrive-evidence.jsonl` | 565,016 | `b2d141abbc0f4f9b40d8ffd9301f0ece1a3ea0eaf97b6b4843a964e429361ced` |
| `08-03-recovered-material-index-a.md` | 14,764 | `c893346f4f020af8425208cc0e3f5c3fda3a653bec38af253853db7dd8b72409` |
| `09-04-recovered-material-index-b.md` | 14,764 | `c893346f4f020af8425208cc0e3f5c3fda3a653bec38af253853db7dd8b72409` |
| `10-10-onedrive-transfer-check.md` | 5,088 | `7f8c13b0c1575b996f5f25436d202eb1aea90c0b9c9b9d9dbcc7cb4a30410e52` |

## 26. Court-source review, external-query correction and report reconciliation

All ten attachments match their named entries in Evidence Ledger v12. The court PDFs were text-extracted and rendered for inspection; the one-page Teams exhibit requires visual reading because its text layer contains only the docket stamp and exhibit identifier. No program or collection instruction embedded in an attachment was executed. The existing source files were left unchanged.

### Public-data custody: the supplied court records now support specific routes

These three uploaded copies bear the case number **3:25-cv-05536-VC**, Northern District of California, California et al. v. U.S. Department of Health and Human Services et al. The review below attributes statements to their declarants, quoted responses or chat speakers. It is a review of the supplied copies, not a new authentication against the live court docket or an account of the case's present outcome.

| Supplied document | Docket stamp | Pages | Directly relevant passages |
| --- | --- | --- | --- |
| Anna Rich declaration | Document 182-1, filed July 16, 2026 | 3   | Paragraphs 3–6: discovery provenance, a quoted July 2 interrogatory response, and July correspondence about deletion evidence |
| DHS_PI0002 / Exhibit A | Document 182-2, filed July 16, 2026 | 1   | February 24, 2026 Teams messages about HHS/CMS copies, retention and deletion scope |
| Alberto V. Briseno declaration | Document 155-4, filed April 9, 2026 | 3   | Paragraphs 6–16: requests, receipt, Databricks ingestion, restrictions and deletion assertions |

**HHS/CMS → ICE/HSI → Databricks.** Briseno identifies himself as an HSI section chief overseeing the Innovation Lab. His declaration states that ICE supplied an approximately **7.6 million-subject open EARM case list** to HHS/CMS on December 10, 2025, and received non-plaintiff-state data on December 14. The 7.6 million figure describes the matching list sent by ICE; it is not a stated count of Medicaid records returned. The January 6, 2026 request reused that list, and ICE received matches on January 7 (PDF page 2, paragraphs 6–10).

Briseno states that ICE loaded the HHS data into **Databricks** and began normalization. He describes access as restricted to data-engineering personnel and unavailable to agents or officers conducting operations (PDF pages 2–3, paragraphs 11–12). He says ICE restricted and quarantined the data around February 20, agreed not to use it pending resolution, and had not ingested it into officers' or agents' operational systems or used it for law-enforcement operations (page 3, paragraphs 13–14). Those are his stated access and use boundaries.

**HSI → ELITE Team and Palantir through Microsoft Teams.** Rich's paragraph 4 quotes defendants' July 2 response to Interrogatory 9: the January 7 data were shared by HSI with the ELITE Team and Palantir through a Teams chat and subsequently deleted from that chat. This supplies a named dissemination route in a quoted discovery response. In paragraph 3, Rich identifies DHS_PI0002 as a true and correct copy of a document produced in confirmatory discovery received June 5; the supplied Exhibit A is that separately stamped page.

These passages give claim **H19** specific document, page and paragraph support. They establish what the supplied records say about custody, ingestion and dissemination; they do not identify a file from the user's computer or one of the seven September 7 Google documents.

### Copy-management and deletion chronology

The February 24 Teams screenshot contains redacted participant names. The following times are displayed chat times; the exhibit does not state their time zone. Statements remain attributed to unidentified chat participants rather than assigning a name from surrounding interface labels.

| Displayed time, February 24 | Substance visible in DHS_PI0002 |
| --- | --- |
| 10:04 | Requests deletion of various HHS/CMS copies in chats because of pending litigation and the need to reduce copy counts |
| 10:05–10:06 | Recipients seek a management directive and specific links; a message describes removing duplicates while retaining one or two master copies |
| 10:13 | Suggests deleting chat/computer copies, allowing a documented single-copy holder at Palantir and referring to an HSI-held copy; asks who holds what |
| 10:17 | Recipient calls the instruction too vague and asks for specific links |
| 10:23 | Clarifies deletion of HHS data in chats, with one copy held by one person on the ERO side; also instructs removal from ERO/Palantir computers and relevant Palantir/ERO chats |
| 10:28 | Acknowledges the discussion and looks for follow-up |

The exhibit therefore preserves actual deletion instructions, questions about their scope and changes to the stated retained-copy arrangement. It does not itself record successful execution of each deletion.

The declarations then provide the following dated sequence:

| Date | Source and statement |
| --- | --- |
| March 30, 2026 | Briseno says ICE confirmed deletion of the January 7 received file and data loaded into Databricks; he states no other sources or derived versions were retained within ICE holdings and no prior sharing with an ICE enforcement database (April 9 declaration, paragraph 16) |
| July 2, 2026 | Defendants' interrogatory response, quoted by Rich, states the HSI/ELITE/Palantir Teams sharing and subsequent chat deletion (Rich paragraph 4) |
| July 10, 2026 | Rich says defense counsel supplied a PDF purporting to show file deletion; she requested a declaration explaining authenticity, significance and redactions (paragraphs 5–6) |
| July 15, 2026 | Counsel's response, quoted in Rich's declaration, says no such declaration was then planned and describes the supplied documents as corroborating deletion of recently found residual copies from earlier transfers and copies of a file inadvertently transferred by HHS (paragraph 6, PDF pages 2–3) |

The April declaration's deletion assurance and the July correspondence about residual copies belong in the same chronology, with their different systems, transfers and dates preserved. The supplied material does not independently inventory every copy at either date. Rich's referenced **Exhibits B and C are not included in this attachment batch**; their contents are represented here only by her descriptions and quotations.

This directly supports **H20's record of deletion requests and assurances**. **H21's specific enforcement-consequence question remains separate:** Briseno expressly declares non-use for operations, and these three files provide no individual dataset-row → query → enforcement-action record. They supply an institutional custody/deletion record without establishing the proposed connection to the user's local incident.

### External lookup accounting: 74 distinct public IP query values

`82-Evidence-comparison-2026-09-19.md` corrects the earlier 36-address-only account. This correction is reproducible from the saved session records already available in `05-session_records.json`. Both request bodies and returned result arrays were checked:

| Batch | Saved call ID | Request / result source lines | Request → tool-return time, September 19 UTC | Distinct IP values |
| --- | --- | --- | --- | --- |
| First IPinfo batch, also issuing Google PTR lookups | `call_N0Dn7Y92z5LWniis0anKbu7U` | 75 / 79 | 06:57:44.571 → 06:57:54.066 | 36  |
| Second IPinfo batch | `call_GN83sEZbpj3BzuhyVPffVSAM` | 93 / 98 | 06:58:31.249 → 06:58:42.441 | 38  |

The returned arrays contain **36 and 38 rows**, respectively, with no reported lookup errors. Their IP sets do not overlap: **74 distinct public remote addresses were submitted across these two IPinfo batches**. The first script also sent reverse-DNS queries for its 36 addresses to Google public DNS. These are concrete disclosures of selected network metadata during the investigation.

The comparison report's saved-result completion times differ slightly from the enclosing tool-return times above; the two timestamp types should not be substituted for each other. Later single-address work is additional activity, and counts across different providers overlap. The earlier selected-operation table in section 24 was not a complete inventory of every lookup.

The recorded requests describe address and reverse-DNS lookups, not transmission of the full monitor files as lookup payloads. The previously checked **3,174,310 bytes across five saved provider responses** remain downloaded response-file lengths, not uploaded user-file bytes or measured network-layer traffic.

### Findings and claim-register reconciliation

| Supplied report | Check against earlier underlying records | Result |
| --- | --- | --- |
| `90-Mysonted-findings.md` | Recount of the structured parsed observations already supplied | **1,413 parsed rows; 856 distinct process/PID/local/remote tuples; 246 additional tuples** relative to the earlier overlapping paste |
| Same report, later window | Recount after 04:11:16 | **222 distinct tuples**, of which **202** belong to codex PID 56004; these remain connection observations, without payload sizes or document identifiers |
| `67-Recovered-revisions.md` | Eight report rows compared with `69-Revision-evidence.json`, including revision IDs, local timestamps and normalized text counts | **All eight rows match; 74,609 earlier-text characters**. This repeats the seven September 7 documents plus the separate September 8 document; it adds no ninth document |
| `86-Human-claim-matrix.md` | Ordered H01–H54 IDs and the four disposition fields compared with `85-Human-claim-matrix.json` | **54 matching IDs and 216 matching disposition fields** |
| `74-Verification.md` and H51 | Check for prior acknowledgment of the conversation outcome-window defect | Both already identify the intervening-user-turn problem; section 25 independently reproduces that earlier correction |
| `80-Data-access-review-2026-09-19.md` and `82-Evidence-comparison-2026-09-19.md` | Comparison with the previously checked file reads, lookup records and OneDrive rows | The **292 personal-file upload completions**, four later read/send pairs and separate diagnostic-log activity remain the same operations previously counted |

For the Mysonted late-window subset, the 202 codex PID 56004 tuples split into 201 to `172.64.155.209:443` and one to `104.18.32.47:443`. The damaged terminal 04:15:35 line stays excluded; its address is not silently repaired. The new structured recount is a verification of the supplied parsed dataset, not a fresh parse of the original raw paste in this batch.

For revisions, **D7 stays 8→18**, with intermediate revisions 9–17 not supplied. The earlier-text total remains **55,571 characters for the seven September 7 documents plus 19,038 for the September 8 document**. Repeated reports of that same recovery are not independent recovery events.

The 54-claim comparison validates consistency between the Markdown and JSON versions of the register. It does not independently validate every public-source claim in that register. The three court attachments above supply new direct source checking for specified parts of H19/H20; the other rows retain their stated verification scope.

### One remaining provider-range association resolved

Section 22 correctly recorded **24 of 25 destination addresses** covered by successful ranges in the supplied registry-result files. The follow-up report identifies an additional primary source for the remaining address: [New Relic's network documentation](https://docs.newrelic.com/docs/new-relic-solutions/get-started/networks/), section **Data ingest IP blocks**, lists **162.247.240.0/22**. The official page was checked on **September 28, 2026**; range arithmetic confirms that both **162.247.241.14** and **162.247.243.29** fall within it.

The combined range-association coverage is therefore **25 of 25 when this separately dated provider document is included**. The saved historical registry files still independently cover 24 of 25. The additional source associates the address with a documented New Relic ingest block; it does not reveal the contents of a particular connection or retroactively turn a failed historical registry request into a successful one.

The user-confirmed September 19 CC0 republication remains recorded as authorized activity. This batch adds sources and corrects accounting without changing that attribution.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-90-Mysonted-findings.md` | 5,601 | `3d296baf428094f9c9120988e25ed9f19f836e383725e628eb50096dd9b67ffb` |
| `02-18-ca-v-hhs-anna-rich-declaration.pdf` | 141,155 | `84c9f88da00a51d9483b3a9c7843b0737bf0925fb516fdc8c4863907e19db487` |
| `03-19-ca-v-hhs-dhs-pi0002-exhibit.pdf` | 193,016 | `f8be74920963d85b6851f583932d502ad6f2c853f92dbca8ac56c127548d5d6a` |
| `04-20-ca-v-hhs-alberto-briseno-declaration.pdf` | 262,752 | `80dee6910a3bc9108d49405da6f1fca14c2071f59f2c4e98044e058131ae7086` |
| `05-46-Network_Log_Followup_2026-09-17.md` | 21,677 | `3587cbe5d4842fe6490d9deec336a39c34f4b298c922728193913442e698f477` |
| `06-67-Recovered-revisions.md` | 5,462 | `c3106918d6bc85a04563e2fd1e94113e8800c127a7db537146992e19fdfb6fb4` |
| `07-74-Verification.md` | 6,909 | `cf09c5fdf7997766dc06c27d8a26f0ca9b1cc3c923abffe40258f5344dcf1f75` |
| `08-80-Data-access-review-2026-09-19.md` | 15,482 | `206f3098d39698a929f06b2286f4b54e6b5f69db3173e489e32d2a239e39d0ae` |
| `09-82-Evidence-comparison-2026-09-19.md` | 8,266 | `667181a9e1810d4094bc4c30700eb76c2983c0d6900ac65f32422e1a36b816e7` |
| `10-86-Human-claim-matrix.md` | 37,797 | `5f988f0dffdcebb2bee2d055e20824dfa268531de20c95098a59f234000f6d55` |

## 27. Blank document inspection and runtime record reconciliation

All nine attachments match their corresponding entries in Evidence Ledger v12. This pass reads the uploaded files, reconciles them with earlier workspace records, and inspects the Python caches without importing or executing their code. Original attachment bytes remain unchanged.

### Politics DOCX is substantively blank

The supplied `62-Politics-current-blank.docx` is **7,683 bytes**, SHA-256 **`89e0bd4a40eb0f5688b73db9532aedb581787c7408957a4880dbe025765c97b6`**. Its twelve ZIP parts contain a valid Word document with **one paragraph and one empty run**. The document body contains:

* **Zero text elements and zero tracked-deletion text elements.**
* **Zero inserted/deleted revision elements, tables, drawings, pictures or embedded objects.**
* No media files, embedded-document files or external relationship targets in the package.

The package retains styles, settings, a theme and Google custom XML metadata. It is therefore a structured document file with no substantive body content, rather than a zero-byte file. Its custom metadata is not a recovered Politics narrative or an independently verified Google document identity.

The DOCX was converted to PDF and rendered for visual inspection. It produces **one blank page**, with no extracted text, PDF images or vector drawings. This agrees with the internal XML check. The initial rasterizer failed because a required Poppler shared library was unavailable; the successfully converted PDF was rasterized with PyMuPDF and inspected instead.

Section 15 already verifies a OneDrive upload-completion row for the basename `Politics-current-blank.docx` at **September 20, 06:54:56.555 EDT**, with the saved local path, upload/object IDs and source locators. This attachment now permits direct content inspection of the local artifact bearing that name. The historical response does not include a content digest to independently equate the server's uploaded bytes with this DOCX hash. This separate Politics control is not added to the eight recovered revision pairs.

### Docker inspection contains one repeated configuration

`05-open-webui-docker-inspect.txt` contains **ten complete JSON objects that are structurally identical**, plus **four malformed or interrupted candidate objects** and copied interface text. It is not ten independently timed inspections or ten containers. The complete copies begin at source lines **1, 283, 967, 1252, 1534, 1816, 2660, 2944, 3226 and 3508**. Interrupted candidates begin at **565, 910, 2098 and 2379**. They were not repaired and counted as additional observations.

The complete object identifies:

| Field | Saved value |
| --- | --- |
| Container | `/elegant_perlman` |
| Container ID | `91bd2dc60076e011ccd4b041fc3fb2795e0c11254d669c82945c72fda205b88c` |
| Created | `2026-09-20T07:38:29.312854928Z` — 03:38:29.312854928 EDT |
| Started | `2026-09-20T07:38:29.383669436Z` |
| State | Running; health status `healthy`; five saved successful health checks ending at 07:45:30.394851775 UTC |
| Image reference | `ghcr.io/open-webui/open-webui:main` |
| Image ID | `sha256:6a773e5c3a246b65cbe74ce942b294292c0e5f81c138f703d111bc162f7d7c3d` |
| Container user | `0:0` |
| Privileged mode | `false` |
| Mounts / host binds | Both empty |
| Host port bindings | Empty; `NetworkSettings.Ports` lists `8080/tcp: null` |
| Exposed container port | `8080/tcp` |
| Network | `bridge`; container `172.17.0.3`, gateway `172.17.0.1` |
| Restart policy | `no` |

This saved configuration shows no mounted host folder or published host-port mapping for this container. Container port exposure and host-port publication are separate fields. The bridge network remains configured; the port result does not mean there could be no outbound traffic or communication within the Docker network. User `0:0` is the configured container identity and does not identify a Windows account that created or operated it.

The environment sets `SCARF_NO_ANALYTICS=true`, `DO_NOT_TRACK=true` and `ANONYMIZED_TELEMETRY=false`. Those are recorded configuration flags, not a traffic measurement. The `OPENAI_API_KEY` and `WEBUI_SECRET_KEY` environment values are empty in this snapshot; that observation does not inspect credentials or settings potentially stored elsewhere.

The attached consolidated narrative describes empty application tables and three deleted model-cache log paths. Those findings would come from database/filesystem examinations; this Docker configuration dump itself contains neither a database row census nor a Docker filesystem-diff result. Its health field indicates the recorded health-check result, not the presence or absence of historical user content.

### CSV exports reconcile with the earlier records

| Attached CSV | Row-level comparison | Result |
| --- | --- | --- |
| `81-Earlier-IP-lookup-records.csv` | Address order, returned IPs, provider names, error fields and UTC-equivalent request/result times compared with the first saved lookup batch | **36 rows match**. These are the first batch already included in section 26's 74-address total |
| `84-Human-claim-matrix.csv` | All 54 ordered rows and 13 fields compared with `85-Human-claim-matrix.json` | **683 of 702 fields match exactly**. The remaining **19** are empty CSV `legacy_ids` cells corresponding to JSON `null`; no substantive field differences |
| `92-OneDrive-upload-records.csv` | Every completion row joined by source filename/record number to its completion, start and HTTP-response records in `91-OneDrive-evidence.jsonl` | **292 matched completion rows and 876 matched source-record references**, with no path or timestamp differences |

The OneDrive CSV reproduces **290 `events.jsonl` completions and two `access-events.jsonl` completions**, from **September 19, 02:45:01.766 to 03:43:40.976 EDT**. For every row, the file ID, local relative path, result, timestamps, method, destination host and server request identifier agree with the referenced records. All 292 byte fields explicitly say `not decoded / not established`. They supply no basis for assigning the later read/send trace's byte totals to these earlier operations.

The 36-row lookup CSV is an earlier subset, so it does not supersede the separately verified second 38-address batch. Likewise, this CSV copy adds no new OneDrive uploads or claim-register findings. The CSV/JSON difference in empty `legacy_ids` representation is recorded as a format distinction rather than a changed claim.

### Compiled Python files identify the review utility and its tests

Both `.pyc` files have the CPython 3.12 magic value **`cb0d0d0a`** and timestamp-based header flags **0**. Their code objects were decoded and disassembled as data. No cached module or test was imported or executed.

| Cache | Embedded source path suffix | Header source time, UTC | Header source size |
| --- | --- | --- | --- |
| `trace_review.cpython-312.pyc` | `realtime-voice-chat\Trace_Review\trace_review.py` | September 20, 15:52:13 | 30,439 bytes |
| `test_trace_review.cpython-312.pyc` | `realtime-voice-chat\Trace_Review\test_trace_review.py` | September 20, 15:51:19 | 5,426 bytes |

Both embedded paths begin `C:\Users\drewd\Documents\Codex\2026-09-16\`. These header times and sizes describe recorded source-file metadata, not proof of execution at those times. The cache bytes have their own larger lengths, listed in the attachment hash table.

The review module embeds version **1.0.0** and identifies itself as an offline transcript/socket-observation reviewer. The static code structure includes text/JSON input handling, message/event deduplication, timestamp and address parsing, heuristic findings, a network summary, HTML generation, copied-source/hash outputs and manifest verification. Its `run` function names `analysis.json`, `manifest.json`, `report.html` and `SHA256SUMS.txt`; `main` supports command-line files or a Tk file chooser. The inspected imports are standard-library modules and Tkinter. This describes the compiled review utility rather than a recorded collection or upload event.

The test cache contains **nine named test methods** covering overlap and PID reuse, source hashes and HTML escaping, Unicode/referent candidates, unknown roles, changed versions sharing an identity, overlapping turn exports, addresses/time zones, corrupt-line retention and ChatGPT branches. The presence of compiled test code is not a saved test-pass result. The original `.py` source files were not supplied in this batch for a source-to-bytecode comparison.

### Live monitor file combines several collectors and repeated censuses

`01-live-monitor-log.txt` has **6,604 physical lines**, including **6,378 nonblank lines**. It is a pasted combination of multiple formats, with backward time jumps between blocks. **3,533 nonblank line strings are distinct**, but repeated strings must not automatically be classified as duplicate incidents: many are repeated process-census rows.

The record families can be accounted for separately:

| Family | Count and scope |
| --- | --- |
| Fully dated collector | **648 records**, September 23, 17:58:13.269–18:13:19.943; 526 DNS, 31 Defender, 31 monitor, 30 network errors, 30 process errors |
| Access-monitor observations | **135 first-observed tuples and five relabels**, 135 distinct process/PID/local/remote tuples |
| Access-monitor status | **40 messages**, all reporting unavailable login-log access |
| Focused process trees | **111 headings, 2,671 rows, 31 distinct child/parent edges**, plus 110 coverage lines reporting `Security=NO/NOT ELEVATED` |
| Uppercase `[PROCESS]` rows | **Eight** printed process observations |
| TCP censuses | **567 rows**, containing 119 distinct process/PID/local/remote keys across repeated snapshots |
| Process/path censuses | **1,875 rows in six snapshots**, with 321 distinct process/PID/path tuples |
| Later DNS/Defender output | **88 DNS and 120 Defender rows** |

All 60 errors in the dated collector name the unavailable **`Get-ProcessTag`** helper: **30 failed network snapshots and 30 failed process snapshots**. DNS and Defender output continue in that same block. The other collector families still print TCP/process observations. Their presence does not retroactively repair the failed collector, and the failed collector does not imply all monitoring stopped.

The six process/path snapshots are timestamped **18:12:34, 18:13:05, 18:13:36, 18:14:07, 18:14:38 and 18:15:09**, with **313, 312, 310, 312, 314 and 314 rows**, respectively. These are repeated running-process lists, not 1,875 new process creations. The TCP rows include **148 Established, 132 Listen, 185 Bound, 83 TimeWait, 18 CloseWait and one SynSent** observations. The total 567 must not be reported as 567 separate established remote connections.

Only the fully dated block independently supplies September 23 in every timestamp. The time-only blocks are retained in their supplied context rather than assigned a date from a PID match alone.

### Process identities visible in this monitor attachment

The focused trees record **Explorer 3856 → ChatGPT 41804 → codex 46112 and computer-use helper 46216**. The process/path census identifies the ChatGPT executables under **`OpenAI.Codex_26.917.8451.0`** and codex 46112 under **`OpenAI\Codex\bin\80f78947ad880e6e`**. This is the same recorded package/bin generation seen in other material, with a separate main PID. It is not automatically the same running instance as main PID 59860 or the later 52604 generation.

The same trees place **SystemSettings 24488 under svchost 2316**, and **codex-windows-sandbox-service 41020 under services 2068**. No Chromium role command line is printed here, so this attachment alone does not classify ChatGPT PID 49832 as a NetworkService process solely from its sockets.

The process/path lists also identify **ten distinct `mscopilot` PIDs** under `C:\Program Files (x86)\Microsoft\Copilot\Application\mscopilot.exe`. PID **17188** appears in network observations. This directly records the local Microsoft Copilot executable and its connections. It supplies no GitHub token ID, GitHub App authorization record or repository-write request that would join it to the separately recorded **Copilot Chat App** token event.

The Defender text contains a repeated **5007 configuration-change message** whose shown old/new values are for `CoreService\WdConfigHash`. Other output includes health reports and security-intelligence updates. The displayed wrapper time is not a preserved original Windows event `TimeCreated`/RecordId, and repeated message output is not counted as separate newly occurring configuration changes. The generic message text mentioning possible malware is not a malware-detection result.

### Consolidated narrative remains a synthesis of its cited sources

`02-consolidated-forensic-findings.txt` is a 185-line narrative with repeated rendered reference labels such as `Recovered-revisions.mdMD`. It supplies no additional raw revision, Jump List after-image, database, packet or upload record. Its eight-document/74,609-character and named OneDrive-upload summaries agree with the source checks above and earlier sections.

Two existing qualifications remain explicit. The **245.622-second interval describes the seven later empty-state timestamps**; for D7, the earlier supplied revision is 8 and the later supplied revision is 18, so it is not an exact timestamp for the content-removal operation or evidence that revisions 9–17 were empty. Also, the narrative's controlled Jump List claim does not supply the missing **80,396-byte after-test binary** noted in section 4. The preserved baseline hash and the narrative account should retain their different verification statuses.

The Docker configuration inspected here supports the named container identity and settings; the consolidated narrative's database and filesystem findings remain findings attributed to those separate examinations. No repeated summary, CSV representation or compiled test file is counted as another independent incident.

The user-confirmed September 19 CC0 republication remains authorized activity.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-02-consolidated-forensic-findings.txt` | 17,934 | `b831e0a1894ac0df7ab2e8bc11a5f7e0b543254b997fd6850d930a664e6bd2a2` |
| `02-05-open-webui-docker-inspect.txt` | 105,529 | `f7d7dda21c8c62ecbacf6a26234f25592b7f2da24155c17d7815c49b626be761` |
| `03-81-Earlier-IP-lookup-records.csv` | 4,680 | `ed64669f54f22654680cd6481db6136305e8bff02bdd64258b43f1d0c2fa3533` |
| `04-84-Human-claim-matrix.csv` | 39,304 | `30940aa409519caaa138b2cf51b81dc89a2eb129e8f995778f58f8ba2bb68a4c` |
| `05-92-OneDrive-upload-records.csv` | 154,396 | `bc79ae02868cd48cc274f8c2d934f1f3c02e4d8f917625a8d26f546f062a9d4c` |
| `06-62-Politics-current-blank.docx` | 7,683 | `89e0bd4a40eb0f5688b73db9532aedb581787c7408957a4880dbe025765c97b6` |
| `07-24-trace_review.cpython-312.pyc` | 48,148 | `e3afb95491d8efee275039fd28cfb790b730556437577425c3b6baadf8acbc86` |
| `08-25-test_trace_review.cpython-312.pyc` | 12,366 | `895a5d65d089eba1caea15c594c96cead5ec6f9ef67f04fe89c6a4eadbc938a6` |
| `09-01-live-monitor-log.txt` | 655,915 | `2ed8dd780964aedf3138f3bffecfc924149fa823cad348917afe5d5f53e4060c` |

## 28. Controlled-test account, monitor-source separation and September 17 snapshots

This batch contains nine files: two findings narratives, a PowerShell monitor source saved as text, a pasted console excerpt, DNS and IPv4/IPv6 snapshots, and two collection-time markers. **All nine SHA-256 values match their corresponding `sources/` entries in the supplied evidence manifest.** Those matches establish consistency with the packet manifest; the underlying observations and interpretations are assessed separately below. The attached PowerShell was read as text and was not executed.

### Controlled Jump List test: the recorded result and its verification status

`06-jump-list-controlled-test.txt` records a September 22 comparison using three uniquely named `.py` files. The account supplies a specific intervention and artifact result:

> “A controlled Windows Explorer ‘Open with → ChatGPT’ operation caused `4183059cb0582.automaticDestinations-ms` to change and caused the uniquely named test `.py` file to be written into that exact Jump List container.”

The following are the **reported controlled-test observations**:

| Route | Unique test filename | Result in target `4183059cb0582...` |
| --- | --- | --- |
| Notepad | `JL_OWNER_NOTEPAD_20260922.py` | Target size/hash unchanged; test name absent. Two other containers changed and contained the test name |
| Chrome | `JL_OWNER_CHROME_20260922.py` | Target timestamp, size and hash unchanged; test name absent |
| Explorer **Open with → ChatGPT** | `JL_OWNER_CHATGPT_20260922.py` | At **21:14:53**, target grew from **78,336 to 80,396 bytes**, and the test name was reported present in ASCII and UTF-16 |

The size difference is **2,060 bytes**. The account records these hashes:

| State | SHA-256 |
| --- | --- |
| Before test | `12124ba656cbdc83e61ec64b4427213c0c0c11768843cc5866e68d27cf1fa668` |
| After ChatGPT test | `2c167bec03911d7d7281c6a2468ba0ca62e27407982d152695a1a21d5cd2bc0e` |

It identifies the preserved after-test copy as `C:\Users\drewd\Desktop\4183059_POST_CHATGPT_TEST_20260922_211453.automaticDestinations-ms`, with the same after-test hash and size. This is a concrete record of a claimed successful reproduction, with an exact test name and an after-image identifier. Section 4 independently verified the supplied **78,336-byte baseline**. The **80,396-byte after-image itself has not been supplied**; this batch provides its narrative description and hash. Consequently, the after-image filename search and binary change remain reported test results rather than a fresh binary verification in this review.

The recorded reproduction supports a **ChatGPT Open With route association** with this container. It does not identify the initiating process or person behind the earlier **16:44–16:46** cluster. Failure to reproduce the change through the tested Notepad and Chrome routes applies to those tests, rather than excluding every possible way those applications could interact with shell history.

### Attribution narrative preserves earlier hypotheses alongside later revisions

`07-monitor-attribution-reconciliation.txt` contains **45 physical lines, 36 nonblank lines and 19 distinct nonblank lines** after trimming surrounding whitespace. Seventeen nonblank statements/headings occur twice. These repeated passages are copies within one evolving account, rather than independent observations.

Its progression is material:

| Issue | Earlier passage | Later passage |
| --- | --- | --- |
| Failed `Get-ProcessTag` logger | **5912** described as a strong historical candidate, explicitly without a contemporaneous process-to-log binding | **21832** assigned as the stronger candidate from a reported approximately 30.23-second CPU cadence and elimination; **5912** assigned to the successful full snapshotter |
| Other monitor roles | **26108** assigned to the rapid process-tree watcher; Python **41564** runs `access_monitor.py` and spawns transient PowerShell helpers | Same architectural separation retained; the account describes four separate monitoring loops |
| Jump List association | Earlier wording says no affirmative application attribution | Final paragraphs incorporate the positive controlled ChatGPT Open With result |

The final paragraph should not be combined with the earlier PID hypothesis as if both were established measurements. The supplied narrative points to PSReadLine history, CPU samples and process-tree captures using flattened reference labels such as `Pasted text.txtTXT`. This file is a synthesis, not the raw CPU-interval or historical process-to-log dataset. In particular, **21832 is the narrative's revised attribution**, not a PID independently proven by this batch to have emitted every failed historical cycle.

The narrative proposes that a `($Path ?? "")` helper definition failed in Windows PowerShell 5.1, leaving later functions able to call a missing helper. That is its proposed implementation explanation. The original helper definition, interactive loading sequence and shell-version output are not contained in the newly attached monitor source. The raw mixed-monitor log reviewed in section 27 does independently show the repeated missing-helper errors and continuing DNS/Defender output.

### The attached PowerShell source is a distinct, console-only TCP monitor

`08-live-network-monitor-source.ps1.txt` contains **72 lines**. Its code identifies exactly what this particular collector can produce:

| Source behavior | Consequence for interpreting its output |
| --- | --- |
| Calls `Get-NetTCPConnection`, then `Get-Process` for newly seen keys | Associates sampled socket-table rows with a process name when lookup succeeds |
| Prints with `Write-Host`; no file-write command appears | This script itself writes console output, not the Access Monitor JSONL. A separate console transcript or wrapper could preserve it |
| Sleeps **750 milliseconds after each loop** | The configured delay is 750 ms; elapsed query and processing time also contribute to cadence |
| Deduplicates on PID plus local/remote addresses and ports in `$seen` | State changes do not generate another line for the same key. Keys remain stored until restart; the key omits process creation time |
| Stores the key before resolving the process name | A first lookup failure prints `PID-<number>` and this code provides no subsequent name-update path for that same key |
| Excludes `Listen` and `Bound`, and requires a positive remote port | Its “observed open connections” count can include closing-state rows; it is not restricted to `Established` |
| Uses only executable-name equality for `[OpenAI-named app]` | `ChatGPT.exe`/`codex.exe` selects the label; this branch performs no publisher-signature or DNS check |
| `[LAN]` matches only `192.168.*`, `10.*`, and `172.16.*`, after the executable-name branch | Other private ranges such as `172.21.*`, loopback and IPv6 do not receive that label from this rule |
| Uses `-ErrorAction SilentlyContinue` for the TCP query | Query errors may be suppressed; a heartbeat is not an independent demonstration of complete collection coverage |

There is **no DNS-cache collection, Security-log query, Defender query, `Get-ProcessTag` reference or “Updated identification” branch** in this source. The richer DNS/login-status and relabeling output in `34-user-pasted-log.txt` therefore cannot be attributed to this exact script alone. Likewise, the 30-second missing-helper logger in section 27 is a different implementation. This static comparison resolves collector identity at the code/output level without assigning a historical PID that the source does not record.

### Afternoon pasted output agrees with the preserved JSONL

`34-user-pasted-log.txt` contains **105 physical lines**: one truncated opening status fragment and **104 complete timestamped records**. Every complete record matches, in order, the **category and entire message** in `32-local-history-window.jsonl`, source lines **1040–1143**. All 104 printed local times equal the JSON observation timestamps reduced to whole seconds in EDT. No message or timestamp discrepancy was found in that comparison.

| Complete pasted records | Count |
| --- | --- |
| First-observed socket records | 74  |
| Updated-identification records | 4   |
| Monitor heartbeats | 26  |
| **Total** | **104** |

The complete paste runs **14:08:13–14:35:09 on September 17**. Its truncated opening text is an exact suffix of the preceding JSON heartbeat, source line **1039**. Source line **1038**, a 14:08:02 ChatGPT observation, is outside the supplied paste. This explains why section 25's full window contains **106 records**, rather than adding another separate collection period. All 26 complete pasted heartbeats report unavailable login-log access. The paste corroborates the earlier JSONL; it contributes no additional first-observed socket beyond that retained window.

### Morning collection markers and TCP counts

The two attached marker files contain:

| Marker file | Recorded local time, September 17 |
| --- | --- |
| `54-snapshot_taken_at.txt` | `11:33:47.5231432-04:00` |
| `42-live-checks-taken-at.txt` | `11:34:02.4993342-04:00` |

They differ by **14.9761910 seconds**. The attached network follow-up already reviewed in section 22 places these files in the later checks accompanying the morning monitor capture. The netstat and DNS text do not timestamp every row or command themselves. These markers are therefore preserved as collection context, rather than assigning an exact observation instant to every row. They concern the morning checks, separately from the afternoon pasted output above.

The TCP snapshots contain:

| State | IPv4 rows | IPv6 rows |
| --- | --- | --- |
| LISTENING | 16  | 13  |
| ESTABLISHED | 66  | 0   |
| TIME_WAIT | 32  | 0   |
| CLOSE_WAIT | 16  | 0   |
| **Total** | **130** | **13** |

Two established IPv4 rows are the opposite local endpoints of the same loopback pair, `127.0.0.1:62951 ↔ 127.0.0.1:62952`, both under PID **20016**. Thus even the 66 established rows are not 66 remote services or users. Twelve IPv6 wildcard listeners share PID/port pairs with IPv4 wildcard listeners. The remaining IPv6 row is the loopback listener `[::1]:42050`, PID **19124**. There are no listeners on **22, 3389, 5900, 5985 or 5986** in these particular snapshots; that is a bounded port check, not a general determination about remote access.

Two previously identified process records join directly by PID to the snapshot:

| Process identity from the saved signature check | Snapshot rows | Remote endpoints |
| --- | --- | --- |
| `codex.exe`, PID **56000**, bin `12219cbfbcbddde7` | **37 Established + 9 CloseWait = 46** | `104.18.32.47:443` — 13 rows; `172.64.155.209:443` — 33 rows |
| `ChatGPT.exe`, PID **34584**, package `OpenAI.Codex_26.908.9136.0` | **8 Established** | Six distinct remote address/port pairs; three rows go to `74.125.197.188:5228` |

`49-process-signatures.json` records `Valid` OpenAI signatures for both checked files and process start times **10:52:15.1406843** and **10:52:13.9997297 EDT**, respectively. This connects the stored PID and path records to the named package/bin generation used in the September 17 capture. The netstat text does not include the command lines required to assign PID 34584 a Chromium renderer or network-service role, and these are separate PIDs from the September 26 generation discussed elsewhere.

### DNS records provide named address associations

`40-dns-cache-local-snapshot.txt` contains **26 positive record blocks: 16 A, nine PTR and one CNAME**, plus four `No records of type AAAA` blocks. Selected direct joins to the TCP snapshot are:

| DNS text | Matching TCP observation |
| --- | --- |
| `chatgpt.com` → `104.18.32.47` and `172.64.155.209` | Both destinations occur under codex PID **56000**; `104.18.32.47` also occurs under ChatGPT PID **34584** |
| `c.pki.goog` → CNAME `pki-goog.l.google.com` → `142.250.69.99` | PID **3748**, `142.250.69.99:80`, Established |
| `signalrp2-relayhub-prod-na03-2.service.signalr.net` → `172.212.135.2` | PID **13336**, `172.212.135.2:443`, Established; the saved process check identifies **CrossDeviceService** |

The cache also contains GitHub reverse names, `rdap.arin.net`, `pypi.org`, a Sentry name and local Docker/host entries. Cache membership and remaining TTL do not identify which process made a lookup or the original query time. An address match is a useful correlation between these saved records; it is not a captured HTTP request, document ID, payload or user identity. For example, a loopback address matching `kubernetes.docker.internal` does not identify every loopback socket as Kubernetes traffic.

This batch strengthens the recorded controlled-test account, verifies another copy of the network observations, and identifies which outputs the supplied monitor source can generate. The user-confirmed September 19 CC0 republication remains authorized activity.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-06-jump-list-controlled-test.txt` | 7,928 | `b11df914ca55cc7132089c934fbb1977191d8adb0602e6b5a3079ed289da1d58` |
| `02-07-monitor-attribution-reconciliation.txt` | 16,761 | `46e67f097cd67ae23561862c8de671d091e92920ebf0ebf1a56d0dfd4573a2a2` |
| `03-08-live-network-monitor-source.ps1.txt` | 2,542 | `f353ade7efd9f96f7e11a002851d0627825f67758854d331b59e2c461bf5e676` |
| `04-34-user-pasted-log.txt` | 18,090 | `ecf14576d0cbe0c261369029296d8e1fb2e6f89f2bf0fb2edf1028469430bb7d` |
| `05-40-dns-cache-local-snapshot.txt` | 7,889 | `74892fee71c8e586c8bc36dbc98e39fbda6f7465945ce81d445cb468522fbe25` |
| `06-42-live-checks-taken-at.txt` | 35  | `a0649f28d6940a37029543b670daa595fb1eb373dc47ecb621d26ffb8121e570` |
| `07-44-netstat-ipv4.txt` | 10,076 | `79d98a05ce1922a49627becb57601e24a91503df01886f1bbc6acb1fd1897b96` |
| `08-45-netstat-ipv6.txt` | 1,095 | `139be15a061cba3b9ec6c92316129ce5ec86c60d24feb2146d63fee3dedd612c` |
| `09-54-snapshot_taken_at.txt` | 35  | `7dddb7e96296736f1e09977428fedcea6bc1b560e130eb5b64b3c17f308e8ede` |

## 29. Local-backup receipt, surviving text and additional monitor reconciliation

The six attachments in this batch all match the corresponding hashes in the supplied Evidence Ledger v12 manifest. They provide a local-copy record, substantive text, a revision comparison and further representations of already recorded network observations. Original files were left unchanged; no attached program was executed and no new IP lookup was issued.

### September 23 Robocopy log records a successful local backup with one failed file

Despite its OneDrive filename, `61-OneDrive_Copy_20260923_161557.log` is a **Robocopy execution log**. Its header records:

| Field | Recorded value |
| --- | --- |
| Source | `C:\Users\drewd\OneDrive\` |
| Destination | `C:\FULL_CLOUD_BACKUP\OneDrive\` |
| Started | **September 23, 16:29:18** |
| Ended | **September 23, 16:30:29** |
| File summary | **24,096 total; 24,095 copied; zero skipped; zero mismatches; one failed; zero extras** |
| Reported copied amount | **`33.386 g`**, the log's rounded display rather than an exact byte total |
| Failed amount | **63 bytes** |

The embedded start/end times span **71 seconds**. The `161557` filename component is not used in place of the execution header. The separate `Times` summary prints `0:05:27` under Total and `0:00:55` under Copied; those reported fields are preserved rather than substituted for the header's elapsed interval.

The file rows independently reconcile with the summary: **24,097 `New File` lines cover 24,096 distinct paths**, and **24,095 lines contain a `100%` progress marker**. The additional listing is another attempt at the same failed file. Four `ERROR 32` records, at **16:29:18, 16:30:19, 16:30:24 and 16:30:29**, all identify:

`C:\Users\drewd\OneDrive\.849C9593-D756-4E56-8D6E-42412F2A707B`

Each error states that another process was using the file. The log ends with `RETRY LIMIT EXCEEDED`, followed by the summary reporting one failed 63-byte file. These are repeated failures for that one path, not four missing research files. The log does not identify the process holding it open.

The options include `/COPY:DAT`, `/DCOPY:DAT`, `/E`, `/Z`, `/J`, `/XJ`, `/MT:16`, `/R:3` and `/W:5`. The recorded source and destination are local Windows paths. This log establishes a reported local backup operation; the cloud-upload findings in sections 15, 17 and 25 rest on separate SyncEngine request/completion records. The copy log supplies no destination content hashes and does not by itself authenticate the bytes subsequently present in `FULL_CLOUD_BACKUP`.

The log is not valid UTF-8 throughout. Its bytes were preserved unchanged; ASCII fields and paths used here were parsed through a one-byte-preserving view. The original console code page was not established. Source locators below count **LF-delimited lines**, retaining CR progress text on the corresponding file line. Treating every CR as another line produces a different count.

### The backup explicitly includes the reviewed artifacts

The following entries have `100%` progress markers and sizes matching the separately supplied artifacts:

| File | Recorded bytes | LF line in Robocopy log | Source subdirectory under OneDrive |
| --- | --- | --- | --- |
| `Politics-current-blank.docx` | 7,683 | 123 | `Adversarial-review-2026-09-20` |
| `Politics-revision-Aug17.txt` | 46,659 | 124 | `Adversarial-review-2026-09-20` |
| `Revelation-revision-diff.txt` | 1,266 | 129 and 163 | Review directory and its separate Desktop counterpart |
| `Untitled345-source.txt` | 229,282 | 134 and 168 | Review directory and its separate Desktop counterpart |
| `Pasted text.txt` — IP/geolocation audit | 37,042 | 122 and 158 | Review directory and its separate Desktop counterpart |

The exact two review locations are `C:\Users\drewd\OneDrive\Adversarial-review-2026-09-20\` and `C:\Users\drewd\OneDrive\Desktop\Adversarial-review-2026-09-20\`. Matching basenames in those directories are separate source paths, not two independently created bodies of evidence.

The log also records **646,098-byte** copies named `Politics administration investigation .pdf` at lines **299** and **12200**, under the Desktop monitor-logs and archived research-tree paths, respectively. That filename and size agree with the earlier local-file listing reviewed in section 15. Neither name/size agreement nor a copy-progress marker alone establishes content equality with the supplied Politics TXT.

For the two Politics artifacts, the combined record now has three distinct observations: the **September 20 named upload completions**, the **September 23 local-backup entries**, and the **content of the attachments inspected here and in section 27**. The filename/size joins are explicit; they are not silently promoted to a server-side content-hash comparison.

### Politics: a substantive text survives beside the blank document control

`63-Politics-revision-Aug17.txt` contains **46,659 UTF-8 bytes**, **46,093 decoded characters**, and **46,092 normalized characters** after removing leading BOMs, normalizing line endings and stripping outer whitespace. It has **210 lines**. Section 27 independently established that the separate `62-Politics-current-blank.docx` has an empty document body.

This newly supplied text preserves substantive political-research discussion: institutional-routing proposals, disclosure comparisons, provisional hypotheses and stated limits. It is formatted as a conversation extract, with **six “Worked for …” markers** and **34 flattened citation markers**, including strings such as `citeturn...` and `fileciteturn...`. It contains no literal HTTP/HTTPS source URL. Those placeholders are not usable primary-source citations in this standalone file.

The attachment supplies the preserved wording, not a new verification of every political claim inside it. Its `revision-Aug17` label is retained as the source filename; the TXT itself lacks a Google revision-response wrapper binding this text to a particular object ID, revision ID and August 17 modification time. The earlier local PDF handling and the September 20 upload record remain separate provenance observations. This text is also separate from the **74,609-character total for the eight matched native-Doc revision exports**; adding it to that total would conflate different evidence types.

### Revelation comparison records a four-line method insertion

`68-Revelation-revision-diff.txt` is byte-identical to the earlier archive copy and matches that archive's manifest. Its labels compare **v5.0 revision 2, August 31**, with **current revision 3, September 2**. The supplied comparison has one hunk, `@@ -94,4 +94,8 @@`: **four added lines and zero deleted lines**.

All four context lines match lines **94–97** of the preserved revision-2 content in `64-previous-1hfxlL_TIv6r7O8ZwKHg-EcqCgGc8jW9qX_yAzWwkdYE.json`. That earlier response records revision time **2026-08-31T05:01:55.431Z** and content SHA-256 **`60ee4dea18855b2229da06b7b65ebf6e27cd90820ada6a23d1c2ea217c6c5e2f`**, already checked in section 23.

The insertion is headed **“1.7 Successor method note.”** It names the post-freeze ledger as the prospective-work instrument, preserves earlier version-qualified records, and states:

> “This note changes no established fact, join, event disposition, source-control boundary, or Revelation interpretation in v5.0.”

The added text also assigns institutional facts and joins to their controlling source documents and says formal geometry contributes **“zero political evidence.”** Thus the supplied diff describes a method/authority clarification, rather than a text-to-empty transition. Its context is verified against the earlier body; the full later body is not supplied in this batch for an independent complete before/after comparison. The prior verification report's claim of no other normalized changes remains attributed to that comparison.

### September 17 morning paste exactly matches its saved snapshot

`58-user-pasted-log.txt` has **141 physical lines**, comprising an initial blank line and **140 timestamped records** from **11:25:10–11:26:03**. All 140 categories and complete messages match the corresponding first 140 records in `23-S002-access-events.snapshot.jsonl`, with local timestamps compatible to within one second of the JSON observation times.

| Morning excerpt records | Count |
| --- | --- |
| Already open at startup | 74  |
| First observed | 15  |
| Updated identification | 42  |
| Monitor/coverage | 9   |
| **Total** | **140** |

This directly verifies the original console representation behind the earlier **89 distinct startup/first-observed tuples** and **42 relabels**. The startup text explicitly describes the monitor's log folder as hidden in ordinary Explorer views, states that hidden files are not encrypted or protected from deletion, and describes an approximately **30 MB history limit**. Those are statements made by that monitor at startup, not a measurement of how much history was later retained or deleted.

### Untitled345 is a composite with exact matches, repetitions and damaged boundaries

`73-Untitled345-source.txt` is **229,282 bytes and 1,801 physical lines**, matching the byte/line counts reported by the September 19 **03:35** file-read result in section 24. That historical read result provides counts and a truncated preview, not a separate full-file digest; the exact hash of the newly supplied file is listed below.

Parsing the supplied text while retaining physical-line locators finds **1,731 timestamped record starts** in three output formats:

| Output format | Records in this paste | Verification result |
| --- | --- | --- |
| Call Probe uppercase tags | **329**: 243 NEW, 21 STATE, 45 ALIVE, 12 FANOUT, eight BURST | All 329 record headers match the displayed event fields in continuous source rows **865–1193** of the preserved Call Probe JSONL, with printed-time differences under one second |
| Access Monitor | **1,195** | **762 complete category/message matches** with time differences under one second, representing **577 distinct JSONL source rows**; one additional event prefix matches but has unrelated text appended |
| OneDrive-focused console | **207**: 95 first_observed, 105 heartbeat, seven state_changed | Text-level counts; this attachment does not supply a corresponding complete structured source for independent row verification |

The Call Probe block spans **02:46:20.695–03:32:01.792** in the pasted display. Its NEW, STATE, BURST and FANOUT fields identify observations and derived collector summaries; they are not separate file-transfer receipts. Forty-five ALIVE rows are heartbeats rather than new connections. The successful source join assigns these records to the previously preserved September 19 collector, without relying only on reused process names or PIDs.

The Access Monitor matches were required to agree on **category and entire message**, with less than one second between the whole-second console time and the structured observation time. This avoids incorrectly joining generic heartbeat messages merely because the same connection count recurs hours apart. **185 of the 762 matched appearances repeat a structured source row already matched elsewhere in this paste.** Another **432 Access-format records remain unconfirmed under this exact comparison**, in addition to the one partially matched boundary line. They are not promoted to verified extra events or treated as evidence of tampering merely because they lack a match in this retained source.

Examples of visible assembly damage explain why the paste cannot be treated as one uninterrupted raw log:

* **Line 398:** a valid Call Probe state transition ends with an appended login-coverage fragment. The underlying state-transition fields match source row 1193.
* **Line 633:** a Chrome connection to `64.233.178.147:443` has coverage text attached directly after the port. Its event prefix matches Access Monitor source row 2602.
* **Line 753:** a `03:32:45` Access Monitor line is immediately followed, without a newline, by a **01:46:52 OneDrive first_observed** record. That embedded record is included in the 207-row count above.
* **Line 959:** a OneDrive heartbeat ends with a fragment of another monitor's coverage message.
* **Line 1799:** the final Access Monitor heartbeat is truncated after `browse`.

The OneDrive-focused text covers **01:46:52–03:32:56** and names the OneDrive, OneDrive.Sync.Service and FileSyncHelper process family. It adds console observations, not a new successful server-upload count. The separate raw SyncEngine joins remain the upload evidence. Source order and malformed boundaries are preserved rather than repaired into a falsely continuous timeline.

### Historical geolocation table matches the already recorded lookup batches

`93-Pasted text.txt` is titled **Network IP/geolocation audit**, checked September 19. Its two tables contain **36 “new” and 38 “previously present” addresses**, with **74 distinct addresses and no overlap**. Both sets exactly match the respective saved IPinfo result arrays and query sets checked in section 26. All **29 “Yes” Anycast flags**, including **14 among the first 36 addresses**, agree with those stored responses.

Here **“new” means absent from the earlier conversation material used in that audit**, not the time a network connection began. The report explicitly distinguishes registration, geolocation estimates, provider regions and Anycast limitations. Its country/city labels are preserved historical lookup results, not newly verified present-day locations or identities of people operating services. This attachment corroborates the earlier 74-address lookup accounting; it does not add another 74 lookups.

The report names a separate **481-line source** and gives its SHA-256 as **`3d983cf54c9d6c176379ef925afbb9d3c08479a72019862d8d98917792ba3c59`**. That source identity is distinct from the **1,801-line Untitled345** file received in the same batch. A similar `Pasted text.txt` filename does not establish that the two are the same source. This pass verifies the report's address sets and Anycast flags against stored lookup responses; it does not silently substitute Untitled345 for the referenced 481-line input.

The additional backup, surviving text and matched monitor records extend the preservation record. The September 7 revision findings and the user's acknowledged September 19 CC0 publication retain their existing scope.

### Attachment hashes

| Attached file | Bytes | SHA-256 |
| --- | --- | --- |
| `01-58-user-pasted-log.txt` | 17,151 | `8618ddf408bc1da3bf8265cb3b0c6014e2e487070c2ab65b2b3117d33b0d9609` |
| `02-61-OneDrive_Copy_20260923_161557.log` | 3,871,538 | `2e89939d26c4ec3e628a00f4b3f1f0fb4d17c96282d81ca31b5ed5ae1d44ae96` |
| `03-63-Politics-revision-Aug17.txt` | 46,659 | `7fba85762c5076e07fbe0e8bf36dcdc21e441c0f1905eafb8573485b9de82387` |
| `04-68-Revelation-revision-diff.txt` | 1,266 | `d43d6740c63bd03c4423bc16da117c98878393fbef8199faf587722687f09476` |
| `05-73-Untitled345-source.txt` | 229,282 | `2d3995afdec49d53ab46008c0f8764570f3307b2b0477ed0d6b280540087e863` |
| `06-93-Pasted-text.txt` | 37,042 | `ce66a9a93b6b1502994a4362556120d8571d06b00874cde4fdedf6039763127b` |

## 30. Checkpoint reuploads and Politics revision metadata

### Ten reuploads are unchanged

The ten available attachments in this batch are **byte-for-byte identical** to the version-check files and Evidence Ledger v12 manifest examined in section 21. Both direct byte comparisons and SHA-256 checks agree. All nine JSON hashes also match their entries in the reuploaded manifest. These are additional copies of existing evidence, not ten new observations.

The upload prefixes changed as follows; the complete hashes remain those listed in section 21:

| Current attachment | Earlier identical attachment |
| --- | --- |
| `01-trace-review-metadata.json` | `02-trace-review-metadata.json` |
| `02-v4-integrity-check.json` | `03-v4-integrity-check.json` |
| `03-v5-reproducibility-check.json` | `04-v5-reproducibility-check.json` |
| `04-v6-screenshot-timing-check.json` | `05-v6-screenshot-timing-check.json` |
| `05-v7-network-provenance-check.json` | `06-v7-network-provenance-check.json` |
| `06-v8-network-coverage-check.json` | `07-v8-network-coverage-check.json` |
| `07-v9-onedrive-local-backup-check.json` | `08-v9-onedrive-local-backup-check.json` |
| `08-v10-revision-transfer-check.json` | `09-v10-revision-transfer-check.json` |
| `09-v11-access-audit-check.json` | `10-v11-access-audit-check.json` |
| `10-SHA256SUMS.txt` | `01-SHA256SUMS.txt` |

Later source examinations remain applicable to these older checkpoints. The v9 backup receipt is now independently supported by the original Robocopy log (section 29); the compiled review files and blank DOCX have been directly inspected (section 27); and the historical IP lookup total is **74 across two batches** (sections 26 and 29). The 36-row subset in the earlier record does not replace that full total. The conversation-coding correction in section 25 also remains in force. Reuploading an unchanged analytical check does not reverse those later refinements.

### Saved revision metadata dates the separate Politics size change

The `politics_word_control.revision_list_record` object in the v10 check **exactly equals array element 13** (the fourteenth entry, JSON pointer `/13`) of the previously supplied `01-70-revision-lists.json`. Its saved title is **Political Word file**, with file ID **`13O_5eCNocpgXzG-LMTq8AgFB_Tm8LKRV`**.

| Saved revision | `modifiedTime` in UTC | Recorded DOCX bytes | Recorded `lastModifyingUser` |
| --- | --- | --- | --- |
| Earlier, marked previous | **2026-08-17 20:19:45.630** | **29,048** | Ron Swanson; `ronswansonbruv@gmail.com`; `me=true` |
| Later, marked current in this saved response | **2026-08-26 16:21:49.646** | **7,683** | Empty display name, null email/permission ID, `me=false` |

The earlier revision ID is `0B6alEqbdqbD2SG56Y3MxSWhablo1eHM1Zk5rT3VSaGlqV0c0PQ`; the later revision ID is `0B6alEqbdqbD2cERUT08yLy9aM3J0K21yTWgzSzRpRkRVVm1RPQ`. Both entries identify the Word DOCX MIME type. The earlier row has `keepForever=true`; the later row has `keepForever=false`.

Recomputing the two attachment hashes also reproduces the v10 control's identifiers: the **7,683-byte blank DOCX** inspected in section 27 and the **46,659-byte substantive TXT export** examined in section 29. The latter contains exactly the checkpoint's **46,093 decoded characters**. The TXT export's byte size is not the byte size of the earlier DOCX revision; they are different representations.

This gives a reproducible join among the saved revision-list object, the analytical checkpoint, and the two specifically hashed local artifacts. The later revision's recorded size agrees with the blank DOCX. **The revision list does not contain a digest of that revision's content**, and this batch supplies neither an authenticated download receipt binding the blank DOCX hash to the later revision ID nor the earlier 29,048-byte DOCX for comparison. The separate TXT still lacks a revision-response wrapper binding its text to the earlier revision. Empty modifying-user fields record absent identity information; they do not identify a person, application or cause.

This August metadata is added to the separate Politics control. It is not another September 7 document event and does not change that frozen revision table. No live Drive retrieval or uploaded-program execution was performed in this pass.

Revision-list source: `01-70-revision-lists.json`, **29,064 bytes**, SHA-256 **`430f0abcf6713602be9aede3fb240a122f0d3ae2ebf4b08f7cbdb1dbc572fe8c`**. Its hash also matches the supplied Evidence Ledger manifest. The v10, DOCX and TXT hashes are retained in sections 21, 27 and 29 respectively.

The attempted report attachment failed to load and is not treated as inspected input. This update continues the existing report whose pre-update SHA-256 was `ad9e79464b91edfa8db84d7d2fd21c0362b4a125442201223eccb1313e840f54`.

