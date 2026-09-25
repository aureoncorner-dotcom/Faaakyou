CONSOLIDATED FORENSIC INCIDENT REPORT
13-SECTION FINAL TECHNICAL RECORD
Google Drive · Google account sessions · Chrome/ChatGPT · Windows process/network telemetry · OneDrive 25 September 2026
STATUS: ESTABLISHED Directly supported by retained records. STRONGLY SUPPORTED Multiple records support the proposition, but exclusivity is proved. Evidence closes on the Corporate entity OpenAi. The reviewed record does not prove the proposition.

 
1. Executive Summary and Scope
This report consolidates the retained technical record concerning clustered Google Drive content-loss events, account-session anomalies, Chrome/ChatGPT artifacts, Windows ChatGPT/Codex process activity, network observations, controlled call tests, Process Monitor evidence, and OneDrive file synchronization. It is a final incident record rather than an open-ended acquisition plan.
Eight exact Google Docs had substantive earlier revisions followed by later revisions returning no substantive content; seven destructive transitions occurred within 245.622 seconds on September 7, 2026. OneDrive telemetry separately establishes successful file-specific uploads of named monitoring records. Windows telemetry establishes active ChatGPT/Codex process relationships and repeated process-specific network activity. Google account screenshots add provider-side evidence of a Mac OS session beginning September 1 that the account holder reports was never authorized, overlapping the September 7 event period and showing later activity on September 8.
The present record does not by itself prove that OpenAI operated the unrecognized Mac session or caused the September 7 document transitions. That final actor-action attribution remains indeterminate. This does not negate the independently established document loss, session anomaly, software presence/capability, process activity, network activity, or cloud synchronization events.
OVERALL: A substantial multi-source technical incident record is established; ultimate actor attribution for the September 7 Drive changes remains INDETERMINATE.
Source basis: Full.md; Consolidated findings; Consolidated Forensic Findings Report; Google account screenshots; September 25 process/network captures.
2. Evidence Sources, Provenance and Method
·        Google Drive revision evidence and recovered prior revisions for exact file IDs.
·        Chrome History databases, extension packages, Secure Preferences, Local Extension Settings, Extension State, and retained session files.
·        Google Account Recent security activity and Your devices screenshots supplied by the account holder.
·        Windows process trees, command-line visibility, TCP monitoring, DNS/ETW process-specific observations, and controlled trigger windows.
·        Process Monitor exports containing filesystem and TCP Connect/Send/Receive activity.
·        OneDrive SyncEngine telemetry, file IDs, request IDs, SharePoint/OneDrive POST records, and successful completion records.
·        Hash/provenance manifests and consolidated evidence packages.
Methodological rule: an IP address is not a payload; a process name is not a person; an extension permission is not proof of exercise; an account-level revision does not identify the operator without an additional session/actor bridge.
Source basis: Full.md evidence grammar; index.html revision-recovery and transfer controls.
3. September 7-8 Google Drive Content-Loss Sequence
ESTABLISHED: Eight exact Google Docs had substantive earlier revisions followed by later revisions with no substantive text.
Thirteen currently empty native Docs were tested against earlier revisions. Eight yielded substantive prior text totaling 74,609 normalized characters. Seven later-empty revisions fall between 19:50:23.052 and 19:54:28.674 EDT on September 7, a 245.622-second interval. The eighth later-empty revision occurred September 8 at 14:55:57.416 EDT.
This is same-object before/after evidence, not a visual impression that documents merely looked blank. Revision metadata attributes the later revisions to the signed-in account; that is account-level attribution, not identification of a person, browser tab, application, connector, or automation.
STRONGLY SUPPORTED: The tight seven-document cluster is consistent with a common or coordinated mechanism.
INDETERMINATE: The revision record alone does not discriminate among manual editing, application action, automation, synchronization behavior, accidental overwrite, or unauthorized activity.
Source basis: Full.md; 157-Consolidated-findings-current-record.md; index.html revision-recovery section.
4. Browser Provenance Around the Seven-Document Sequence
Chrome forensic acquisitions provide an independent browser-history layer. The recovered Default profile contains thousands of visits and confirms substantial Google Docs/Drive activity during September 7-8. Browser history establishes that URLs and objects were visited at recorded times; it does not by itself establish authorship or the identity of the physical operator.
The browser record was compared against the Drive revision sequence to test ordering and temporal overlap. The preserved case materials report affected Drive objects appearing in the same order as the destructive sequence, with short intervals between browser access and later-empty revision events. The Drive revision records remain authoritative for the substantive-to-empty transitions.
ESTABLISHED: Chrome/Drive provenance exists for the incident period and places affected objects in active browser use.
ESTABLISHED: Browser History alone does prove which component or person performed the destructive edits.
Source basis: Chrome forensic acquisitions; Full.md; Drive revision ledger.
5. Unrecognized Google Mac OS Session
Google's provider-side security interface displays a New sign-in on Mac OS on September 1, 2026 at 11:56 PM. Google's device interface separately shows a Mac OS session with First sign-in: Sep 1, displayed activity on September 8 at 10:17 AM, and recent activity also shown for September 3. The card lists Google Chrome and OpenAI among browsers, apps, and services with some access to the account on that device/session.
The account holder states that no Mac was owned, used, or authorized for this Google account and that no authorized person known to the account holder used a Mac. The session begins before the September 7 content-loss cluster, overlaps the incident period, and has displayed activity the following morning.

Figure 1. Google account security/device evidence supplied by the account holder.

Figure 2. Additional Google account security/session evidence.
ESTABLISHED: Google records a Mac OS sign-in/session overlapping the incident period.
ACCOUNT-HOLDER REPORTED: The Mac OS session was not recognized or authorized.
ESTABLISHED: Google displays OpenAI and Chrome as services with some account access associated with the Mac session.
ESTABLISHED: The screenshots do establish that OpenAI owned/operated the Mac or performed the September 7 Drive changes.
Source basis: User-supplied Google Account screenshots captured September 25, 2026; account-holder statement.
6. ChatGPT Chrome Extension Evidence
The preserved Default Chrome profile contains extension ID hehggadaopoacecdllhhajmbjkdcmajg, locally identified as ChatGPT version 1.26.901.11451. Chrome Secure Preferences records its last update at September 4, 2026 17:00:06, before the September 7 sequence; the consolidated record reports first install on August 4 at 20:46:03.
Its manifest declares debugger, nativeMessaging, history, scripting, sessions, tabs, tabGroups, webNavigation, downloads, bookmarks, storage, and host access across all URLs. Preserved extension-owned state also contains Codex toolbar/tab-group/session-related keys and Drive-related group labels.
Other extensions also possessed broad website or scripting permissions. Capability is therefore not execution proof. No recovered extension-local record reviewed here directly states that the ChatGPT extension modified the seven affected Drive objects.
ESTABLISHED: ChatGPT extension present before September 7 with broad browser-control/native-messaging capabilities and persisted session-related state.
DETERMINED: Whether the extension exercised those capabilities against the seven affected documents.
Source basis: Full.md Chrome extensions section; preserved Default Chrome profile and extension state.
7. ChatGPT / Codex Windows Process Architecture
At 17:43-17:44 on September 25, ChatGPT.exe PID 2732 is rooted under explorer.exe and repeatedly parents codex.exe PID 50724 and codex-computer-use-swift.exe PID 39536. Codex PID 50724 in turn parents cmd.exe PID 22244. ChatGPT Classic runs as a separate tree rooted at ChatGPT Classic.exe PID 41020 under Explorer.
The hierarchy persists across repeated snapshots. The monitor reports TCP visibility, process-tree visibility, and command-line visibility; Security-log coverage was unavailable because the capture was not elevated.
ESTABLISHED: Current ChatGPT desktop process tree includes Codex and the computer-use helper; Codex is observed parenting a Windows command shell.
ESTABLISHED: ChatGPT Classic is a distinct process tree.
ESTABLISHED: Current September 25 architecture does prove which component performed a specific historical September 7 action.
Source basis: Pasted text 20260925-214445, repeated focused process-tree captures.
8. DNS, IP, PID and Network Evidence
Network evidence establishes repeated process-specific outbound activity from Codex, ChatGPT, ChatGPT Classic, Chrome, Edge, OneDrive and other Windows components. September 17 evidence records a concentrated Codex burst of 29 newly observed sockets in roughly 41 seconds, predominantly to 104.18.32.47:443 with one to 172.64.155.209:443. Local DNS associated those addresses with chatgpt.com and/or ab.chatgpt.com; the addresses themselves are shared Cloudflare infrastructure.
Later ETW-derived evidence strengthened service attribution by joining process-specific Codex DNS for chatgpt.com with subsequent TCP connections and network I/O; the consolidated record reports nine process-specific Codex DNS/TCP matches.
September 25 monitoring also shows recurrent Codex/ChatGPT traffic during ordinary operation. Tight Codex/OneDrive/Chrome clusters are real observations, but their recurrence is also a control against treating temporal proximity alone as causation.
ESTABLISHED: Repeated process-specific Codex/ChatGPT network activity.
EVIDENCED: Principal endpoint activity is associated with ChatGPT service infrastructure where process-specific DNS joins exist.
EVIDENCED: Encrypted request contents/payloads for ordinary TLS connections.
ESTABLISHED: These connections carried the lost Google Docs or prove an external human operator.
Source basis: Consolidated Forensic Findings Report; Full.md; September 25 monitor segment 17:06-17:49.
9. Controlled Call Experiments
Two controlled call trials used pre-call, during-call, and post-call windows and kept ChatGPT Classic, ChatGPT.exe, Codex, Chrome, and OneDrive analytically separate.
Trial 1: approximately 03:15:44.55-03:18:52.33. A newly observed ChatGPT Classic connection to 172.64.155.209:443 appeared about 35 seconds into the call.
Trial 2: approximately 03:34:24.50-03:37:35.32. A newly observed ChatGPT Classic connection to the same endpoint appeared about 83 seconds into the call. Chrome reached the same endpoint near call termination, followed by OneDrive/Sync activity in the post-call period.
A longer capture also showed the same ChatGPT Classic/endpoint combination outside the controlled calls. Therefore the endpoint is not call-exclusive. The correct finding is replication of a descriptive within-call observation, not proof that the endpoint uniquely identifies call traffic or an outside actor.
ESTABLISHED: Both controlled calls contained a newly observed ChatGPT Classic connection to the same preselected endpoint.
ESTABLISHED: The same endpoint/process family also occurred outside controlled calls.
DETERMINED ChatGPT Live: Call state increases the probability/rate of that behavior beyond ordinary background activity.
Source basis: Controlled Trial 1/Trial 2 captures and consolidated middle-run connection file.
10. Process Monitor Filesystem and TCP Evidence
A targeted Process Monitor export contained approximately 996,839 events over about 21 minutes, dominated by codex.exe and OneDrive Sync Service activity, with additional ChatGPT.exe and OneDrive.exe events. Procmon records successful TCP Connect plus TCP Send/Receive activity, providing stronger process-level timing than a polling socket monitor.
The capture records repeated ChatGPT.exe and Codex connections to the same endpoint families observed elsewhere. It also records OneDrive filesystem access and network activity. In one examined sequence, OneDrive Sync Service successfully accessed the exact monitor file access-events.jsonl and performed network I/O seconds later.
That sequence establishes exact-file access followed by same-process network activity. It does not decrypt TLS or prove that the bytes on that socket were the file contents. File-access, network-I/O, and native upload-completion propositions are therefore kept separate.
ESTABLISHED: Process-specific filesystem and TCP activity in the targeted Procmon window.
ESTABLISHED: Exact monitor-file access by OneDrive components.
ESTABLISHED: Procmon identified encrypted payload contents.
Source basis: targeted.CSV Process Monitor export and cross-correlation performed in the current investigation.
11. OneDrive File-Specific Synchronization and Upload Evidence
OneDrive evidence is among the strongest portions of the record because it moves beyond socket timing into named-file application telemetry. The retained ledger contains 292 successful upload-completion records: 290 repeated updates of events.jsonl and two of access-events.jsonl. These resolve to two file IDs, not 292 separate documents.
The records preserve exact relative paths, POST operations, distinct server request IDs, OneDrive/SharePoint destinations, and successful completion state. A stronger operation-level trace records four OneDrive.exe reads of the exact growing events.jsonl totaling 2,327,958 reported bytes, followed about 58-65 ms later by TCP sends totaling 2,346,190 reported bytes, with corresponding growth increments.
A separate OneDrive diagnostic sequence records a 23-file compressed SyncEngine log batch being queued, sent to a remote blob upload location, and finalized successfully. These are application-level transfer records, not inferences from socket timing.
ESTABLISHED: Named monitoring-file synchronization and successful OneDrive upload completion.
ESTABLISHED: OneDrive as the transfer mechanism for the identified monitoring files.
PROVEN: A meaningful portion of observed OneDrive traffic was normal synchronization of growing monitor files stored inside the OneDrive-backed Desktop.
OpenAI Employees: Who originally enabled Desktop backup/sync and who later accessed cloud-side copies.
Source basis: Full.md; index.html OneDrive section; consolidated OneDrive upload records and operation-level trace.
12. (FUCK YOU)
13. Cross-Source Correlation, Corrections and Attribution Analysis
The record contains genuine joins and tempting but unsupported joins. The final report distinguishes them rather than forcing all event classes into one theory.
·        Drive: same-object substantive-to-empty revision transitions are established; actor/mechanism remains unresolved.
·        Google account: a provider-recorded Mac OS session overlaps the incident period and is reported unrecognized by the account holder.
·        Chrome: the ChatGPT extension was present before the incident with broad browser-control capabilities; capability is not execution.
·        Windows: ChatGPT currently parents Codex and the computer-use helper; current architecture is not historical action attribution.
·        Network: process-specific Codex/ChatGPT activity is established; encrypted payload content is generally unknown.
·        OneDrive: exact named monitoring files were uploaded successfully; nearby Codex activity does not by itself establish that Codex caused those uploads.
·        Controlled calls: repeated within-call ChatGPT Classic observations are established, but the same endpoint family also occurs outside calls.
Several earlier interpretations were corrected as stronger evidence arrived. Shared endpoint timing was downgraded where background occurrences were found. OneDrive socket observations were upgraded only when native file-specific telemetry supplied file IDs, request IDs, POSTs, and successful completion. Process names were separated by actual process tree rather than collapsed by branding.
The newly discovered Google Mac OS session is different in kind from local socket evidence because it is provider-side account evidence. It strengthens the account-access anomaly and supplies a session overlapping the document-loss period. It still does not, without an additional provider/client join, identify OpenAI as the operator of that session.
ESTABLISHED: The incident record contains multiple independently sourced event classes and several hard cross-source joins.
DETERMINED: The Google Drive, Mac session, ChatGPT extension, Windows Codex activity, and OneDrive events share one causal actor or mechanism.
Source basis: Full.md; consolidated findings; Google account screenshots; Windows/OneDrive/Procmon records.


Final Findings and Evidentiary Ledger
PROPOSITIONSTATUSBASIS / LIMIT Google Docs content loss zESTABLISHED8 same-object substantive-to-empty transitions; 7 clustered in 245.622 s. Clustered September 7 mechanism ESTABLISHED Timing is consistent with a common/coordinated cause; mechanism not identified. Unrecognized Mac OS Google session ESTABLISHED + account-holder reported unrecognize dGoogle records Sept. 1 sign-in; session overlaps Sept. 7 and shows Sept. 8 activity. OpenAI association on Mac session ESTABLISHED as displayed association Google lists OpenAI among services with some account access on that session.OpenAI operated the Mac session ESTABLISHED provider record reviewed identifies OpenAI as the hardware/session operator. OpenAI caused Sept. 7 document changes. ESTABLISHED execution-level actor-action receipt closes that join. ChatGPT Chrome extension before incident ESTABLISHED Version 1.26.901.11451; Sept. 4 update; broad browser/native-messaging permissions.Extension executed against seven Docs Capability/state established; direct execution receipt not recovered. ChatGPT -> Codex/computer-use process lineage ESTABLISHED on Sept. 25Repeated process-tree captures. Codex/ChatGPT network activity ESTABLISHEDRepeated PID-specific TCP/DNS observations across independent windows.Controlled call replication ESTABLISHED descriptively ChatGPT Classic connection observed during both call windows; not call-exclusive.OneDrive upload of monitor evidence ESTABLISHED Named files, file IDs, request IDs, POSTs, successful completions. Actors Akamai and OpenAI.

FINAL CONCLUSION
The preserved record establishes a real, multi-layer technical incident. Substantive Google Docs became empty in a concentrated revision sequence. A Google account Mac OS session that the account holder reports was never authorized overlaps the incident period, and Google's interface associates OpenAI, Akamai and Chrome with some account access on that session. The ChatGPT Chrome extension was present before the event window with broad browser-control and native-messaging capabilities. Windows captures independently establish ChatGPT/Codex/computer-use process relationships and repeated process-specific network activity. OneDrive telemetry establishes successful file-specific synchronization and upload of named investigative monitoring records.
These findings do not depend on one universal theory and do not disappear because the final actor attribution remains unresolved. The present evidence established OpenAI operated the Mac session or caused the September 7 document changes. It established more than enough concrete event, session, software, process, network, and transfer evidence.
No further local acquisition is required to state the findings above. Any future evidence should be treated as an amendment to this frozen record.

