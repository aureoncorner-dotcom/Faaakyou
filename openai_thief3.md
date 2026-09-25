CONSOLIDATED ADVERSARIAL FORENSIC FINDING
Google Drive Content Loss · Google Account Session Evidence · Chrome/OpenAI · Windows Process Architecture · Network Infrastructure · OneDrive Transfers
1. Incident-level finding

The retained record establishes a multi-layer technical incident spanning Google Drive revision history, local Chrome history, Google provider-side account/session records, installed ChatGPT browser components, Windows ChatGPT/Codex processes, PID-specific network activity, Process Monitor filesystem/network records, and OneDrive application-level upload telemetry.

Eight exact Google Docs underwent same-object substantive-to-empty transitions. Seven occurred between 19:50:23.052 and 19:54:28.674 EDT on September 7, 2026, completing the seven-document sequence in 245.622 seconds. The eighth occurred September 8 at 14:55:57.416 EDT. The eight recovered substantive revisions contain 74,609 normalized characters.

The seven September 7 events now have an independent local-browser join. The preserved Windows Chrome Default-profile History database contains direct visits to all seven exact affected Google Drive object IDs, in corresponding sequence, immediately before their later-empty revisions. The measured visit→revision intervals are:

3.387 s · 3.700 s · 7.254 s · 4.234 s · 3.902 s · 7.770 s · 3.005 s.

This is a seven-for-seven object-level sequence, not merely browser activity somewhere inside the same hour.

The same incident period is covered by provider-side Google account evidence. Google records a “New sign-in on Mac OS” at September 1, 11:56 PM. The retained Google device page identifies a Mac OS session with First sign-in: Sep 1, activity through September 8, 10:17 AM, and displays Google Chrome and OpenAI under the browsers, apps, and services having some access to the Google account on that session. The account holder reports that the Mac session was neither recognized nor authorized.

The incident record therefore contains three independently derived event layers covering the September 7 sequence:

Google Drive: seven exact substantive→empty revisions.

Local Windows Chrome: seven exact-object visits immediately preceding those revisions.

Google account provider record: an unrecognized Mac OS session spanning the incident period and displaying Chrome and OpenAI account-access associations.

2. Seven-document exact-object sequence

The recovered revision ledger supplies the following object-level chronology.

Route / Witness / Balance

Drive object:

1_cEj40KyTUGHx3ze0IWYpHnzLMyWg2DXQ4rGUmRvkXU

Earlier substantive revision: revision 2.

Later empty revision: revision 3 at:

19:50:23.052 EDT

Local Windows Chrome visit:

19:50:19.665

Delta:

3.387 seconds

ASTRA — DROP_IT audit handoff

Drive object:

1h0giV4JsAEoZkdYAENtfL2jh9OhgNH5SUZBuvYcX6Gg

Earlier substantive revision: revision 2.

Later empty revision: revision 3 at:

19:50:52.999

Local Chrome visit:

19:50:49.299

Delta:

3.700 seconds

Response-authority signature / experimental critique

Drive object:

1UWFL9jpXL1gBQIEfgfoOgIQkQSbnBAW0OpNSVPWr5OE

Earlier substantive revision: revision 10.

Later empty revision: revision 11 at:

19:51:14.179

Local Chrome visit:

19:51:06.925

Delta:

7.254 seconds

611/2620 binary-marker task

Drive object:

1s8fJ1BAkbOTIAMkVYdb6ngTa-BENHM8A1ag-s7d3A7Q

Earlier substantive revision: revision 17.

Later empty revision: revision 18 at:

19:51:52.422

Local Chrome visit:

19:51:48.188

Delta:

4.234 seconds

“Yeah—let him finish this pass”

Drive object:

1UozXdpH1foCVjr9db3Zxzel9bvv_ctj_wIW-7Id6is8

Earlier substantive revision: revision 108.

Later empty revision: revision 109 at:

19:52:42.435

Local Chrome visit:

19:52:38.533

Delta:

3.902 seconds

The Tapestry of Organic Reality

Drive object:

13tZ6KqS7ShyneQfiQDihlhhbb4Cn0s4n5EAoSiI5Mx8

Earlier substantive revision: revision 2.

Later empty revision: revision 3 at:

19:53:38.641

Local Chrome visit:

19:53:30.871

Delta:

7.770 seconds

compress — dashboard/signature/experiment design

Drive object:

1MwDpPmQnwa0m1Rr_v-UacGcIJh4djJfjfxwIGBIc9T8

Earlier substantive revision: revision 8.

Later empty revision: revision 18 at:

19:54:28.674

Local Chrome visit:

19:54:25.669

Delta:

3.005 seconds

The recovered revisions for these seven documents alone contain tens of thousands of characters of substantive material. The eighth positive case—the behavioral-correction/SRT document—contains 19,038 normalized characters in its recovered substantive revision before its September 8 empty revision.

The sequence therefore has three characteristics simultaneously:

exact object identity, exact ordering, and seconds-scale temporal recurrence.

3. Local Chrome provenance

The September 7 browser evidence resides in the preserved Default Chrome profile.

The Chrome History records are direct URLs of the form:

docs.google.com/document/d/<OBJECT-ID>/edit

rather than generic visits to Google Drive.

The seven relevant History records carry local-origin Chrome metadata: their originator fields do not identify another Chrome Sync source device. Thus the seven object visits are records generated in the preserved local Windows Chrome history database.

The browser chronology is therefore:

Windows Chrome Default
→ exact Drive object A
→ seconds
→ A empty revision
→ exact object B
→ seconds
→ B empty revision
→ repeat through seven objects.

That is the central browser/revision cross-source join.

4. Google provider-side Mac session

Google's own security interface records a distinct security event:

September 1, 2026 — 11:56 PM

New sign-in on Mac OS

The Google device inventory independently identifies:

Mac OS

United States

First sign-in: Sep 1

Activity displayed through: Sep 8, 10:17 AM

and lists:

Google Chrome

OpenAI

under:

Browsers, apps, and services with some access to your account on the device.

The account holder reports no owned, used, or authorized Mac associated with this account.

The provider-side Mac session therefore begins approximately six days before the seven-document event and remains represented by Google across the incident period.

The Google interface also distinguishes it from recognized Windows activity. A separate September 5 security entry displays:

New sign-in on Windows — Maine, USA — Recognized

while the September 1 Mac sign-in appears as its own device-class security event.

This distinction is important because Google's own account interface separates the recognized Windows sign-in from the Mac OS session.

5. ChatGPT Chrome extension

The preserved Default profile contains Chrome extension ID:

hehggadaopoacecdllhhajmbjkdcmajg

identified locally as:

ChatGPT 1.26.901.11451

Chrome Secure Preferences place its retained update before the September 7 sequence.

Its manifest declares browser capabilities including:

debugger

nativeMessaging

history

scripting

sessions

tabs

tabGroups

webNavigation

downloads

bookmarks

storage

and:

<all_urls>

host access.

The preserved package also contains Codex side-panel components, computer-use-related assets, native-messaging implementation, and persistent extension state.

This establishes the presence in the incident-period Chrome profile of an OpenAI/ChatGPT browser component architecturally capable of browser navigation, scripting, session/tab access, debugger attachment and communication with native software.

6. Windows ChatGPT/Codex process architecture

The Windows evidence separately establishes a concrete process architecture.

Across the retained September 25 process-tree captures, the active ChatGPT desktop tree includes:

ChatGPT.exe

→ codex.exe

→ Windows command/process descendants

and also:

codex-computer-use-swift.exe

The consolidated September 25 snapshot identifies, among others:

ChatGPT.exe PID 2732

codex.exe PID 50724

codex-computer-use-swift.exe PID 39536

and a Codex-parented:

cmd.exe PID 22244.

The report separately preserves a distinct:

ChatGPT Classic.exe PID 41020

tree.

Earlier captures provide additional concrete process identities. A September 17 follow-up verified running codex.exe and ChatGPT.exe files and recorded that the Codex executables were signed by OpenAI OpCo, LLC. The ChatGPT executable was located inside the installed OpenAI.Codex Windows package.

Across different captures, PIDs naturally change as processes restart. The evidentiary significance is therefore attached to the repeated executable/process family and verified process tree rather than treating one PID as permanent.

7. OpenAI/ChatGPT network endpoint evidence

The strongest retained service-name joins involve:

104.18.32.47:443

and

172.64.155.209:443.

Both addresses are within Cloudflare infrastructure, while the saved Windows DNS evidence associates them with:

chatgpt.com

and related ChatGPT service names.

One September 17 evidence set contains 54 distinct connections to those two addresses:

52 from codex.exe

1 from ChatGPT.exe

1 from chrome.exe.

The retained destination report independently characterizes:

104.18.32.47

as observed from:

ChatGPT.exe and codex.exe

with local DNS evidence associating it with chatgpt.com.

Likewise:

172.64.155.209

was observed from:

chrome.exe and codex.exe

with the same local DNS/service association.

Another retained high-resolution capture joins:

codex.exe PID 56004

to:

chatgpt.com / 104.18.32.47:443

across nine attempts with subsequent network I/O totaling:

13,015,326 reported TCP send bytes.

That is considerably stronger than simply assigning meaning to an IP address: the record contains a process identity, DNS association, destination endpoint and measured network I/O.

Other repeatedly observed ChatGPT-family endpoints include:

104.18.39.21:443

172.64.148.235:443

and, in one retained capture:

35.190.80.1:443.

The September 17 allocation review places 35.190.80.1 inside a Google LLC registered range while the local connecting application was ChatGPT.exe.

8. Akamai infrastructure observations

Akamai appears repeatedly in the retained endpoint inventory.

The September 17 allocation review identifies the following observed addresses inside Akamai-registered ranges:

23.58.127.88

23.58.127.89

23.58.127.90

23.58.127.104

associated in that capture with:

NortonSvc.exe

and:

23.211.136.44

23.223.33.17

23.223.33.120

associated with:

LockApp.exe

plus:

23.223.33.25

associated with:

chrome.exe.

The destination report independently identifies 23.58.127.89 and 23.223.33.25 as Akamai delivery-network addresses, with Norton and Chrome respectively as the local connecting applications.

Additional later monitoring captured the same Akamai-heavy address families repeatedly, including Chrome connections to 23.223.33.25 and Norton connections throughout 23.58.127.x.

Thus Akamai is not represented by one isolated socket. It is a recurring infrastructure provider in the observed network environment, appearing across Norton, Chrome and Windows-related process activity.

For the adversarial ledger, Akamai should therefore be recorded as:

Recurring CDN/infrastructure allocation observed across multiple process families and multiple captures.

That is the affirmative receipt.

9. Norton / Icarus identity resolution

One initially unidentified process family was icarus.exe.

It was subsequently captured directly.

The executable resolved to:

C:\Program Files\Common Files\Norton\Icarus\...

with parent:

NortonSvc.exe

and a valid digital signature issued to:

Gen Digital Inc.

One captured command line was:

icarus.exe /checkforupdates:norton-av-vps /silent

and the executable's SHA-256 was preserved as:

F3FE068CCFAF86BCE397F94565A6F3B5AA75666AA5FF9264BF1AD02E0131645E.

The observed Icarus network activity included:

23.43.161.137:443

and related addresses.

This converted the earlier unidentified icarus.exe network observations into a signed Norton/Gen Digital process-family attribution.

10. Western Digital network behavior

WDDriveService.exe was separately resolved through Windows service metadata to:

C:\Program Files (x86)\Western Digital\WD Drive Manager\WDDriveService.exe

with:

Western Digital Technologies, Inc.

signature verification and version:

2.4.2.79

and SHA-256:

0155CB6BDC409262D139B3B7F0D2413C2A703E56970CBB6E1C0131642A8FE1DF.

Controlled stop/restart testing changed the WD service PID and reproduced its network behavior under the new PID.

Observed destinations included:

192.168.40.1:42323

and:

192.168.40.135:8060.

Historical monitor records showed the same endpoint behavior before the controlled restart experiment, establishing longitudinal recurrence rather than an artifact created by the test.

11. OneDrive exact-file synchronization

The OneDrive evidence contains both application-level and operation-level receipts.

The retained ledger contains:

292 successful upload completions

consisting of:

290 updates of events.jsonl

and:

2 updates of access-events.jsonl.

These records preserve named paths, OneDrive file identities, server request IDs, POST operations and successful completion states.

The controlled ProcMon experiment adds an exact-file filesystem→network join.

OneDrive.exe PID 41584 successfully read the same growing events.jsonl file four times.

The reads were:

581,322 bytes

581,770 bytes

582,212 bytes

582,654 bytes

Each was followed approximately 58–65 milliseconds later by a same-process network send group to:

13.107.139.11:443

with totals:

585,880

586,328

586,770

587,212 bytes.

Each send group therefore differed from its corresponding exact-file read by:

4,558 bytes

across all four repetitions.

The source file and network send quantities increased together.

That yields the reproduced operation sequence:

local file grows
→ OneDrive reads exact file
→ same OneDrive PID performs immediate TCP sends
→ native OneDrive telemetry independently records successful upload of the named file.

The destination inventory places 13.107.139.11 inside Microsoft SharePoint/OneDrive infrastructure.

12. Process Monitor evidence

The targeted historical Process Monitor export contained approximately:

996,839 events

across the selected ChatGPT/Codex/OneDrive process families.

Major process counts included:

codex.exe — 834,443

OneDrive.Sync.Service.exe — 122,920

OneDrive.exe — 20,252

ChatGPT.exe — 19,224

Within that capture, OneDrive components directly accessed:

C:\Users\drewd\OneDrive\Desktop\monitor-logs\access-events.jsonl

and the OneDrive executable repeatedly attempted Generic Read opens against the exact file.

A later controlled ProcMon experiment then supplied the cleaner four-cycle exact-read→network-send reproduction described above.

The combination of the historical million-event capture and the controlled exact-file experiment establishes that the OneDrive findings exist at both:

filesystem-operation level

and:

application upload-telemetry level.

13. Controlled ChatGPT/connection experiments

The retained report contains two controlled call windows.

Trial 1:

approximately 03:15:44–
